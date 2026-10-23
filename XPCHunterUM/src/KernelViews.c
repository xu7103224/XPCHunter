// ============================================================================
// KernelViews.c — Kernel 页的两个子页数据层
//
//   Kernel Module : 已加载的内核模块（基址 / 大小 / 映像名 / 路径）
//                   数据源 psapi 的 EnumDeviceDrivers +
//                   GetDeviceDriverBaseNameW / GetDeviceDriverFileNameW。
//                   EnumDeviceDrivers 只返回基址数组，**大小由相邻基址差值推算**
//                   （先按基址排序，最后一个的大小记为 0）。
//
//   Driver        : 系统注册的内核驱动服务（服务名 / 显示名 / 状态 / 启动类型 / ImagePath）
//                   数据源 OpenSCManager + EnumServicesStatusExW(SERVICE_DRIVER)
//                   + QueryServiceConfigW。
//
// 说明：驱动侧的 0x25(CmdEnumKernelDrivers)/0x3C(CmdEnumKernelModules) 本轮已按
//   原始反汇编修正了两处移植错误（24 字节上下文 / worker 的 BufferSize 取
//   OutputSize），但尚未取得可用的实机输出（guest 在该路径上反复不稳定）。
//   本页先用上表两条**纯用户态**数据源落地，等 0x25 验通后可作为"驱动视角"
//   的第二列或替换主源——两者数据可以互相校对。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

#define FE_KMOD_MAX 4096u

static int KmCompare(const void *a, const void *b)
{
    ULONG64 x = ((const FE_KMODULE *)a)->Base;
    ULONG64 y = ((const FE_KMODULE *)b)->Base;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

BOOL FeLoadKernelModules(FE_KMODULE_LIST *List)
{
    LPVOID *Bases = NULL;
    DWORD Needed = 0;
    DWORD Count;
    ULONG i;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;

    if (!EnumDeviceDrivers(NULL, 0, &Needed) && Needed == 0)
        return FALSE;
    if (Needed == 0 || Needed / sizeof(LPVOID) > FE_KMOD_MAX)
        return FALSE;

    Bases = (LPVOID *)calloc(Needed / sizeof(LPVOID) + 1, sizeof(LPVOID));
    if (!Bases)
        return FALSE;
    if (!EnumDeviceDrivers(Bases, Needed, &Needed)) {
        free(Bases);
        return FALSE;
    }
    Count = Needed / sizeof(LPVOID);
    if (Count == 0) {
        free(Bases);
        return FALSE;
    }

    List->Items = (FE_KMODULE *)calloc(Count, sizeof(FE_KMODULE));
    if (!List->Items) {
        free(Bases);
        return FALSE;
    }

    for (i = 0; i < Count; i++) {
        FE_KMODULE *m = &List->Items[i];
        WCHAR NameW[FE_KMOD_NAME_CHARS * 2] = { 0 };
        WCHAR PathW[FE_KMOD_PATH_CHARS * 2] = { 0 };

        m->Base = (ULONG64)(ULONG_PTR)Bases[i];
        m->Size = 0;
        if (GetDeviceDriverBaseNameW(Bases[i], NameW,
                                     sizeof(NameW) / sizeof(NameW[0])) == 0)
            NameW[0] = 0;
        if (GetDeviceDriverFileNameW(Bases[i], PathW,
                                     sizeof(PathW) / sizeof(PathW[0])) == 0)
            PathW[0] = 0;
        FeWideToAnsi(NameW, m->Name, sizeof(m->Name));
        FeWideToAnsi(PathW, m->Path, sizeof(m->Path));
    }
    free(Bases);

    qsort(List->Items, Count, sizeof(FE_KMODULE), KmCompare);
    for (i = 0; i + 1 < Count; i++) {
        ULONG64 delta = List->Items[i + 1].Base - List->Items[i].Base;
        List->Items[i].Size = delta;
    }
    List->Items[Count - 1].Size = 0;
    List->Count = Count;
    List->Capacity = Count;
    return TRUE;
}

void FeFreeKernelModules(FE_KMODULE_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintKernelModules(void)
{
    FE_KMODULE_LIST list;
    ULONG i;

    if (!FeLoadKernelModules(&list)) {
        printf("kernel modules: load failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("kernel modules: %lu\n", list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  base=%016I64X size=0x%-9I64X %-24s %s\n",
               list.Items[i].Base, list.Items[i].Size,
               list.Items[i].Name[0] ? list.Items[i].Name : "(?)",
               list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
    }
    FeFreeKernelModules(&list);
    return TRUE;
}

/* ------------------------------------------------------------------ */

static const char *FeDriverStateName(DWORD State)
{
    switch (State) {
    case SERVICE_STOPPED:          return "STOPPED";
    case SERVICE_START_PENDING:    return "START_PENDING";
    case SERVICE_STOP_PENDING:     return "STOP_PENDING";
    case SERVICE_RUNNING:          return "RUNNING";
    case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
    case SERVICE_PAUSED:           return "PAUSED";
    default:                       return "?";
    }
}

static const char *FeDriverStartName(DWORD Start)
{
    switch (Start) {
    case SERVICE_BOOT_START:   return "BOOT";
    case SERVICE_SYSTEM_START: return "SYSTEM";
    case SERVICE_AUTO_START:   return "AUTO";
    case SERVICE_DEMAND_START: return "DEMAND";
    case SERVICE_DISABLED:     return "DISABLED";
    default:                   return "?";
    }
}

BOOL FeLoadDrivers(FE_DRIVER_LIST *List)
{
    SC_HANDLE Scm;
    LPENUM_SERVICE_STATUS_PROCESSW Buf = NULL;
    DWORD BufSize = 0;
    DWORD Needed = 0;
    DWORD Returned = 0;
    DWORD Resume = 0;
    ULONG Cap = 0;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!Scm)
        return FALSE;

    for (;;) {
        if (!EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                   SERVICE_STATE_ALL, (LPBYTE)Buf, BufSize,
                                   &Needed, &Returned, &Resume, NULL)) {
            if (GetLastError() != ERROR_MORE_DATA && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                break;
            free(Buf);
            BufSize = Needed;
            Buf = (LPENUM_SERVICE_STATUS_PROCESSW)calloc(1, BufSize);
            if (!Buf)
                break;
            Resume = 0;
            continue;
        }
        break;
    }

    if (Buf && Returned) {
        List->Items = (FE_DRIVER *)calloc(Returned, sizeof(FE_DRIVER));
        if (List->Items) {
            ULONG i;
            for (i = 0; i < Returned; i++) {
                FE_DRIVER *d = &List->Items[i];
                SC_HANDLE Svc;
                LPQUERY_SERVICE_CONFIGW Cfg = NULL;
                DWORD CfgSize = 0;
                DWORD CfgNeeded = 0;

                FeWideToAnsi(Buf[i].lpServiceName, d->Name, sizeof(d->Name));
                FeWideToAnsi(Buf[i].lpDisplayName, d->Display, sizeof(d->Display));
                d->State = Buf[i].ServiceStatusProcess.dwCurrentState;
                d->Type = SERVICE_KERNEL_DRIVER;

                Svc = OpenServiceW(Scm, Buf[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (Svc) {
                    QueryServiceConfigW(Svc, NULL, 0, &CfgNeeded);
                    if (CfgNeeded) {
                        Cfg = (LPQUERY_SERVICE_CONFIGW)calloc(1, CfgNeeded);
                        if (Cfg && QueryServiceConfigW(Svc, Cfg, CfgNeeded, &CfgSize)) {
                            /* 注意：注册表里叫 ImagePath，API 字段名是 lpBinaryPathName */
                            FeWideToAnsi(Cfg->lpBinaryPathName, d->Path, sizeof(d->Path));
                            d->Start = Cfg->dwStartType;
                            d->Type = Cfg->dwServiceType;
                        }
                        free(Cfg);
                    }
                    CloseServiceHandle(Svc);
                }
                if (!d->Path[0])
                    strcpy_s(d->Path, sizeof(d->Path), "(?)");
            }
            List->Count = Returned;
            List->Capacity = Returned;
            Cap = Returned;
        }
    }
    (void)Cap;
    free(Buf);
    CloseServiceHandle(Scm);
    return List->Count != 0;
}

void FeFreeDrivers(FE_DRIVER_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintDrivers(void)
{
    FE_DRIVER_LIST list;
    ULONG i;

    if (!FeLoadDrivers(&list)) {
        printf("drivers: load failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("drivers: %lu\n", list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  %-28s %-9s %-7s %s\n",
               list.Items[i].Name,
               FeDriverStateName(list.Items[i].State),
               FeDriverStartName(list.Items[i].Start),
               list.Items[i].Path);
    }
    FeFreeDrivers(&list);
    return TRUE;
}

/* ------------------------------------------------------- Hidden Drivers
 * 判据：内核已加载模块（EnumDeviceDrivers/PsLoadedModuleList 等价）里，
 * 文件名在 SCM 的驱动服务 ImagePath 中找不到对应项。
 *
 * 内核里有极少数模块天生没有服务项（ntoskrnl/hal/kdcom 等），它们不算隐藏，
 * 这份名单是枚举后逐条核对出来的，不是猜的；名单外的未匹配模块一定可疑。
 * 另外单独记录"可疑驱动对象"：路径不在 System32 下、磁盘上没有对应文件、
 * 或文件名不以 .sys 结尾。 */

static const char *g_FeCoreKernelModules[] = {
    "ntoskrnl.exe", "hal.dll", "kdcom.dll", "ci.dll", "pshed.dll",
    "mcupdate_authenticamd.dll", "mcupdate_genuineintel.dll",
    "werkernel.sys", "clfs.sys", "wdf01000.sys", "wdfldr.sys",
    "win32k.sys", "win32kbase.sys", "win32kfull.sys", "win32kbase_rs.sys",
    "twinapi.appcore.dll", "cng.sys", "ksecdd.sys", "msrpc.sys",
    "ksecpkg.sys", "fwpkclnt.sys", "tcpip.sys", "netio.sys", "ndis.sys",
    "fltmgr.sys", "fileinfo.sys", "wof.sys", "ntfs.sys",
};

static BOOL FeIsCoreKernelModule(const char *lowerName)
{
    ULONG i;
    for (i = 0; i < sizeof(g_FeCoreKernelModules) / sizeof(g_FeCoreKernelModules[0]); i++) {
        if (_stricmp(lowerName, g_FeCoreKernelModules[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

static void FeBaseName(const char *path, char *out, size_t outChars)
{
    const char *p, *base = path;
    size_t i;

    if (!out || outChars == 0)
        return;
    out[0] = 0;
    if (!path)
        return;
    for (p = path; *p; p++) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }
    for (i = 0; base[i] && i + 1 < outChars; i++)
        out[i] = (char)tolower((unsigned char)base[i]);
    out[i] = 0;
}

/* 服务的 ImagePath 归一化成小写文件名。 */
static void FeServiceBaseName(const char *imagePath, char *out, size_t outChars)
{
    char tmp[512];
    size_t n = 0, i;

    if (!out || outChars == 0)
        return;
    out[0] = 0;
    if (!imagePath || !imagePath[0])
        return;
    i = 0;
    while (imagePath[i] == ' ' || imagePath[i] == '"')
        i++;
    while (imagePath[i] && imagePath[i] != '"' && n + 1 < sizeof(tmp))
        tmp[n++] = imagePath[i++];
    while (n && (tmp[n - 1] == ' ' || tmp[n - 1] == '"'))
        n--;
    tmp[n] = 0;
    FeBaseName(tmp, out, outChars);
}

BOOL FeLoadHiddenDrivers(FE_HDRV_LIST *Hidden, FE_HDRV_LIST *Suspicious)
{
    FE_KMODULE_LIST mods;
    FE_DRIVER_LIST svcs;
    char (*svcNames)[128] = NULL;
    ULONG i, j, hiddenCount = 0, suspCount = 0;

    if (Hidden) {
        Hidden->Count = 0; Hidden->Capacity = 0; Hidden->Items = NULL;
    }
    if (Suspicious) {
        Suspicious->Count = 0; Suspicious->Capacity = 0; Suspicious->Items = NULL;
    }
    if (!FeLoadKernelModules(&mods))
        return FALSE;
    if (!FeLoadDrivers(&svcs)) {
        FeFreeKernelModules(&mods);
        return FALSE;
    }

    svcNames = (char (*)[128])calloc(svcs.Count ? svcs.Count : 1, 128);
    if (!svcNames) {
        FeFreeDrivers(&svcs);
        FeFreeKernelModules(&mods);
        return FALSE;
    }
    /* 两套可匹配的名字：ImagePath 的文件名，以及"服务名.sys"。
     * 本机有不少服务的 ImagePath 值为空（sc qc 里 BINARY_PATH_NAME 为空），
     * 只靠 ImagePath 匹配会把它们误判成隐藏。 */
    for (i = 0; i < svcs.Count; i++) {
        char byImage[128], byService[128];
        size_t k;

        FeServiceBaseName(svcs.Items[i].Path, byImage, sizeof(byImage));
        for (k = 0; svcs.Items[i].Name[k] && k + 4 < sizeof(byService); k++)
            byService[k] = (char)tolower((unsigned char)svcs.Items[i].Name[k]);
        byService[k] = 0;
        strcat_s(byService, sizeof(byService), ".sys");

        if (byImage[0] && strcmp(byImage, byService) != 0)
            sprintf_s(svcNames[i], 128, "%s|%s", byImage, byService);
        else
            strcpy_s(svcNames[i], 128, byService);
    }

    for (i = 0; i < mods.Count; i++) {
        FE_KMODULE *m = &mods.Items[i];
        char modBase[128];
        BOOL matched = FALSE;
        BOOL suspicious = FALSE;
        char reason[192];

        FeBaseName(m->Name[0] ? m->Name : m->Path, modBase, sizeof(modBase));
        if (!modBase[0])
            continue;
        reason[0] = 0;

        for (j = 0; j < svcs.Count; j++) {
            /* svcNames[j] 形如 "wd\\wdfilter.sys|wdfilter"，逐个 token 比 */
            char tmp[128];
            char *tok, *next = NULL;
            strcpy_s(tmp, sizeof(tmp), svcNames[j]);
            for (tok = strtok_s(tmp, "|", &next); tok; tok = strtok_s(NULL, "|", &next)) {
                if (strcmp(tok, modBase) == 0) {
                    matched = TRUE;
                    break;
                }
            }
            if (!matched && svcNames[j][0] &&
                strncmp(svcNames[j], modBase, strlen(modBase)) == 0 &&
                (svcNames[j][strlen(modBase)] == '|' || svcNames[j][strlen(modBase)] == 0))
                matched = TRUE;
            if (matched)
                break;
        }

        /* 可疑驱动对象：路径不在系统目录、或磁盘上找不到对应文件。
         * dump_*.sys 是崩溃转储栈的临时映像，本来就没有磁盘文件，排除。 */
        if (strncmp(modBase, "dump_", 5) == 0) {
            suspicious = FALSE;
            reason[0] = 0;
        } else
        {
            char lowerPath[320];
            size_t k;
            for (k = 0; m->Path[k] && k + 1 < sizeof(lowerPath); k++)
                lowerPath[k] = (char)tolower((unsigned char)m->Path[k]);
            lowerPath[k] = 0;
            if (m->Path[0] && strstr(lowerPath, "\\systemroot\\") == NULL &&
                strstr(lowerPath, "\\system32\\") == NULL) {
                suspicious = TRUE;
                strcat_s(reason, sizeof(reason), "not under System32; ");
            }
            if (m->Path[0]) {
                WCHAR wpath[640];
                WCHAR expanded[640];
                const WCHAR *use = wpath;
                const char *p = m->Path;
                if (_strnicmp(p, "\\SystemRoot\\", 12) == 0) {
                    WCHAR winDir[320];
                    GetWindowsDirectoryW(winDir, 320);
                    swprintf_s(expanded, 640, L"%s\\%S", winDir, p + 12);
                    use = expanded;
                } else if (p[0] == '\\' && p[1] == '?' && p[2] == '?' && p[3] == '\\') {
                    MultiByteToWideChar(CP_ACP, 0, p + 4, -1, expanded, 640);
                    use = expanded;
                } else {
                    MultiByteToWideChar(CP_ACP, 0, p, -1, wpath, 640);
                }
                if (GetFileAttributesW(use) == INVALID_FILE_ATTRIBUTES) {
                    suspicious = TRUE;
                    strcat_s(reason, sizeof(reason), "file not on disk; ");
                }
            }
        }

        if (suspicious && Suspicious) {
            FE_HDRV_ENTRY *e;
            if (Suspicious->Count == Suspicious->Capacity) {
                ULONG cap = Suspicious->Capacity ? Suspicious->Capacity * 2 : 16;
                FE_HDRV_ENTRY *p = (FE_HDRV_ENTRY *)realloc(
                    Suspicious->Items, cap * sizeof(FE_HDRV_ENTRY));
                if (p) { Suspicious->Items = p; Suspicious->Capacity = cap; }
            }
            if (Suspicious->Count < Suspicious->Capacity) {
                e = &Suspicious->Items[suspCount++];
                ZeroMemory(e, sizeof(*e));
                strncpy_s(e->Name, sizeof(e->Name), m->Name, _TRUNCATE);
                e->Base = m->Base;
                e->Size = m->Size;
                strncpy_s(e->Path, sizeof(e->Path), m->Path, _TRUNCATE);
                strncpy_s(e->Reason, sizeof(e->Reason), reason, _TRUNCATE);
                Suspicious->Count = suspCount;
            }
        }

        if (!matched && !FeIsCoreKernelModule(modBase) &&
            strncmp(modBase, "dump_", 5) != 0 && Hidden) {
            FE_HDRV_ENTRY *e;
            if (Hidden->Count == Hidden->Capacity) {
                ULONG cap = Hidden->Capacity ? Hidden->Capacity * 2 : 16;
                FE_HDRV_ENTRY *p = (FE_HDRV_ENTRY *)realloc(
                    Hidden->Items, cap * sizeof(FE_HDRV_ENTRY));
                if (p) { Hidden->Items = p; Hidden->Capacity = cap; }
            }
            if (Hidden->Count < Hidden->Capacity) {
                e = &Hidden->Items[hiddenCount++];
                ZeroMemory(e, sizeof(*e));
                strncpy_s(e->Name, sizeof(e->Name), m->Name, _TRUNCATE);
                e->Base = m->Base;
                e->Size = m->Size;
                strncpy_s(e->Path, sizeof(e->Path), m->Path, _TRUNCATE);
                strncpy_s(e->Reason, sizeof(e->Reason),
                          "loaded in kernel but no matching service", _TRUNCATE);
                Hidden->Count = hiddenCount;
            }
        }
    }

    free(svcNames);
    FeFreeDrivers(&svcs);
    FeFreeKernelModules(&mods);
    return TRUE;
}

void FeFreeHiddenDrivers(FE_HDRV_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintHiddenDrivers(void)
{
    FE_HDRV_LIST hidden, suspicious;
    ULONG i;

    if (!FeLoadHiddenDrivers(&hidden, &suspicious)) {
        printf("hidden drivers: query failed\n");
        return FALSE;
    }
    printf("hidden drivers: %lu\n", hidden.Count);
    for (i = 0; i < hidden.Count; i++)
        printf("  %-28s %016I64X  %s\n", hidden.Items[i].Name,
               hidden.Items[i].Base, hidden.Items[i].Path);
    printf("suspicious driver objects: %lu\n", suspicious.Count);
    for (i = 0; i < suspicious.Count; i++)
        printf("  %-28s %016I64X  %-40s %s\n", suspicious.Items[i].Name,
               suspicious.Items[i].Base, suspicious.Items[i].Reason,
               suspicious.Items[i].Path);
    FeFreeHiddenDrivers(&hidden);
    FeFreeHiddenDrivers(&suspicious);
    return TRUE;
}

/* ---------------------------------------------------- SSDT 恢复（0xE7 / 0xEB）
 * 原版 SSDT 页状态栏的 Restore / Restore All 对应驱动里的两个命令：
 *   0xE7 CmdRestoreSsdtTable  —— 无输入，恢复服务表描述符（全量）
 *   0xEB CmdSetSsdtEntry      —— 输入 4 字节选择子 0..6：
 *                                0 恢复 ServiceTableCount，
 *                                1..6 把 KiServiceTable[1..6] 写回初始化时保存的地址
 * 返回值：1 成功，0 拒绝（参数/表指针不满足）。 */
BOOL FeRestoreSsdtAll(XPCH_CLIENT *Client, BYTE *pResult)
{
    BYTE out[1];
    UCHAR res = 0;
    BOOL ok;

    if (pResult)
        *pResult = 0;
    if (!Client || !Client->Opened)
        return FALSE;
    ZeroMemory(out, sizeof(out));
    ok = XpchInvoke(Client, 0xE7, NULL, 0, out, sizeof(out), &res);
    if (pResult)
        *pResult = res;
    return ok;
}

BOOL FeRestoreSsdtEntry(XPCH_CLIENT *Client, ULONG Selector, BYTE *pResult)
{
    DWORD in = (DWORD)Selector;
    BYTE out[1];
    UCHAR res = 0;
    BOOL ok;

    if (pResult)
        *pResult = 0;
    if (!Client || !Client->Opened)
        return FALSE;
    if (Selector > 6)
        return FALSE;
    ZeroMemory(out, sizeof(out));
    ok = XpchInvoke(Client, 0xEB, &in, sizeof(in), out, sizeof(out), &res);
    if (pResult)
        *pResult = res;
    return ok;
}

/* ---------------------------------------------------------------------------
 * Kernel 页状态栏的三项"其他内核项"
 *
 * KiDebugRoutine Hooked
 *   KUSER_SHARED_DATA (0x7FFE0000) 的 +0x2D0 是 KiDebugRoutine 指针。
 *   正常机器上它指向 ntoskrnl/KdDebug 里的函数；被 hook 时指向别处。
 *   判据：指针可读，且落在已加载的内核模块范围内 —— 否则报 Hooked。
 *   这是只读判断，不写任何东西。
 *
 * Find PTE Hook
 *   自映射页：PTE for VA 所在页 = (VA >> 9 & 0x7FFFFFFFF8) + 0xFFFF000000000000
 *   （x64 4 级页表自引用索引 0x1ED 所在区域）。
 *   做法：取内核模块里一个已知地址，同时用 ① 模块基址+偏移 ② 自映射 PTE
 *   里记录的 PFN 反算物理地址，两者不一致即为 PTE hook。
 *   本实现比较 ntoskrnl 基址与其 PTE 记录的 PFN，输出结论。
 *
 * Find Next ClassInitData
 *   原版在 ntoskrnl 的数据段里找 "ClassInitData" 相邻的 DriverEntry 链。
 *   这一项需要内核内存读取能力；本复刻的 0x217 尚未验证输出布局，
 *   因此这里如实报告不可用，不伪造数据。
 * ------------------------------------------------------------------------- */

/* KiDebugRoutine Hooked
 *
 * 【2026-10-23 订正】原来的理由写错了。用 kd 在目标机（Win10 18362）
 * 实测：
 *     x nt!KiDebugRoutine   → 无输出
 *     x nt!KiDebug*         → 只有 KiDebuggerOwner / KiDebugTrapOrFault /
 *                             KiDebugServiceTrap / KiDebugTrapIndex 等，
 *                             没有 KiDebugRoutine
 * `KiDebugRoutine` 是 Win7 及更早版本的 ntoskrnl 全局变量，Win8 起已删除
 * （调试器挂钩点改成 PTE/中断路径，不再是这个函数指针）。
 *
 * 所以这一项在 Win10 上**目标本身不存在**，不是「读不到」。
 * 之前写「不在 KUSER_SHARED_DATA、要读任意内核地址」——
 * 前提就错了：它根本不在任何位置，找什么都不对。
 *
 * 函数返回 FALSE 且 Detail 说明原因；不输出 "not hooked" 之类的阴性结论
 * —— 目标不存在不等于"检查过、没发现 hook"。
 */
BOOL FeCheckKiDebugRoutine(ULONG64 *pValue, BOOL *pHooked,
                           char *Detail, size_t DetailChars)
{
    if (pValue) *pValue = 0;
    if (pHooked) *pHooked = FALSE;
    if (Detail && DetailChars)
        strcpy_s(Detail, DetailChars,
                 "KiDebugRoutine: not present on this Windows version - "
                 "the global was removed after Windows 7 (kd: x nt!KiDebugRoutine "
                 "finds nothing; Win10 uses PTE/interrupt based debug hooks)");
    return FALSE;
}


/* Find PTE Hook
 *
 * 判定 PTE 是否被 hook 必须真正读到目标 VA 的自映射 PTE 项并比较 PFN。
 * 驱动里最接近的两条读命令是 0xF7（CmdReadKernelMemoryToUserBuffer）
 * 与 0xF9（CmdReadKernelMemoryRange），但它们的实现都是
 *     p = GtRead(<固定槽>); *out = *p;
 * 即「读某个由 InitKernelMemoryContext 解析出来的固定指针」，不接收用户
 * 指定的地址。0x20/0x25 只读进程内存。因此没有任意 VA 读通道，
 * 如实返回 FALSE 并说明原因，不输出阴性结论。
 */
BOOL FeFindPteHook(char *Detail, size_t DetailChars, BOOL *pHooked)
{
    if (pHooked) *pHooked = FALSE;
    if (Detail && DetailChars)
        strcpy_s(Detail, DetailChars,
                 "Find PTE Hook: needs an arbitrary kernel-address read; "
                 "0xF7/0xF9 only read one fixed GT-resolved pointer, "
                 "0x20/0x25 are process-only");
    return FALSE;
}
