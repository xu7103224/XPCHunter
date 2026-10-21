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
