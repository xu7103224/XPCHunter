/* ============================================================================
 * system.c —— 模块、句柄、内核模块、驱动、隐藏驱动
 *
 * 数据源分工（2026-11-03 内核化改造后）：
 *   内核模块   —— 0x0C5 SDK 扩展命令（DriverSection 加载链）
 *   驱动服务   —— SCM EnumServicesStatusEx（服务配置枚举，非内核访问）
 *   系统句柄   —— 0x26 CmdEnumHandles（驱动）
 *   隐藏驱动   —— 0x0C5 内核模块列表与驱动服务列表的差集（推导）
 * ==========================================================================*/
#include "XpchSdk_internal.h"
#include <psapi.h>
#include <winternl.h>

/* ============================================================
 * 进程模块
 * ============================================================*/
/* ============================================================
 * 系统句柄（0x26）
 *
 * 输出布局（实机校准，146 条真实进程）：
 *   +0x00 DWORD count
 *   每条 552 字节（138 个 DWORD）：
 *     +0x08 MarkType(1=新进程)   +0x09 受保护标志
 *     +0x10/+0x20 创建时间       +0x18 PID
 *     +0x28 进程对象指针         +0x30 映像路径(UTF-16)
 * 注意这是"进程记录"而非逐句柄；真正的逐句柄枚举命令在 0x26 家族里
 * 输出布局随版本变化，此处只暴露已稳定的进程维度。
 * ============================================================*/
#define HANDLE_RECORD_STRIDE  552u
#define HANDLE_RECORD_MAX     512u
#define HANDLE_PID_OFF        0x18u
#define HANDLE_OBJECT_OFF     0x28u
#define HANDLE_PATH_OFF       0x30u

XPCH_STATUS XpchEnumSystemHandles(XPCH_SESSION *Session,
                                  XPCH_HANDLE_INFO **Handles, ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *Buf;
    SIZE_T OutSize;
    XPCH_STATUS St;
    XPCH_HANDLE_INFO *Items;
    ULONG i, Cnt;

    if (!Session || !Handles || !Count)
        return XPCH_E_INVALID_ARG;
    *Handles = NULL;
    *Count = 0;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    OutSize = 4u * 1024u * 1024u;
    Buf = (BYTE *)XpchAlloc(OutSize);
    if (!Buf)
        return XPCH_E_NO_MEMORY;

    St = XpchInvokeRaw(Session, CMD_ENUM_SYSTEM_HANDLES, NULL, 0,
                       Buf, (ULONG)OutSize);
    if (St != XPCH_OK) {
        XpchFreeInternal(Buf);
        return St;
    }

    Cnt = *(ULONG *)Buf;
    if (Cnt > HANDLE_RECORD_MAX)
        Cnt = HANDLE_RECORD_MAX;
    if (Cnt == 0) {
        XpchFreeInternal(Buf);
        return XPCH_E_NO_DATA;
    }

    Items = (XPCH_HANDLE_INFO *)XpchAlloc((SIZE_T)Cnt * sizeof(XPCH_HANDLE_INFO));
    if (!Items) {
        XpchFreeInternal(Buf);
        return XPCH_E_NO_MEMORY;
    }

    for (i = 0; i < Cnt; i++) {
        const BYTE *Rec = Buf + (SIZE_T)i * HANDLE_RECORD_STRIDE;
        if ((SIZE_T)(Rec - Buf) + HANDLE_PATH_OFF >= OutSize)
            break;
        Items[i].Pid = *(const ULONG *)(Rec + HANDLE_PID_OFF);
        Items[i].Object = *(const ULONG64 *)(Rec + HANDLE_OBJECT_OFF);
        Items[i].HandleIndex = 0;          /* 该命令不提供逐句柄索引 */
        Items[i].ObjectTypeIndex = 0;
        Items[i].GrantedAccess = 0;
        Items[i].TypeName[0] = 0;
        /* 映像路径保留在 Object 字段之外，此处不搬运（结构里没有对应字段） */
    }

    XpchFreeInternal(Buf);
    *Handles = Items;
    *Count = Cnt;
    return XPCH_OK;
}

/* ============================================================
 * 内核模块（psapi EnumDeviceDrivers）
 * ============================================================*/
XPCH_STATUS XpchEnumKernelModules(XPCH_SESSION *Session, XPCH_KERNEL_MODULE **Modules, ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *Out;
    ULONG OutSize = 4 + 1024 * 80;
    XPCH_STATUS St;
    XPCH_KERNEL_MODULE *Items;
    ULONG i, N;

    if (!Modules || !Count)
        return XPCH_E_INVALID_ARG;
    *Modules = NULL;
    *Count = 0;
    if (!Session)
        return XPCH_E_INVALID_ARG;
    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    Out = (BYTE *)XpchAlloc(OutSize);
    if (!Out)
        return XPCH_E_NO_MEMORY;

    /* 0x0C5：从驱动自身 DriverSection 沿 InLoadOrderLinks 遍历 */
    St = XpchInvokeRaw(Session, CMD_X_ENUM_KERNEL_MODULES, NULL, 0,
                       Out, OutSize);
    if (St != XPCH_OK) {
        XpchFreeInternal(Out);
        return St;
    }

    N = *(ULONG *)Out;
    if (N == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_DATA;
    }

    Items = (XPCH_KERNEL_MODULE *)XpchAlloc((SIZE_T)N * sizeof(XPCH_KERNEL_MODULE));
    if (!Items) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_MEMORY;
    }

    /* 驱动条目 80 字节：{ u64 Base; u32 SizeOfImage; CHAR Name[64] } */
    for (i = 0; i < N; i++) {
        const BYTE *E = Out + 4 + (SIZE_T)i * 80;
        ZeroMemory(&Items[i], sizeof(Items[i]));
        Items[i].Base = *(const ULONG64 *)(E + 0);
        Items[i].Size = *(const ULONG *)(E + 8);
        memcpy(Items[i].Name, E + 16, 64);
        Items[i].Name[XPCH_KMOD_NAME_CHARS - 1] = 0;
    }

    XpchFreeInternal(Out);
    *Modules = Items;
    *Count = N;
    return XPCH_OK;
}

/* ============================================================
 * 驱动服务（SCM）
 * ============================================================*/
XPCH_STATUS XpchEnumDrivers(XPCH_DRIVER_INFO **Drivers, ULONG *Count)
{
    SC_HANDLE Scm, Svc;
    LPBYTE Buf = NULL;
    DWORD Needed = 0, Got = 0, Resume = 0, Count_ = 0;
    XPCH_DRIVER_INFO *Items;
    ULONG n = 0;

    if (!Drivers || !Count)
        return XPCH_E_INVALID_ARG;
    *Drivers = NULL;
    *Count = 0;

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!Scm)
        return XPCH_E_ACCESS_DENIED;

    if (!EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                               SERVICE_STATE_ALL, NULL, 0, &Needed, &Got,
                               &Resume, NULL)) {
        if (GetLastError() != ERROR_MORE_DATA) {
            CloseServiceHandle(Scm);
            return XPCH_E_NO_DATA;
        }
    }
    if (!Needed) {
        CloseServiceHandle(Scm);
        return XPCH_E_NO_DATA;
    }

    Buf = (LPBYTE)XpchAlloc(Needed);
    if (!Buf) {
        CloseServiceHandle(Scm);
        return XPCH_E_NO_MEMORY;
    }

    Resume = 0;
    if (!EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                               SERVICE_STATE_ALL, Buf, Needed, &Got,
                               &Count_, &Resume, NULL)) {
        XpchFreeInternal(Buf);
        CloseServiceHandle(Scm);
        return XPCH_E_NO_DATA;
    }

    Items = (XPCH_DRIVER_INFO *)XpchAlloc(
                (SIZE_T)Count_ * sizeof(XPCH_DRIVER_INFO));
    if (!Items) {
        XpchFreeInternal(Buf);
        CloseServiceHandle(Scm);
        return XPCH_E_NO_MEMORY;
    }

    {
        ENUM_SERVICE_STATUS_PROCESSW *Arr =
            (ENUM_SERVICE_STATUS_PROCESSW *)Buf;
        DWORD i;
        for (i = 0; i < Count_; i++) {
            XPCH_DRIVER_INFO *D = &Items[n];
            DWORD BytesNeeded = 0;

            WideCharToMultiByte(CP_ACP, 0, Arr[i].lpServiceName, -1,
                                D->Name, XPCH_DRV_NAME_CHARS, NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0, Arr[i].lpDisplayName, -1,
                                D->Display, XPCH_DRV_DISP_CHARS, NULL, NULL);

            D->State = Arr[i].ServiceStatusProcess.dwCurrentState;
            D->Type  = Arr[i].ServiceStatusProcess.dwServiceType;
            D->Start = 0;
            D->Path[0] = 0;

            /* 逐个查 ImagePath 与启动类型 */
            Svc = OpenServiceW(Scm, Arr[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (Svc) {
                LPQUERY_SERVICE_CONFIGW Cfg = NULL;
                DWORD CfgNeeded = 0;
                QueryServiceConfigW(Svc, NULL, 0, &CfgNeeded);
                if (CfgNeeded) {
                    Cfg = (LPQUERY_SERVICE_CONFIGW)XpchAlloc(CfgNeeded);
                    if (Cfg && QueryServiceConfigW(Svc, Cfg, CfgNeeded, &BytesNeeded)) {
                        D->Start = Cfg->dwStartType;
                        if (Cfg->lpBinaryPathName)
                            WideCharToMultiByte(CP_ACP, 0, Cfg->lpBinaryPathName,
                                                -1, D->Path, XPCH_DRV_PATH_CHARS,
                                                NULL, NULL);
                    }
                    XpchFreeInternal(Cfg);
                }
                CloseServiceHandle(Svc);
            }
            n++;
        }
    }

    XpchFreeInternal(Buf);
    CloseServiceHandle(Scm);

    if (n == 0) {
        XpchFreeInternal(Items);
        return XPCH_E_NO_DATA;
    }

    *Drivers = Items;
    *Count = n;
    return XPCH_OK;
}

/* ============================================================
 * 隐藏驱动：内核模块里有、驱动服务里没有
 * ============================================================*/
XPCH_STATUS XpchEnumHiddenDrivers(XPCH_SESSION *Session,
                                  XPCH_KERNEL_MODULE **Hidden, ULONG *Count)
{
    XPCH_KERNEL_MODULE *Mods = NULL;
    XPCH_DRIVER_INFO *Drvs = NULL;
    ULONG ModCount = 0, DrvCount = 0, i, j, n = 0;
    XPCH_KERNEL_MODULE *Out;
    XPCH_STATUS St;

    UNREFERENCED_PARAMETER(Session);

    if (!Hidden || !Count)
        return XPCH_E_INVALID_ARG;
    *Hidden = NULL;
    *Count = 0;

    St = XpchEnumKernelModules(Session, &Mods, &ModCount);
    if (St != XPCH_OK)
        return St;
    St = XpchEnumDrivers(&Drvs, &DrvCount);
    if (St != XPCH_OK) {
        XpchFreeInternal(Mods);
        return St;
    }

    Out = (XPCH_KERNEL_MODULE *)XpchAlloc(
              (SIZE_T)ModCount * sizeof(XPCH_KERNEL_MODULE));
    if (!Out) {
        XpchFreeInternal(Mods);
        XpchFreeInternal(Drvs);
        return XPCH_E_NO_MEMORY;
    }

    for (i = 0; i < ModCount; i++) {
        BOOL Found = FALSE;
        const char *ModName = Mods[i].Name;

        if (!ModName[0])
            continue;

        for (j = 0; j < DrvCount; j++) {
            /* 驱动服务的 ImagePath 末尾通常是 "xxx.sys"，
               内核模块名是 "xxx.sys"，用子串匹配 */
            if (_strnicmp(Mods[i].Name, Drvs[j].Name, strlen(Drvs[j].Name)) == 0
                || strstr(Drvs[j].Path, Mods[i].Name) != NULL) {
                Found = TRUE;
                break;
            }
        }
        if (!Found)
            Out[n++] = Mods[i];
    }

    XpchFreeInternal(Mods);
    XpchFreeInternal(Drvs);

    if (n == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_DATA;
    }

    *Hidden = Out;
    *Count = n;
    return XPCH_OK;
}