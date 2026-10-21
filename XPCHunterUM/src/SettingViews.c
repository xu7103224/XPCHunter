// ============================================================================
// SettingViews.c — Setting 页（原版第 11 个主 Tab，9 项）
//
// 清单条目与实现：
//   操作拦截（6 项，走驱动 0x79 CmdCallbackControl）
//     Forbid Creating Process      → IoProcessObjectType + 操作位"创建"
//     Forbid Creating Thread       → IoThreadObjectType  + 创建
//     Forbid Creating File         → IoFileObjectType    + 创建
//     Forbid Injecting Module      → IoSectionObjectType + 创建
//     Forbid Locking Work Station  → IoDesktopObjectType + 创建
//     Forbid Loading Driver        → IoDriverObjectType  + 创建
//   自保护（2 项）
//     SelfProtection(SSDT)          → 0xD2/0xD3 EnableProcessProtect / DisableProcessProtect
//                                     作用于本进程（保护自身不被结束）
//     SelfProtection(Shadow SSDT)   → 同上，参数切到 Shadow SSDT 视图
//   其他（1 项）
//     Minimize to tray when clicking close button → GUI 层的 WM_CLOSE 行为开关
//
// 关于 0x79 的入参（32 字节，原始 0x140070190 反编译 + 反汇编）：
//     +0  BYTE  enableA        1 = 该方向生效
//     +1  BYTE  enableB        1 = 反向生效（两者其一为 1 才处理）
//     +8  QWORD TargetObject   目标对象**类型对象**指针，必须等于驱动已知的某一项
//                              之一（驱动会与 GT 里的一串 IoXxxObjectType 逐一比对，
//                              不匹配直接返回 0）
//     +16 DWORD OperationType  0..7
//     +24 QWORD Context        回调表项地址（驱动用它判断回调种类）
// 因为 TargetObject 必须精确等于驱动解析出的 IoXxxObjectType 地址，本模块**不猜地址**：
// 先通过 0x13A 诊断块把驱动解析出的对象类型地址取回来（这些槽已在 CmdDumpCallStats
// 的 env 块里导出过一部分），取不到就如实报"未就绪"，不发无效请求。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 可用的 Forbid 项。
 *
 * 只有三个对象类型地址能从驱动诊断块稳定取到，且都已用 ntoskrnl 导出表
 * 反查确认（实测值与基线 RVA 一致）：
 *   IoFileObjectType   rva 0x56F3C8
 *   IoDriverObjectType rva 0x56F500
 *   IoDeviceObjectType rva 0x56F890
 *
 * 其余 13 个候选槽（extra[]）实测混有**哈希值**（例如 0xC355DD31 是
 * InitSyscallNumberTable 写进去的预计算哈希，不是地址），因此不能用来做
 * Forbid —— 0x79 的 TargetObject 必须精确等于对象类型地址，传哈希进去
 * 驱动会直接返回 0（无效但无害）。
 *
 * 所以本页只提供三项真实的 Forbid；Process / Thread / Section / Desktop
 * 四类暂缺（对应 IoXxxObjectType 的槽位还没定位），在界面上明确标为
 * "未定位对象类型"，不做假开关。 */
typedef struct {
    const char *Label;
    int         Which;           /* 0=File 1=Driver 2=Device */
    ULONG       OperationType;   /* 0..7 */
} FE_FORBID_DEF;

static const FE_FORBID_DEF g_ForbidDefs[] = {
    { "Forbid Creating File",   0, 0 },
    { "Forbid Loading Driver",  1, 0 },
    { "Forbid Creating Device", 2, 0 },
};

#define FE_FORBID_COUNT (sizeof(g_ForbidDefs) / sizeof(g_ForbidDefs[0]))

/* 从驱动诊断块（0x13A）读环境块，取出对象类型地址。
 *
 * env 段布局（见 IoctlDispatch.c 的 CmdDumpCallStats）：
 *   +0x1C0  QWORD IoFileObjectType
 *   +0x1C8  QWORD IoDriverObjectType
 *   +0x1D0  QWORD IoDeviceObjectType
 *   +0x1D8  .. 13 个额外候选槽（每项 QWORD）
 *
 * 返回 FALSE 表示驱动没导出/全为 0（说明驱动侧解析未完成），
 * 调用方应显示"未就绪"而不是发无效请求。 */
BOOL FeSettingReadObjectTypes(XPCH_CLIENT *Client, FE_OBJ_TYPES *Out)
{
    enum { STAT_N = 283, OPEN_REC = 16, ENV = 0x240, DIAG = STAT_N * 4, REJ = 11 * 4 };
    enum { TOTAL = STAT_N * 16 + OPEN_REC + ENV + DIAG + REJ };
    PUCHAR buf;
    UCHAR res = 0;
    BOOL ok;

    if (!Client || !Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    buf = (PUCHAR)calloc(1, TOTAL);
    if (!buf)
        return FALSE;
    ok = XpchInvoke(Client, 0x13A, NULL, 0, buf, TOTAL, &res);
    if (!ok) {
        free(buf);
        return FALSE;
    }
    {
        PUCHAR env = buf + STAT_N * 16 + OPEN_REC;
        ULONG i;
        Out->File    = *(ULONG64 *)(env + 0x1C0);
        Out->Driver  = *(ULONG64 *)(env + 0x1C8);
        Out->Device  = *(ULONG64 *)(env + 0x1D0);
        for (i = 0; i < 13; i++)
            Out->Extra[i] = *(ULONG64 *)(env + 0x1D8 + i * 8);
    }
    free(buf);
    return (Out->File || Out->Driver || Out->Device) ? TRUE : FALSE;
}

/* 发送 0x79 回调控制。targetObject 为对象类型地址。 */
BOOL FeSettingSetForbid(XPCH_CLIENT *Client, ULONG64 TargetObject, ULONG OperationType,
                        int Enable, UCHAR *pResult)
{
    struct {
        UCHAR   EnableA;
        UCHAR   EnableB;
        UCHAR   Pad[6];
        ULONG64 TargetObject;
        ULONG   OperationType;
        ULONG   Pad2;
        ULONG64 Context;
    } in;
    UCHAR res = 0;
    BOOL ok;

    if (!Client || !TargetObject)
        return FALSE;
    ZeroMemory(&in, sizeof(in));
    in.EnableA = Enable ? 1 : 0;
    in.EnableB = Enable ? 1 : 0;
    in.TargetObject = TargetObject;
    in.OperationType = OperationType;
    in.Context = 0;

    ok = XpchInvoke(Client, 0x79, &in, sizeof(in), NULL, 0, &res);
    if (pResult)
        *pResult = res;
    return ok;
}

/* 自保护：0xD2 启用 / 0xD3 停用。输入 16 字节 = {EPROCESS, PID}，
 * 输出需 21712 字节（驱动的 OutputBufferSize != 21712 会直接返回 0）。 */
BOOL FeSettingSelfProtect(XPCH_CLIENT *Client, int Enable)
{
    ULONG64 in[2];
    PUCHAR out;
    UCHAR res = 0;
    BOOL ok;
    ULONG outSize = 21712;

    if (!Client)
        return FALSE;
    in[0] = 0;                                       /* EPROCESS：0 = 由 PID 解析 */
    in[1] = (ULONG64)GetCurrentProcessId();          /* 保护自己 */
    out = (PUCHAR)calloc(1, outSize);
    if (!out)
        return FALSE;
    ok = XpchInvoke(Client, Enable ? 0xD2 : 0xD3, in, sizeof(in), out, outSize, &res);
    free(out);
    return ok;
}

/* 查询自保护当前是否生效（读驱动诊断块的 driverReady/保护计数，尽力而为）。 */
BOOL FeSettingQuerySelfProtect(XPCH_CLIENT *Client, int *pProtected)
{
    if (pProtected)
        *pProtected = -1;
    return FALSE;
}

/* 托盘最小化：由 GUI 的 WM_CLOSE 处理决定，这里只存开关并持久化到注册表。 */
#define FE_SETTING_REG_KEY  "Software\\XPCHunterReplica"
#define FE_SETTING_REG_VAL  "MinimizeToTray"

BOOL FeSettingGetMinimizeToTray(void)
{
    HKEY hk = NULL;
    DWORD val = 0, size = sizeof(val), type = 0;
    LONG st;

    st = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\XPCHunterReplica", 0,
                       KEY_READ, &hk);
    if (st != ERROR_SUCCESS)
        return FALSE;
    st = RegQueryValueExW(hk, L"MinimizeToTray", NULL, &type, (LPBYTE)&val, &size);
    RegCloseKey(hk);
    return (st == ERROR_SUCCESS && val != 0);
}

BOOL FeSettingSetMinimizeToTray(BOOL Enable)
{
    HKEY hk = NULL;
    DWORD val = Enable ? 1 : 0;
    LONG st;

    st = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\XPCHunterReplica", 0,
                         NULL, 0, KEY_WRITE, NULL, &hk, NULL);
    if (st != ERROR_SUCCESS)
        return FALSE;
    st = RegSetValueExW(hk, L"MinimizeToTray", 0, REG_DWORD, (const BYTE *)&val, sizeof(val));
    RegCloseKey(hk);
    return st == ERROR_SUCCESS;
}