// ============================================================================
// XPCHunter Frontend - Win32 GUI command tester
//
// Purpose: exercise the driver command channel and show, per command,
// whether it succeeds. This is the "test commands through the frontend"
// deliverable.
//
// Layout:
//   [Connect] [Scan All] [Send]   status: device / ioctl / key
//   command edit (0xNN)  output size edit
//   ListView: cmd | name | result | hex output (first bytes)
// ============================================================================

#include "XPCHunterUM.h"
#include "CliMain.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")

/* 本文件是 /DUNICODE 编译的，而所有列表标题都是 ANSI 字面量（LVCOLUMNA）。
 * ListView_InsertColumn 在 UNICODE 下展开成 LVM_INSERTCOLUMNW (0x1061)，
 * 会把 char* 当 wchar_t* 读，表头就成了乱码。这里统一改走 ANSI 通道。 */
int FeInsertColumnA(HWND h, int i, const LVCOLUMNA *pc)
{
    LVCOLUMNA copy;

    if (!pc)
        return 0;
    copy = *pc;
    return (int)SendMessageA(h, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&copy);
}

XPCH_CLIENT g_Client; /* 2026-10-28 去静态：CliMain.c 共用 */
static HWND g_hStatus;   /* 主窗口状态栏（main 模块） */
HWND g_hMainTabs, g_hPageHint;
HWND g_hMainWnd;
/* 第二步增量2：Process 页的列过滤输入框（PageShow 控制显隐） */
HWND g_hProcFilter = NULL;
/* 第二步增量：统一刷新模型——当前页的 auto-refresh 入口（页模块设置） */
void (*g_AutoRefFn)(void) = NULL;
/* Key 子页当前打开的路径；Kernel 页 "Locate in Registry Tab" 会改写它 */
/* Network 页（主 Tab 4）：原版为 "Network Callback" 树 + 右侧 6 列列表。
   树由 sub_1400A78F0 按系统 build 构建，节点 lParam = formatter case 号；
   选中节点由 sub_1400A70D0 调 sub_1400A7750(page, 1) 重建列并填表。
   已解码数据源（见 src/NetworkViews.c）：
     节点 1 NdisTdiCallback —— cmd 0xE6 / 恢复 0xE7
     节点 2 TdiPnpClient     —— cmd 0xE8 */
int  g_MainTab = 0;    /* 当前主 Tab（0 = Process） */
int  g_StartTab = 0;   /* 2026-10-28 去静态：CliMain.c 的 --tab 块写入 */   /* --tab N：启动时预选 Process 的子视图页 */

/* 原版 PCHunter 的 14 个主 Tab，顺序与 docs/reversing/原版前端功能地图.md 一致 */
static const char *g_MainTabNames[14] = {
    "Process", "Kernel", "Ring0 Hooks", "Ring3 Hooks", "Network",
    "Registry", "Startup Info", "Services", "File", "Examination",
    "Setting", "Fireeye", "Trojan Detection", "Other"
};

/* Names for the commands we know (index = cmd - 0x20). Others show "-". */
static const char *CmdName(ULONG cmd)
{
    switch (cmd) {
    case 0x20: return "CmdReadProcessMemory";
    case 0x21: return "CmdResetProcessContext";
    case 0x22: return "CmdQueryProcessInfo";
    case 0x24: return "CmdGetModuleCount";
    case 0x25: return "CmdEnumKernelDrivers";
    case 0x26: return "CmdEnumHandles";
    case 0x27: return "CmdCheckProcessAccess";
    case 0x28: return "CmdProcessOperation";
    case 0x2A: return "CmdEnumThreads";
    default:   return "-";
    }
}

void SetStatus(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    SetWindowTextA(g_hStatus, buf);
}

void SetSubItemText(int iItem, int iSub, const char *text);

void AddRow(ULONG cmd, const char *result, const char *detail)
{
    LVITEMA item;
    int idx = (int)SendMessageA(g_hList, LVM_GETITEMCOUNT, 0, 0);
    char cbuf[16];

    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = idx;

    sprintf_s(cbuf, sizeof(cbuf), "0x%02X", cmd);
    item.iSubItem = 0;
    item.pszText = cbuf;
    /* The build defines UNICODE, so the ListView_* macros expand to the W
       variants.  This frontend is deliberately ANSI, hence the explicit
       A-suffixed messages. */
    SendMessageA(g_hList, LVM_INSERTITEMA, 0, (LPARAM)&item);

    SetSubItemText(idx, 1, CmdName(cmd));
    SetSubItemText(idx, 2, result);
    SetSubItemText(idx, 3, detail);
}

void SetSubItemText(int iItem, int iSub, const char *text)
{
    LVITEMA item;
    ZeroMemory(&item, sizeof(item));
    item.iSubItem = iSub;
    item.pszText = (LPSTR)text;
    SendMessageA(g_hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&item);
}

/* Command call shapes, mirrored from probe.c.

   Every handler validates its own InSize/OutSize before doing anything, so
   the front end must send the shape the handler expects. Commands absent
   from this table get a 1-byte output buffer: enough to receive the result
   code byte, and small enough that a handler which forgets to validate
   OutSize fails fast instead of writing past the buffer. */
typedef struct _FE_SHAPE { ULONG Cmd; ULONG InSize; ULONG OutSize; } FE_SHAPE;

static const FE_SHAPE g_FeShapes[] = {
    { 0x20, 8,    0      },  /* CmdReadProcessMemory      in: ULONG64 addr           */
    { 0x22, 0,    4      },  /* CmdQueryProcessInfo       out: DWORD                 */
    { 0x24, 0,    4      },  /* CmdGetModuleCount         out: DWORD build#          */
    { 0x26, 0,    0x240  },  /* CmdEnumHandles                                       */
    { 0x2A, 8,    520    },  /* CmdEnumThreads            in: pid, out: WCHAR[260]   */
    { 0x2B, 16,   0      },  /* CmdReadProcessMemoryBlock                            */
    { 0x37, 16,   0x40   },  /* CmdReadProcessMemoryEx                               */
    { 0x3C, 0,    0x1000 },  /* CmdEnumKernelModules                                 */
    { 0x42, 0,    0x40   },  /* CmdQuerySsdtInfo                                     */
    { 0x54, 0,    0x300  },  /* CmdEnumProcessHandles                                */
    { 0x7F, 0,    0      },  /* CmdStubAlwaysTrue                                    */
    { 0xAB, 0,    0x1000 },  /* CmdQueryObjectInfo                                   */
    { 0xB0, 0,    0x1000 },  /* CmdEnumSyscallTable2                                 */
    { 0xE1, 0,    0x1E0  },  /* CmdEnumProcessListEx                                 */
    { 0xE2, 0,    0x1E0  },  /* CmdEnumProcessListWin7                               */
    { 0xE3, 0,    0x1E0  },  /* CmdEnumProcessListWin8                               */
    { 0xE4, 0,    0x1E0  },  /* CmdEnumProcessListWin10                              */
    { 0xE6, 0,    0x40   },  /* CmdGetSsdtTableInfo                                  */
    { 0xE8, 0,    0x300  },  /* CmdEnumObjectTypeInfo                                */
    { 0x10B,0,    0x90   },  /* MiniFilterPreAcquire                                 */
};

/* Commands that need front-end state this build does not establish yet.
   Sending them bare dereferences an uninitialised kernel pointer, so the
   tester reports them as SKIP rather than taking the guest down. See
   probe.c's g_SkipCommands for the per-command reason. */
static const ULONG g_FeSkip[] = { 0x25, 0x28, 0x30, 0x56, 0x115 };

BOOL FeIsSkipped(ULONG cmd)
{
    size_t i;
    for (i = 0; i < sizeof(g_FeSkip) / sizeof(g_FeSkip[0]); i++)
        if (g_FeSkip[i] == cmd)
            return TRUE;
    return FALSE;
}

static const FE_SHAPE *FeShapeOf(ULONG cmd)
{
    size_t i;
    for (i = 0; i < sizeof(g_FeShapes) / sizeof(g_FeShapes[0]); i++)
        if (g_FeShapes[i].Cmd == cmd)
            return &g_FeShapes[i];
    return NULL;
}

/* Send one command using its known shape (1-byte out otherwise). */
BOOL SendOne(ULONG cmd, ULONG outSize, char *detail, size_t detailLen)
{
    const FE_SHAPE *shape = FeShapeOf(cmd);
    BYTE *out = NULL;
    ULONG64 inArg = 0;
    ULONG inSize;
    UCHAR res = 0;
    BOOL ok;

    if (FeIsSkipped(cmd)) {
        sprintf_s(detail, detailLen, "SKIP: needs front-end state");
        return FALSE;
    }

    if (shape) {
        inSize  = shape->InSize;
        outSize = shape->OutSize;
    } else {
        inSize  = 0;
        outSize = 1;
    }
    if (outSize > 0x10000)
        outSize = 0x10000;

    if (outSize) {
        out = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSize);
        if (!out) {
            sprintf_s(detail, detailLen, "alloc failed");
            return FALSE;
        }
    }

    SetLastError(0);
    ok = XpchInvoke(&g_Client, cmd,
                    inSize ? &inArg : NULL, inSize,
                    out, outSize, &res);

    if (!ok) {
        sprintf_s(detail, detailLen, "result=%u", res);
    } else if (out && outSize >= 8) {
        sprintf_s(detail, detailLen, "%02X %02X %02X %02X %02X %02X %02X %02X",
                  out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
    } else if (out && outSize >= 4) {
        sprintf_s(detail, detailLen, "%lu", *(ULONG *)out);
    } else {
        sprintf_s(detail, detailLen, "OK");
    }

    if (out)
        HeapFree(GetProcessHeap(), 0, out);
    return ok;
}

HWND g_hList;    /* Process 列表/命令/大小控件（Proc 页） */
HWND g_hCmd;
HWND g_hSize;
static void DoConnect(void)
{
    if (g_Client.Opened) {
        XpchClose(&g_Client);
        SetStatus("Disconnected");
        return;
    }

    if (!XpchOpen(&g_Client)) {
        SetStatus("Open %ls FAILED, GetLastError=%lu", XPCH_DEVICE_NAME, GetLastError());
        return;
    }

    /* 必须先握手：驱动就绪标志 GT[0x304] 为 0 时除 0x22 以外的命令全部被拒 */
    XpchHandshake(&g_Client);

    SetStatus("Connected  device=%ls  ioctl=0x%08X  key=0x%02X",
              XPCH_DEVICE_NAME, g_Client.IoControlCode, g_Client.KeyByte);
}

static void DoScan(void)
{
    ULONG cmd;
    int okCount = 0, failCount = 0, skipCount = 0;
    char detail[128];

    if (!g_Client.Opened) {
        SetStatus("Not connected");
        return;
    }

    ListView_DeleteAllItems(g_hList);

    for (cmd = XPCH_CMD_MIN; cmd <= XPCH_CMD_MAX; cmd++) {
        if (FeIsSkipped(cmd)) {
            SendOne(cmd, 0, detail, sizeof(detail));
            AddRow(cmd, "SKIP", detail);
            skipCount++;
        } else if (SendOne(cmd, 256, detail, sizeof(detail))) {
            AddRow(cmd, "OK", detail);
            okCount++;
        } else {
            AddRow(cmd, "REJECTED", detail);
            failCount++;
        }
    }

    SetStatus("Scan done: %d OK, %d REJECTED, %d SKIP (total %d)",
              okCount, failCount, skipCount, okCount + failCount + skipCount);
}

static void DoSend(void)
{
    char cbuf[64];
    char detail[128];
    ULONG cmd = 0, size = 256;

    GetWindowTextA(g_hCmd, cbuf, sizeof(cbuf));
    cmd = (ULONG)strtoul(cbuf, NULL, 0);

    GetWindowTextA(g_hSize, cbuf, sizeof(cbuf));
    size = (ULONG)strtoul(cbuf, NULL, 0);

    if (!g_Client.Opened) {
        SetStatus("Not connected");
        return;
    }
    if (cmd < XPCH_CMD_MIN || cmd > XPCH_CMD_MAX) {
        SetStatus("Command 0x%02X out of range [0x20,0x13A]", cmd);
        return;
    }

    if (SendOne(cmd, size, detail, sizeof(detail))) {
        AddRow(cmd, "OK", detail);
        SetStatus("0x%02X OK", cmd);
    } else {
        AddRow(cmd, "FAIL", detail);
        SetStatus("0x%02X FAILED (%s)", cmd, detail);
    }
}

static void CreateListColumns(HWND h)
{
    LVCOLUMNA col;
    static const char *titles[] = { "Cmd", "Name", "Result", "Output" };
    static const int widths[] = { 60, 220, 70, 320 };
    int i;

    for (i = 0; i < 4; i++) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.iSubItem = i;
        col.pszText = (LPSTR)titles[i];
        col.cx = widths[i];
        SendMessageA(h, LVM_INSERTCOLUMNA, i, (LPARAM)&col);
    }
}

/* ---- Process 页 ---------------------------------------------------------- */

/* 进程列表的列：PID / 进程名 / EPROCESS。
   进程名来自驱动在条目 +0x08 写入的 EPROCESS.ImageFileName（15 字节 ANSI），
   完整路径需要 0x2A 的映像路径查询，而它依赖的 GT[GtEprocessField33]
   尚未在本移植里正确初始化（实测会 BSOD），因此暂不提供 Path 列。 */

/* ---- 明细子视图（Modules / Threads / Windows）--------------------------- */

static const char *g_TabNames[7] = { "Modules", "Threads", "Windows", "Handles",
                                     "Memory", "Timer", "HotKey" };

ULONG GetSelectedPid(void)
{
    int i = (int)SendMessageA(g_hProc, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    char buf[32];

    if (i < 0)
        return 0;
    buf[0] = 0;
    {
        LVITEMA item;
        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 0;
        item.pszText = buf;
        item.cchTextMax = sizeof(buf);
        SendMessageA(g_hProc, LVM_GETITEMTEXTA, (WPARAM)i, (LPARAM)&item);
    }
    return (ULONG)strtoul(buf, NULL, 10);
}





/* ç»æéä¸­è¿ç¨ï¼ç ´åæ§æä½ï¼åäºæ¬¡ç¡®è®¤ã */
void DoRefreshProcs(void);
void DoRefreshFiles(void);



/* ==========================================================================
 * 主 Tab 容器（M1）
 *
 * 原版是单窗口 + 14 个主 Tab。这里：
 *   顶部工具条（连接/刷新/命令测试器）   10..38
 *   主 Tab 栏                            44..68
 *   页面区（各页控件都建在主窗口里，按选中页显示/隐藏）
 *
 * 14 页全部有实现：0 Process / 1 Kernel / 2-3 Ring0+Ring3 Hooks /
 * 4 Network / 5 Registry / 6 Startup Info / 7 Services / 8 File /
 * 9 Examination / 10 Setting / 11 Fireeye / 12 Trojan Detection / 13 Other。
 * Network 页的 30 个字段无数据源（命令表审计确认原驱动无对应命令），
 * 页内如实标注，不伪造数据。
 * ========================================================================== */

/* ---- Startup Info 页（主 Tab 6）---- */



/* ---- Services 页（主 Tab 7）---- */


/* ==========================================================================
 * Network 页（主 Tab 4）—— 原版 Network Callback 树
 *
 * 两节已完整解码并接入真实命令（详见 src/NetworkViews.c 文件头）：
 *
 *   1) NdisTdiCallback  ← 0xE6 CmdGetSsdtTableInfo（实为 TDI 回调查询）
 *      原版客户端 sub_1400ABA60 / sub_140025470。固定两行：
 *        TdiRegisterDeviceObject ：当前 = out[4] / 原始 = out[2]
 *        TdiPnPHandler          ：当前 = out[5] / 原始 = out[3]
 *      当前值 != 原始值 → 列 "Hook" 显示 "Hook"，否则 "-"。
 *      恢复：0xE7（原版同级菜单，恢复后两行都应变成非 Hook）。
 *
 *   2) TdiPnpClient     ← 0xE8 CmdEnumObjectTypeInfo（实为 TDI PnP 客户端）
 *      原版客户端 sub_1400ADE50 / sub_140025570。每个客户端一条记录，
 *      五个 handler 每个非 0 就展开一行；字段名表 off_1406D03E8。
 *
 * 模块/公司两列由 0x42（selector=0）的驱动对象列表解析，与原版
 * sub_14001F980 / sub_14001F8B0 完全同源。
 * ========================================================================== */





/* 原版 sub_1400A78F0：按 build 条件插入节点，节点 5 是根级兄弟节点。 */



/* 原版恢复入口：sub_1400A6840 -> sub_140025510（cmd 0xE7），无参数。 */



/* Startup Info 页右键：Delete Startup / Delete(Startup And File) / Repair Startup。
 * 原版的这三项都在自启动项列表的右键菜单里。 */


/* Services 页右键：原版把服务的 ImagePath / ServiceDll 直接送到 FireEye 页
 * 分析（Analyse ImagePath by FireEye / Analyse ServiceDll by FireEye）。
 * 这里取选中行的服务名 → 重新查该服务 → 切到 FireEye 页并填入路径。 */


/* 取 Services 列表选中行的服务条目（重新查表以拿到完整字段）。 */

/* Services 页右键。对应功能地图第 8 节列出的操作：
     Delete Service(Not Delete File) / Verify ServiceDll Signature /
     Find ImagePath Target / Find ServiceDll Target /
     Copy ImagePath / Copy ServiceDll Path /
     Locate in File Tab (ImagePath / ServiceDll)
   另有 Analyse ImagePath/ServiceDll by FireEye（DoServiceFireeye 单独实现）。 */


/* ---- Registry 页（主 Tab 5）----
 * 两个子页：
 *   Reg Handle     全系统 ObjectType="Key" 的句柄（pid / handle / access / object）
 *   Hidden Item    控制字符键名 + HKCU\Software\Classes 独占项
 * 四列都可在列表里选中复制（Copy Key Name / RegPath / RegValue / RegData 由
 * 用户复制对应列实现；原版的复制菜单项文本与此一一对应）。 */



/* ---- File 页（主 Tab 8）---- */



/* ---- Other 页（主 Tab 13）---- */


/* ---- Examination 页（主 Tab 9）---- */



/* ---- Fireeye 页（主 Tab 11）---- */



/* ---- Setting 页（主 Tab 10）----
 * 三项可用 Forbid（对应已确认的 IoFile/Driver/DeviceObjectType）
 * + 四项标注"未定位对象类型"
 * + 两项自保护（占位，需 0xD2/0xD3 的 21712 字节输出）
 * + 托盘最小化开关 */



/* ---- Trojan Detection 页（主 Tab 12）---- */



/* ---- Ring0 / Ring3 Hooks 页（主 Tab 2 / 3）----
 * Ring3 扫 IAT 越界；Ring0 标 blocked（驱动链缺 6 个函数，见
 * docs/reversing/Hooks页落地_2026-10-21.md）。 */


/* ---- Ring0 两项恢复操作的点击处理 ----
 * 两者都必须把「没有待恢复项」和「失败」区分开显示：
 * 本机 908 条 Hook 条目全部 clean，0x118 返回 0 是正常结果，
 * 若显示成 FAILED 会误导用户以为自己系统被 hook 了。 */


void ShowPage(HWND hWnd, int page)
{
    char hint[512];
    /* 统一页面注册表：每页的显隐/按需刷新在各自模块的 PageShow 中实现。 */
    static const FE_PAGE_SHOW_FN g_PageShows[] = {
        FeProcPagePageShow,   /* 0 (Process) */
        FeKernelPagePageShow,   /* 1 (Kernel) */
        FeHookPagePageShow,   /* 2 (Ring0) */
        FeHookPagePageShow,   /* 3 (Ring3) */
        FeNetworkPagePageShow,   /* 4 (Network) */
        FeRegistryPagePageShow,   /* 5 (Registry) */
        FeStartupPagePageShow,   /* 6 (Startup) */
        FeServicePagePageShow,   /* 7 (Services) */
        FeFilePagePageShow,   /* 8 (File) */
        FeExamPagePageShow,   /* 9 (Exam) */
        FeSettingPagePageShow,   /* 10 (Setting) */
        FeFireeyePagePageShow,   /* 11 (Fireeye) */
        FeTrojanPagePageShow,   /* 12 (Trojan) */
        FeOtherPagePageShow,   /* 13 (Other) */
    };
    for (int i = 0; i < (int)(sizeof(g_PageShows)/sizeof(g_PageShows[0])); i++)
        g_PageShows[i](hWnd, page);

    g_MainTab = page;

    if (g_hPageHint) {
        if (page >= 0 && page <= 13) {   /* 注册表覆盖全部 14 个主 Tab */
            ShowWindow(g_hPageHint, SW_HIDE);
        } else {
            /* 14 个主 Tab 均已有实现，此分支理论上不可达；保留仅为兜底。 */
            sprintf_s(hint, sizeof(hint),
                      "%s  -  this page has no view yet.",
                      g_MainTabNames[page < 14 ? page : 0]);
            SetWindowTextA(g_hPageHint, hint);
            ShowWindow(g_hPageHint, SW_SHOW);
        }
    }

    g_MainTab = page;
    if (page == 0) {
        RECT rc;
        GetClientRect(hWnd, &rc);
        SendMessageA(hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));
    }
}


/* ==========================================================================
 * Kernel 页（原版第 2 个主 Tab，现已是主 Tab 容器里的一页）
 *
 *   Kernel Module : EnumDeviceDrivers + GetDeviceDriverBaseNameW/FileNameW
 *   Driver        : SCM 的 SERVICE_DRIVER 枚举 + QueryServiceConfig
 * ========================================================================== */



/* 把 Kernel 列表当前选中行的某列复制到剪贴板。
 * 原版 Driver 页右键菜单有 Copy Driver Name / Copy Driver Path，
 * 这里做成按钮。复制后把内容回显到状态栏，便于截图取证。 */

/* 取 Kernel 列表当前选中行的驱动服务名。Driver 子页第 0 列就是服务名。 */

/* Driver 子页的 5 个右键操作。破坏性操作先弹二次确认（原版同样要求确认）。 */

/* 进程右键操作：Kill / Force Kill / Suspend / Resume / Kill By Process Tree /
 * Kill And Delete File / Copy Image Path。 */


/* ---- 模块右键操作：Copy Module Path / Dump Module Memory / Locate in File Tab ---- */



/* 简易文本输入框：自建模态子窗口（EDIT + OK/Cancel），自带消息循环。
 * 不用资源文件，也不依赖任何 shell 组件。 */




/* 模块搜索 5 项（76004..6008）。结果直接填进 Modules 视图的列表。 */


/* 原版 Driver 页的 "Locate in Registry Tab"：跳到 Registry 页的 Key 子页，
 * 直接打开 HKLM\SYSTEM\CurrentControlSet\Services\<驱动名>。 */

/* Driver 子页右键菜单：与原版一致的操作集合。 */

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        g_hMainWnd = hWnd;

        CreateWindowA("BUTTON", "Connect", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      10, 10, 90, 28, hWnd, (HMENU)IDC_CONNECT, hInst, NULL);
        CreateWindowA("BUTTON", "Refresh Processes", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      110, 10, 140, 28, hWnd, (HMENU)IDC_REFRESH, hInst, NULL);
        CreateWindowA("BUTTON", "Scan All", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      260, 10, 90, 28, hWnd, (HMENU)IDC_SCAN, hInst, NULL);
        CreateWindowA("BUTTON", "Send", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      360, 10, 70, 28, hWnd, (HMENU)IDC_SEND, hInst, NULL);
        CreateWindowA("BUTTON", "Kill", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      675, 10, 90, 28, hWnd, (HMENU)IDC_KILL, hInst, NULL);
        /* Kernel 页入口（原版第 2 个主 Tab；先落 Kernel Module / Driver 两个子页） */
        CreateWindowA("BUTTON", "Kernel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      780, 10, 90, 28, hWnd, (HMENU)IDC_KERNEL, hInst, NULL);

        CreateWindowA("STATIC", "cmd", WS_CHILD | WS_VISIBLE,
                      445, 16, 30, 20, hWnd, NULL, hInst, NULL);
        g_hCmd = CreateWindowA("EDIT", "0x24", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                               475, 12, 80, 24, hWnd, (HMENU)IDC_CMD, hInst, NULL);
        CreateWindowA("STATIC", "size", WS_CHILD | WS_VISIBLE,
                      565, 16, 30, 20, hWnd, NULL, hInst, NULL);
        g_hSize = CreateWindowA("EDIT", "256", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                595, 12, 70, 24, hWnd, (HMENU)IDC_OUTSIZE, hInst, NULL);

        g_hStatus = CreateWindowA("STATIC", "Disconnected", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  10, 46, 940, 20, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        /* ---- 14 个主 Tab 容器（M1）---- */
        g_hMainTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | TCS_TABS,
                                    10, 44, 940, 24, hWnd, (HMENU)IDC_MAIN_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            for (k = 0; k < 14; k++) {
                ZeroMemory(&t, sizeof(t));
                t.mask = TCIF_TEXT;
                t.pszText = (LPSTR)g_MainTabNames[k];
                SendMessageA(g_hMainTabs, TCM_INSERTITEMA, k, (LPARAM)&t);
            }
        }

        /* 未实现页的占位提示（不伪造功能，写清状态） */
        g_hPageHint = CreateWindowA("STATIC", "", WS_CHILD | SS_LEFT,
                                    20, 90, 900, 140, hWnd, (HMENU)IDC_PAGEHINT, hInst, NULL);

        /* Process 页主视图 */
        g_hProc = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA,
                                  "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  10, 76, 940, 300, hWnd, (HMENU)IDC_PROCLIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hProc, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateProcColumns(g_hProc);

        g_hProcStatus = CreateWindowA("STATIC", "Not connected", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      10, 380, 940, 20, hWnd, (HMENU)IDC_PROCSTATUS, hInst, NULL);
        /* 第二步增量：Auto Refresh 开关（Process 页专属，PageShow 控制显隐）。
           压在状态行右端之上创建（z 序更高），左侧留给状态文本。 */
        CreateWindowA("BUTTON", "Auto Refresh: OFF", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                      858, 376, 94, 24, hWnd, (HMENU)IDC_PROC_AUTO, hInst, NULL);
        /* 第二步增量2：列过滤（Process 页专属；空串 = 不过滤）。
           布局在 WM_SIZE 的 Process 分支里定，这里只给初始位置。 */
        g_hProcFilter = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                        10, 350, 240, 24, hWnd,
                                        (HMENU)IDC_PROC_FILTER, hInst, NULL);
        SendMessageA(g_hProcFilter, EM_SETCUEBANNER, TRUE,
                     (LPARAM)L"Filter (PID / Name / Path / EPROCESS / State)");

        /* 明细子视图：tab + 一个 ListView（列随 tab 切换） */
        g_hTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | TCS_TABS,
                                10, 402, 940, 24, hWnd, (HMENU)IDC_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            for (k = 0; k < 7; k++) {
                ZeroMemory(&t, sizeof(t));
                t.mask = TCIF_TEXT;
                t.pszText = (LPSTR)g_TabNames[k];
                SendMessageA(g_hTabs, TCM_INSERTITEMA, k, (LPARAM)&t);
            }
        }
        SendMessageA(g_hTabs, TCM_SETCURSEL, (WPARAM)g_StartTab, 0);
        g_hDetail = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                    10, 426, 940, 190, hWnd, (HMENU)IDC_DETAIL, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hDetail, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        /* ---- Kernel 页（主 Tab 1）：刷新 + 子页 Tab + 列表 + 状态 ---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_KM_REFRESH, hInst, NULL);
        /* 原版 Driver 页的三个右键菜单项，做成按钮便于实机验证 */
        CreateWindowA("BUTTON", "Only Show Loaded Driver", WS_CHILD | BS_AUTOCHECKBOX,
                      88, 80, 200, 24, hWnd, (HMENU)IDC_KM_ONLYLOADED, hInst, NULL);
        CreateWindowA("BUTTON", "Copy Name", WS_CHILD | BS_PUSHBUTTON,
                      292, 76, 90, 28, hWnd, (HMENU)IDC_KM_COPYNAME, hInst, NULL);
        CreateWindowA("BUTTON", "Copy Path", WS_CHILD | BS_PUSHBUTTON,
                      386, 76, 90, 28, hWnd, (HMENU)IDC_KM_COPYPATH, hInst, NULL);
        /* 其余 5 项（Verify / Verify All / Unload / Delete File / Delete File+Reg）
           与原版一样放在右键菜单里，这个按钮只是把同一个菜单弹出来便于取证。 */
        CreateWindowA("BUTTON", "Driver Ops", WS_CHILD | BS_PUSHBUTTON,
                      480, 76, 90, 28, hWnd, (HMENU)IDC_KM_DRVOP, hInst, NULL);
        /* SSDT / Shadow SSDT 子页的 Restore / Restore All */
        CreateWindowA("BUTTON", "Restore", WS_CHILD | BS_PUSHBUTTON,
                      480, 76, 90, 28, hWnd, (HMENU)IDC_KM_RESTORE, hInst, NULL);
        CreateWindowA("BUTTON", "Restore All", WS_CHILD | BS_PUSHBUTTON,
                      574, 76, 100, 28, hWnd, (HMENU)IDC_KM_RESTOREALL, hInst, NULL);
        g_hKmStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    576, 82, 374, 20, hWnd, (HMENU)IDC_KM_STATUS, hInst, NULL);
        /* 原版 Driver 页的"其他内核项"三项：独立一行，避免挤在计数行里
           被截断（KiDebugRoutine / Find PTE Hook / Find Next ClassInitData）。 */
        g_hKmKExtra = CreateWindowA("STATIC", "", WS_CHILD | SS_LEFT,
                                    10, 106, 940, 18, hWnd, (HMENU)IDC_KM_KEXTRA, hInst, NULL);
        g_hKmTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | TCS_TABS,
                                  10, 110, 940, 24, hWnd, (HMENU)IDC_KM_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            static const char *kmNames[11] = { "Kernel Module", "Driver", "SSDT",
                                               "Shadow SSDT", "Device", "Object",
                                               "Hidden Drivers", "Suspicious DriverObj",
                                               "IDT", "I/O Port", "GDT" };
            for (k = 0; k < 11; k++) {
                ZeroMemory(&t, sizeof(t));
                t.mask = TCIF_TEXT;
                t.pszText = (LPSTR)kmNames[k];
                SendMessageA(g_hKmTabs, TCM_INSERTITEMA, k, (LPARAM)&t);
            }
        }
        g_hKmList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 140, 940, 476, hWnd, (HMENU)IDC_KM_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hKmList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateKmColumns(g_hKmList, 0);
        DoRefreshKernel();

        /* ---- Startup Info 页（主 Tab 6）---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_SU_REFRESH, hInst, NULL);
        g_hSuStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    110, 82, 840, 20, hWnd, (HMENU)IDC_SU_STATUS, hInst, NULL);
        g_hSuList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 510, hWnd, (HMENU)IDC_SU_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hSuList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateSuColumns(g_hSuList);
        DoRefreshStartup();

        /* ---- Services 页（主 Tab 7）---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_SV_REFRESH, hInst, NULL);
        g_hSvStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    110, 82, 840, 20, hWnd, (HMENU)IDC_SV_STATUS, hInst, NULL);
        g_hSvList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 510, hWnd, (HMENU)IDC_SV_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hSvList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateSvColumns(g_hSvList);
        DoRefreshServices();

        /* ---- Registry 页（主 Tab 5）---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_RG_REFRESH, hInst, NULL);
        g_hRgStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    110, 82, 840, 20, hWnd, (HMENU)IDC_RG_STATUS, hInst, NULL);
        /* Key 子页的路径框（只在选中 Key 子页时显示） */
        {
            HWND hPath = CreateWindowA("EDIT", g_RgPath,
                                       WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                       110, 76, 580, 24, hWnd, (HMENU)IDC_RG_PATH, hInst, NULL);
            CreateWindowA("BUTTON", "Go", WS_CHILD | BS_PUSHBUTTON,
                          698, 74, 50, 28, hWnd, (HMENU)IDC_RG_GO, hInst, NULL);
            ShowWindow(hPath, SW_HIDE);
            ShowWindow(GetDlgItem(hWnd, IDC_RG_GO), SW_HIDE);
        }
        g_hRgTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | TCS_TABS,
                                  10, 110, 940, 24, hWnd, (HMENU)IDC_RG_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            /* 原版 Registry 子页名单（PCHunter64.exe 0x45D99A 起）：
               View Handle / Hidden Item / CmpNotifyChange
               此前第 3 项写成 "Key"，与原版不符。 */
            static const char *rgNames[3] = { "View Handle", "Hidden Item", "CmpNotifyChange" };
            for (k = 0; k < 3; k++) {
                ZeroMemory(&t, sizeof(t));
                t.mask = TCIF_TEXT;
                t.pszText = (LPSTR)rgNames[k];
                SendMessageA(g_hRgTabs, TCM_INSERTITEMA, k, (LPARAM)&t);
            }
        }
        g_hRgList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 140, 940, 476, hWnd, (HMENU)IDC_RG_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hRgList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateRgColumns(g_hRgList, 0);
        DoRefreshRegistry();

        /* ---- File 页（主 Tab 8）---- */
        g_hFlDir = CreateWindowA("EDIT", "C:\Windows\System32",
                                 WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                 10, 76, 560, 24, hWnd, (HMENU)IDC_FL_DIR, hInst, NULL);
        CreateWindowA("BUTTON", "Go", WS_CHILD | BS_PUSHBUTTON,
                      580, 74, 50, 28, hWnd, (HMENU)IDC_FL_GO, hInst, NULL);
        CreateWindowA("BUTTON", "Verify", WS_CHILD | BS_PUSHBUTTON,
                      636, 74, 70, 28, hWnd, (HMENU)IDC_FL_VERIFY, hInst, NULL);
        CreateWindowA("BUTTON", "Delete", WS_CHILD | BS_PUSHBUTTON,
                      712, 74, 70, 28, hWnd, (HMENU)IDC_FL_DEL, hInst, NULL);
        g_hFlStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    790, 80, 160, 20, hWnd, (HMENU)IDC_FL_STATUS, hInst, NULL);
        g_hFlList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 108, 940, 500, hWnd, (HMENU)IDC_FL_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hFlList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateFlColumns(g_hFlList);
        DoRefreshFiles();

        /* ---- Other 页（主 Tab 13）---- */
        g_hOtPath = CreateWindowA("EDIT", "C:\Windows\System32\ntoskrnl.exe",
                                  WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                  10, 76, 620, 24, hWnd, (HMENU)IDC_OT_PATH, hInst, NULL);
        CreateWindowA("BUTTON", "Verify", WS_CHILD | BS_PUSHBUTTON,
                      640, 74, 70, 28, hWnd, (HMENU)IDC_OT_VERIFY, hInst, NULL);
        CreateWindowA("BUTTON", "Query Online", WS_CHILD | BS_PUSHBUTTON,
                      716, 74, 110, 28, hWnd, (HMENU)IDC_OT_QUERY, hInst, NULL);
        g_hOtStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    836, 80, 120, 20, hWnd, (HMENU)IDC_OT_STATUS, hInst, NULL);
        g_hOtList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 108, 940, 500, hWnd, (HMENU)IDC_OT_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hOtList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        DoRefreshOther();

        /* ---- Network 页（主 Tab 4）----
           原版布局：左侧 "Network Callback" 树 + 右侧 6 列列表，
           节点 lParam = formatter case 号，数据层见 src/NetworkViews.c。 */
        g_hNwTree = CreateWindowExA(WS_EX_CLIENTEDGE, WC_TREEVIEWA, "",
                                    WS_CHILD | TVS_HASLINES | TVS_HASBUTTONS |
                                    TVS_LINESATROOT | TVS_SHOWSELALWAYS,
                                    10, 76, 260, 500, hWnd, (HMENU)IDC_NW_TREE, hInst, NULL);
        g_hNwStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    10, 632, 940, 20, hWnd, (HMENU)IDC_NW_STATUS, hInst, NULL);
        g_hNwList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    280, 76, 670, 500, hWnd, (HMENU)IDC_NW_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hNwList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        BuildNwTree();
        CreateNwColumns(g_hNwList, 1);

        /* ---- Examination 页（主 Tab 9）---- */
        CreateWindowA("BUTTON", "Computer Examination", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 170, 28, hWnd, (HMENU)IDC_EX_RUN, hInst, NULL);
        CreateWindowA("BUTTON", "Terminate", WS_CHILD | BS_PUSHBUTTON,
                      188, 76, 90, 28, hWnd, (HMENU)IDC_EX_CANCEL, hInst, NULL);
        CreateWindowA("BUTTON", "Export Report", WS_CHILD | BS_PUSHBUTTON,
                      286, 76, 120, 28, hWnd, (HMENU)IDC_EX_EXPORT, hInst, NULL);
        g_hExStatus = CreateWindowA("STATIC", "Not run", WS_CHILD | SS_LEFT,
                                    416, 82, 540, 20, hWnd, (HMENU)IDC_EX_STATUS, hInst, NULL);
        g_hExList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 500, hWnd, (HMENU)IDC_EX_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hExList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        /* ---- Fireeye 页（主 Tab 11）---- */
        g_hFePath = CreateWindowA("EDIT", "C:\Windows\System32\ntoskrnl.exe",
                                  WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                  10, 76, 520, 24, hWnd, (HMENU)IDC_FE_PATH, hInst, NULL);
        CreateWindowA("BUTTON", "Analyse", WS_CHILD | BS_PUSHBUTTON,
                      540, 74, 80, 28, hWnd, (HMENU)IDC_FE_ANALYSE, hInst, NULL);
        CreateWindowA("BUTTON", "Open Query", WS_CHILD | BS_PUSHBUTTON,
                      626, 74, 100, 28, hWnd, (HMENU)IDC_FE_OPEN, hInst, NULL);
        CreateWindowA("BUTTON", "Records", WS_CHILD | BS_PUSHBUTTON,
                      732, 74, 80, 28, hWnd, (HMENU)IDC_FE_RECORDS, hInst, NULL);
        CreateWindowA("BUTTON", "Clear", WS_CHILD | BS_PUSHBUTTON,
                      818, 74, 70, 28, hWnd, (HMENU)IDC_FE_CLEAR, hInst, NULL);
        g_hFeStatus = CreateWindowA("STATIC", "Ready", WS_CHILD | SS_LEFT,
                                    10, 106, 940, 20, hWnd, (HMENU)IDC_FE_STATUS, hInst, NULL);
        g_hFeList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 130, 940, 480, hWnd, (HMENU)IDC_FE_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hFeList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        /* ---- Setting 页（主 Tab 10）---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_ST_REFRESH, hInst, NULL);
        CreateWindowA("BUTTON", "Forbid File", WS_CHILD | BS_PUSHBUTTON,
                      106, 76, 100, 28, hWnd, NULL, hInst, NULL);
        CreateWindowA("BUTTON", "Apply File", WS_CHILD | BS_PUSHBUTTON,
                      212, 76, 90, 28, hWnd, (HMENU)IDC_ST_APPLY, hInst, NULL);
        CreateWindowA("BUTTON", "Protect SSDT", WS_CHILD | BS_PUSHBUTTON,
                      308, 76, 110, 28, hWnd, (HMENU)IDC_ST_PROT_SSDT, hInst, NULL);
        CreateWindowA("BUTTON", "Protect Shadow", WS_CHILD | BS_PUSHBUTTON,
                      424, 76, 120, 28, hWnd, (HMENU)IDC_ST_PROT_SHADOW, hInst, NULL);
        CreateWindowA("BUTTON", "Tray Toggle", WS_CHILD | BS_PUSHBUTTON,
                      550, 76, 110, 28, hWnd, (HMENU)IDC_ST_TRAY, hInst, NULL);
        g_hStStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    670, 82, 280, 20, hWnd, (HMENU)IDC_ST_STATUS, hInst, NULL);
        g_hStList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 500, hWnd, (HMENU)IDC_ST_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hStList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        DoRefreshSetting();

        /* ---- Trojan Detection 页（主 Tab 12）---- */
        CreateWindowA("BUTTON", "Scan MBR", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 100, 28, hWnd, (HMENU)IDC_TR_SCAN, hInst, NULL);
        CreateWindowA("BUTTON", "Backup MBR", WS_CHILD | BS_PUSHBUTTON,
                      116, 76, 110, 28, hWnd, (HMENU)IDC_TR_BACKUP, hInst, NULL);
        CreateWindowA("BUTTON", "Reset MBR", WS_CHILD | BS_PUSHBUTTON,
                      232, 76, 100, 28, hWnd, (HMENU)IDC_TR_RESTORE, hInst, NULL);
        CreateWindowA("BUTTON", "Repair All", WS_CHILD | BS_PUSHBUTTON,
                      338, 76, 100, 28, hWnd, (HMENU)IDC_TR_REPAIR, hInst, NULL);
        g_hTrStatus = CreateWindowA("STATIC", "Not scanned", WS_CHILD | SS_LEFT,
                                    446, 82, 500, 20, hWnd, (HMENU)IDC_TR_STATUS, hInst, NULL);
        g_hTrList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 500, hWnd, (HMENU)IDC_TR_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hTrList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        DoTrojanScan();

        /* ---- Ring0/Ring3 Hooks 页（主 Tab 2 / 3）---- */
        CreateWindowA("BUTTON", "Refresh", WS_CHILD | BS_PUSHBUTTON,
                      10, 76, 90, 28, hWnd, (HMENU)IDC_HK_REFRESH, hInst, NULL);
        /* 原版右键菜单的两项恢复操作，这里做成按钮便于实机验证 */
        CreateWindowA("BUTTON", "Restore Over. Hooks/Patches", WS_CHILD | BS_PUSHBUTTON,
                      106, 76, 210, 28, hWnd, (HMENU)IDC_HK_RESTORE, hInst, NULL);
        CreateWindowA("BUTTON", "Restore KernelCallbackTable", WS_CHILD | BS_PUSHBUTTON,
                      322, 76, 210, 28, hWnd, (HMENU)IDC_HK_CBTABLE, hInst, NULL);
        g_hHkStatus = CreateWindowA("STATIC", "Not scanned", WS_CHILD | SS_LEFT,
                                    540, 82, 410, 20, hWnd, (HMENU)IDC_HK_STATUS, hInst, NULL);
        g_hHkList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 110, 940, 500, hWnd, (HMENU)IDC_HK_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hHkList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        DoRefreshHooks();

        /* 命令测试器（保留：逐条命令的结果与形状） */
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA,
                                  "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  10, 402, 940, 150, hWnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateListColumns(g_hList);

        /* 初始页：--page N，或 --kernel-gui 等价于 --page 1 */
        {
            const char *cl = GetCommandLineA();
            int page = 0;
            const char *p = cl ? strstr(cl, "--page ") : NULL;
            const char *pk;
            if (p) page = atoi(p + 7);
            if (cl && strstr(cl, "--kernel-gui")) page = 1;
            if (page < 0 || page > 13) page = 0;
            SendMessageA(g_hMainTabs, TCM_SETCURSEL, (WPARAM)page, 0);
            ShowPage(hWnd, page);
            /* --kmtab N：预选 Kernel 页的子页（0 Module / 1 Driver / 2 SSDT /
               3 Shadow SSDT / 4 Device / 5 Object / 6 Hidden / 7 Suspicious） */
            pk = cl ? strstr(cl, "--kmtab ") : NULL;
            if (pk && g_hKmTabs) {
                int kt = atoi(pk + 8);
                if (kt >= 0 && kt <= 10) {
                    HWND b;
                    g_KmTab = kt;
                    SendMessageA(g_hKmTabs, TCM_SETCURSEL, (WPARAM)kt, 0);
                    DoRefreshKernel();
                    b = GetDlgItem(hWnd, IDC_KM_RESTORE);
                    if (b) ShowWindow(b, (kt == 2 || kt == 3) ? SW_SHOW : SW_HIDE);
                    b = GetDlgItem(hWnd, IDC_KM_RESTOREALL);
                    if (b) ShowWindow(b, (kt == 2 || kt == 3) ? SW_SHOW : SW_HIDE);
                    b = GetDlgItem(hWnd, IDC_KM_DRVOP);
                    if (b) ShowWindow(b, (kt == 2 || kt == 3) ? SW_HIDE : SW_SHOW);
                }
            }
            /* --nwtab N：兼容旧参数（0 -> 节点 1 NdisTdiCallback，1 -> 节点 2 TdiPnpClient） */
            pk = cl ? strstr(cl, "--nwtab ") : NULL;
            if (pk && g_hNwTree) {
                int nt = atoi(pk + 8);
                if (nt == 0 || nt == 1)
                    NwSelectNode(nt + 1);
            }
            /* --nwnode N：预选 Network 页的树节点（1..22，对应 formatter case） */
            pk = cl ? strstr(cl, "--nwnode ") : NULL;
            if (pk && g_hNwTree) {
                int nt = atoi(pk + 9);
                if (nt > 0)
                    NwSelectNode(nt);
            }
            /* --filter TEXT：启动即套用 Process 页列过滤（验证与自动化用；
               过滤串在 DoRefreshProcs 之前先写进编辑框，刷新时生效） */
            pk = cl ? strstr(cl, "--filter ") : NULL;
            if (pk && g_hProcFilter) {
                const char *v = pk + 9;
                char f[128];
                size_t i = 0;
                while (v[i] && v[i] != ' ' && i + 1 < sizeof(f)) {
                    f[i] = v[i];
                    i++;
                }
                f[i] = 0;
                SetWindowTextA(g_hProcFilter, f);
                FeProcPageSetFilter(f);   /* 缓存未就绪时只记录，刷新后生效 */
            }
        }

        SetWindowTextA(hWnd, "PC Hunter Replica");
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        int w, h, pageTop, pageBottom;
        GetClientRect(hWnd, &rc);
        w = rc.right - 20;
        h = rc.bottom;
        if (w < 400) w = 400;
        pageTop = 76;                 /* 主 Tab 栏之下 */
        pageBottom = h - 12;          /* 留一点下边距 */

        if (g_hMainTabs)
            MoveWindow(g_hMainTabs, 10, 44, w, 24, TRUE);
        if (g_hPageHint)
            MoveWindow(g_hPageHint, 20, pageTop + 20, w - 20, 160, TRUE);

        if (g_MainTab == 0) {
            /* Process 页：进程列表(上半) + 子视图 Tab + 明细列表(下半) + 命令测试器 */
            int listH = (pageBottom - pageTop) / 2 - 40;
            int midY, detailH, filterH = 30;   /* 过滤框高度 + 间隙 */
            if (listH < 100) listH = 100;
            listH -= filterH;                  /* 列表底部让出过滤框的位置 */
            if (listH < 80) listH = 80;
            midY = pageTop + listH + filterH;
            detailH = pageBottom - (midY + 28) - 150;
            if (detailH < 80) detailH = 80;
            if (g_hProc)       MoveWindow(g_hProc, 10, pageTop, w, listH, TRUE);
            /* 第二步增量2：过滤框贴在进程列表与状态行之间 */
            if (g_hProcFilter) MoveWindow(g_hProcFilter, 10, midY - filterH + 2, 260, 24, TRUE);
            if (g_hProcStatus) MoveWindow(g_hProcStatus, 10, midY, w, 20, TRUE);
            /* 第二步增量：Auto Refresh 开关贴状态行右端（随窗口重排） */
            {
                HWND hAuto = GetDlgItem(hWnd, IDC_PROC_AUTO);
                if (hAuto) MoveWindow(hAuto, 10 + w - 96, midY - 4, 94, 24, TRUE);
            }
            if (g_hTabs)       MoveWindow(g_hTabs, 10, midY + 22, w, 24, TRUE);
            if (g_hDetail)     MoveWindow(g_hDetail, 10, midY + 46, w, detailH, TRUE);
            if (g_hList)       MoveWindow(g_hList, 10, h - 150, w, 132, TRUE);
        } else if (g_MainTab == 1) {
            /* Kernel 页：刷新 + 状态 + 子页 Tab + 列表 */
            int listY = pageTop + 64;
            int listH = pageBottom - listY;
            if (listH < 100) listH = 100;
            {
                HWND hRef = GetDlgItem(hWnd, IDC_KM_REFRESH);
                HWND b;
                if (hRef) {
                    MoveWindow(hRef, 10, pageTop, 90, 28, TRUE);
                    ShowWindow(hRef, SW_SHOW);
                }
                /* 原版 Driver 页的三个右键菜单项 */
                b = GetDlgItem(hWnd, IDC_KM_ONLYLOADED);
                if (b) { MoveWindow(b, 88, pageTop + 4, 200, 24, TRUE); ShowWindow(b, SW_SHOW); }
                b = GetDlgItem(hWnd, IDC_KM_COPYNAME);
                if (b) { MoveWindow(b, 292, pageTop, 90, 28, TRUE); ShowWindow(b, SW_SHOW); }
                b = GetDlgItem(hWnd, IDC_KM_COPYPATH);
                if (b) { MoveWindow(b, 386, pageTop, 90, 28, TRUE); ShowWindow(b, SW_SHOW); }
                b = GetDlgItem(hWnd, IDC_KM_DRVOP);
                if (b) { MoveWindow(b, 480, pageTop, 90, 28, TRUE); ShowWindow(b, SW_SHOW); }
                b = GetDlgItem(hWnd, IDC_KM_RESTORE);
                if (b) { MoveWindow(b, 480, pageTop, 90, 28, TRUE); }
                b = GetDlgItem(hWnd, IDC_KM_RESTOREALL);
                if (b) { MoveWindow(b, 574, pageTop, 100, 28, TRUE); }
            }
            if (g_hKmStatus) MoveWindow(g_hKmStatus, 576, pageTop + 6,
                                        (w > 700 ? w - 576 : 200), 34, TRUE);
            if (g_hKmKExtra) MoveWindow(g_hKmKExtra, 10, pageTop + 34, w, 18, TRUE);
            if (g_hKmTabs)   MoveWindow(g_hKmTabs, 10, pageTop + 54, w, 24, TRUE);
            if (g_hKmList)   MoveWindow(g_hKmList, 10, listY + 20, w, listH - 20, TRUE);
            if (g_hList)     ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 2 || g_MainTab == 3) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND a = GetDlgItem(hWnd, IDC_HK_REFRESH);
            if (listH < 100) listH = 100;
            if (a) MoveWindow(a, 10, pageTop, 90, 28, TRUE);
            if (g_hHkStatus) MoveWindow(g_hHkStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            if (g_hHkList)   MoveWindow(g_hHkList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 12) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND a = GetDlgItem(hWnd, IDC_TR_SCAN);
            HWND b = GetDlgItem(hWnd, IDC_TR_BACKUP);
            HWND c = GetDlgItem(hWnd, IDC_TR_RESTORE);
            HWND d = GetDlgItem(hWnd, IDC_TR_REPAIR);
            if (listH < 100) listH = 100;
            if (a) MoveWindow(a, 10, pageTop, 100, 28, TRUE);
            if (b) MoveWindow(b, 116, pageTop, 110, 28, TRUE);
            if (c) MoveWindow(c, 232, pageTop, 100, 28, TRUE);
            if (d) MoveWindow(d, 338, pageTop, 100, 28, TRUE);
            if (g_hTrStatus) MoveWindow(g_hTrStatus, 446, pageTop + 6, w - 436, 20, TRUE);
            if (g_hTrList)   MoveWindow(g_hTrList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 10) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND a = GetDlgItem(hWnd, IDC_ST_REFRESH);
            HWND b = GetDlgItem(hWnd, IDC_ST_APPLY);
            HWND c = GetDlgItem(hWnd, IDC_ST_PROT_SSDT);
            HWND d = GetDlgItem(hWnd, IDC_ST_PROT_SHADOW);
            HWND e = GetDlgItem(hWnd, IDC_ST_TRAY);
            if (listH < 100) listH = 100;
            if (a) MoveWindow(a, 10, pageTop, 90, 28, TRUE);
            if (b) MoveWindow(b, 212, pageTop, 90, 28, TRUE);
            if (c) MoveWindow(c, 308, pageTop, 110, 28, TRUE);
            if (d) MoveWindow(d, 424, pageTop, 120, 28, TRUE);
            if (e) MoveWindow(e, 550, pageTop, 110, 28, TRUE);
            if (g_hStStatus) MoveWindow(g_hStStatus, 670, pageTop + 6, w - 660, 20, TRUE);
            if (g_hStList)   MoveWindow(g_hStList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 11) {
            int listY = pageTop + 56;
            int listH = pageBottom - listY;
            HWND a = GetDlgItem(hWnd, IDC_FE_ANALYSE);
            HWND b = GetDlgItem(hWnd, IDC_FE_OPEN);
            HWND c = GetDlgItem(hWnd, IDC_FE_RECORDS);
            HWND d = GetDlgItem(hWnd, IDC_FE_CLEAR);
            if (listH < 100) listH = 100;
            if (g_hFePath)   MoveWindow(g_hFePath, 10, pageTop, w - 420, 24, TRUE);
            if (a) MoveWindow(a, w - 400, pageTop - 2, 80, 28, TRUE);
            if (b) MoveWindow(b, w - 314, pageTop - 2, 100, 28, TRUE);
            if (c) MoveWindow(c, w - 208, pageTop - 2, 80, 28, TRUE);
            if (d) MoveWindow(d, w - 122, pageTop - 2, 70, 28, TRUE);
            if (g_hFeStatus) MoveWindow(g_hFeStatus, 10, pageTop + 28, w, 20, TRUE);
            if (g_hFeList)   MoveWindow(g_hFeList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 9) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND h1 = GetDlgItem(hWnd, IDC_EX_RUN);
            HWND h2 = GetDlgItem(hWnd, IDC_EX_CANCEL);
            HWND h3 = GetDlgItem(hWnd, IDC_EX_EXPORT);
            if (listH < 100) listH = 100;
            if (h1) MoveWindow(h1, 10, pageTop, 170, 28, TRUE);
            if (h2) MoveWindow(h2, 188, pageTop, 90, 28, TRUE);
            if (h3) MoveWindow(h3, 286, pageTop, 120, 28, TRUE);
            if (g_hExStatus) MoveWindow(g_hExStatus, 416, pageTop + 6, w - 410, 20, TRUE);
            if (g_hExList)   MoveWindow(g_hExList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 13) {
            int listY = pageTop + 56;
            int listH = pageBottom - listY;
            HWND h1 = GetDlgItem(hWnd, IDC_OT_VERIFY);
            HWND h2 = GetDlgItem(hWnd, IDC_OT_QUERY);
            if (listH < 100) listH = 100;
            if (g_hOtPath)   MoveWindow(g_hOtPath, 10, pageTop, w - 300, 24, TRUE);
            if (h1) MoveWindow(h1, w - 280, pageTop - 2, 70, 28, TRUE);
            if (h2) MoveWindow(h2, w - 204, pageTop - 2, 110, 28, TRUE);
            if (g_hOtStatus) MoveWindow(g_hOtStatus, 10, pageTop + 26, w, 20, TRUE);
            if (g_hOtList)   MoveWindow(g_hOtList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 8) {
            int listY = pageTop + 36;
            int listH = pageBottom - listY;
            if (listH < 100) listH = 100;
            if (g_hFlDir)    MoveWindow(g_hFlDir, 10, pageTop, w - 320, 24, TRUE);
            {
                HWND h1 = GetDlgItem(hWnd, IDC_FL_GO);
                HWND h2 = GetDlgItem(hWnd, IDC_FL_VERIFY);
                HWND h3 = GetDlgItem(hWnd, IDC_FL_DEL);
                if (h1) MoveWindow(h1, w - 310 + 10, pageTop - 2, 50, 28, TRUE);
                if (h2) MoveWindow(h2, w - 250 + 10, pageTop - 2, 70, 28, TRUE);
                if (h3) MoveWindow(h3, w - 174 + 10, pageTop - 2, 70, 28, TRUE);
            }
            if (g_hFlStatus) MoveWindow(g_hFlStatus, 10, pageTop + 26, w, 20, TRUE);
            if (g_hFlList)   MoveWindow(g_hFlList, 10, listY + 20, w, listH - 20, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 5) {
            HWND hRg = GetDlgItem(hWnd, IDC_RG_REFRESH);
            HWND hPath = GetDlgItem(hWnd, IDC_RG_PATH);
            HWND hGo = GetDlgItem(hWnd, IDC_RG_GO);
            int tabsY, listY, listH;
            if (g_RgTab == 0) {
                /* View Handle 子页多一行路径框：Refresh | [path] [Go] / status / tabs / list */
                tabsY = pageTop + 56;
                listY = pageTop + 86;
                if (hPath) MoveWindow(hPath, 110, pageTop + 2,
                                      (w > 800 ? w - 330 : 300), 24, TRUE);
                if (hGo) MoveWindow(hGo, (w > 800 ? w - 212 : 418), pageTop, 50, 28, TRUE);
                if (g_hRgStatus) MoveWindow(g_hRgStatus, 110, pageTop + 30, w - 100, 20, TRUE);
            } else {
                tabsY = pageTop + 34;
                listY = pageTop + 64;
                if (g_hRgStatus) MoveWindow(g_hRgStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            }
            listH = pageBottom - listY;
            if (listH < 100) listH = 100;
            if (hRg) MoveWindow(hRg, 10, pageTop, 90, 28, TRUE);
            if (g_hRgTabs)   MoveWindow(g_hRgTabs, 10, tabsY, w, 24, TRUE);
            if (g_hRgList)   MoveWindow(g_hRgList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 7) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND hSv = GetDlgItem(hWnd, IDC_SV_REFRESH);
            if (listH < 100) listH = 100;
            if (hSv) MoveWindow(hSv, 10, pageTop, 90, 28, TRUE);
            if (g_hSvStatus) MoveWindow(g_hSvStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            if (g_hSvList)   MoveWindow(g_hSvList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 6) {
            int listY = pageTop + 34;
            int listH = pageBottom - listY;
            HWND hSu = GetDlgItem(hWnd, IDC_SU_REFRESH);
            if (listH < 100) listH = 100;
            if (hSu) MoveWindow(hSu, 10, pageTop, 90, 28, TRUE);
            if (g_hSuStatus) MoveWindow(g_hSuStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            if (g_hSuList)   MoveWindow(g_hSuList, 10, listY, w, listH, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else if (g_MainTab == 4) {
            /* Network 页：左树 + 右列表 + 底部状态（与原版一致） */
            int listY = pageTop;
            int listH = pageBottom - listY - 26;
            int treeW = 250;
            if (listH < 100) listH = 100;
            if (g_hNwTree)   MoveWindow(g_hNwTree, 10, listY, treeW, listH + 26, TRUE);
            if (g_hNwList)   MoveWindow(g_hNwList, 10 + treeW + 8, listY,
                                        w - treeW - 8, listH, TRUE);
            if (g_hNwStatus) MoveWindow(g_hNwStatus, 10 + treeW + 8,
                                        pageBottom - 22, w - treeW - 8, 20, TRUE);
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        } else {
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        }
        return 0;
    }

    case WM_COMMAND:
        /* 第二步增量2：过滤框边打边筛（EN_CHANGE 是通知码，不是命令 ID） */
        if (LOWORD(wParam) == IDC_PROC_FILTER && HIWORD(wParam) == EN_CHANGE) {
            char filter[128];
            GetDlgItemTextA(hWnd, IDC_PROC_FILTER, filter, sizeof(filter));
            FeProcPageSetFilter(filter);
            return 0;
        }
        switch (LOWORD(wParam)) {
        case IDC_CONNECT: DoConnect(); return 0;
        case IDC_REFRESH: DoRefreshProcs(); return 0;
        case IDC_SCAN:    DoScan();    return 0;
        case IDC_SEND:    DoSend();    return 0;
        case IDC_KILL:    DoKillSelected(); return 0;
        case IDC_PROC_AUTO: FeProcPageToggleAuto(hWnd); return 0;   /* 第二步增量 */
        case IDC_KM_REFRESH: DoRefreshKernel(); return 0;
        case IDC_KM_ONLYLOADED:
            g_KmOnlyLoaded = (IsDlgButtonChecked(hWnd, IDC_KM_ONLYLOADED) == BST_CHECKED) ? 1 : 0;
            DoRefreshKernel();
            return 0;
        case IDC_KM_COPYNAME: DoCopyKmColumn(0, "Driver name"); return 0;
        case IDC_KM_COPYPATH: DoCopyKmColumn(3, "Driver path"); return 0;
        case IDC_KM_DRVOP:    DoDriverContextMenu(hWnd, -1, -1); return 0;
        case IDC_KM_RESTORE:
        case IDC_KM_RESTOREALL: {
            BYTE res = 0;
            char msg[256];
            if (!g_Client.Opened) {
                SetWindowTextA(g_hKmStatus, "SSDT restore: not connected to the driver");
                return 0;
            }
            if (wParam == IDC_KM_RESTOREALL) {
                BOOL ok = FeRestoreSsdtAll(&g_Client, &res);
                sprintf_s(msg, sizeof(msg), "Restore All (0xE7): %s, result=%u",
                          ok ? "sent" : "rejected", res);
            } else {
                int sel = ListView_GetNextItem(g_hKmList, -1, LVNI_SELECTED);
                if (sel < 0) {
                    SetWindowTextA(g_hKmStatus,
                                   "Restore: select an SSDT entry row first");
                    return 0;
                }
                if (sel > 6) {
                    sprintf_s(msg, sizeof(msg),
                              "Restore: driver 0xEB only covers selectors 0..6 "
                              "(ServiceTableCount and KiServiceTable[1..6]); "
                              "row %d is not restorable", sel);
                } else {
                    BOOL ok = FeRestoreSsdtEntry(&g_Client, (ULONG)sel, &res);
                    sprintf_s(msg, sizeof(msg),
                              "Restore entry %d (0xEB): %s, result=%u",
                              sel, ok ? "sent" : "rejected", res);
                }
            }
            SetWindowTextA(g_hKmStatus, msg);
            return 0;
        }
        case IDC_SU_REFRESH: DoRefreshStartup(); return 0;
        case IDC_SV_REFRESH: DoRefreshServices(); return 0;
        case IDC_RG_REFRESH: DoRefreshRegistry(); return 0;
        case IDC_RG_GO:      DoRefreshRegistry(); return 0;
        case IDC_FL_GO:      DoRefreshFiles(); return 0;
        case IDC_OT_VERIFY:  DoRefreshOther(); return 0;
        case IDC_EX_RUN:     DoRefreshExamination(); return 0;
        case IDC_EX_CANCEL:  FeExamCancel(); return 0;
        case IDC_EX_EXPORT:  DoExportExamination(); return 0;
        case IDC_FE_ANALYSE: DoFireeyeAnalyse(); return 0;
        case IDC_FE_OPEN: {
            char url[512];
            if (g_FeHasJob && FeFireeyeBuildUrl(&g_FeJob, url, sizeof(url))) {
                FeOpenUrl(url);
                FeFireeyeAddRecord(&g_FeJob);
                DoFireeyeRecords();
            }
            return 0;
        }
        case IDC_FE_RECORDS: DoFireeyeRecords(); return 0;
        case IDC_FE_CLEAR:   FeFireeyeDeleteRecords(); DoFireeyeRecords(); return 0;
        case IDC_ST_REFRESH: DoRefreshSetting(); return 0;
        case IDC_TR_SCAN:    DoTrojanScan(); return 0;
        case IDC_TR_BACKUP:  DoTrojanBackup(); return 0;
        case IDC_HK_REFRESH: DoRefreshHooks(); return 0;
        case IDC_HK_RESTORE: DoRestoreOverHooks(); return 0;
        case IDC_HK_CBTABLE: DoRestoreCallbackTable(); return 0;
        case IDC_ST_APPLY: {
            /* 按列表选中行决定对哪一项下 Forbid；未选中时默认第 1 项（File）。 */
            int si = g_hStList
                     ? ListView_GetNextItem(g_hStList, -1, LVNI_SELECTED) : -1;
            if (si < 0 || si > 4) {
                if (g_hStStatus)
                    SetWindowTextA(g_hStStatus,
                                   "Select one of the five Forbid rows first");
                return 0;
            }
            DoApplyForbid(si);
            return 0;
        }
        case IDC_ST_PROT_SSDT:
            if (FeSettingSelfProtect(&g_Client, 1)) SetWindowTextA(g_hStStatus, "SSDT self-protection enabled");
            else SetWindowTextA(g_hStStatus, "SelfProtection rejected (needs 21712-byte output)");
            return 0;
        case IDC_ST_PROT_SHADOW:
            if (FeSettingSelfProtect(&g_Client, 0)) SetWindowTextA(g_hStStatus, "SSDT self-protection disabled");
            else SetWindowTextA(g_hStStatus, "SelfProtection rejected");
            return 0;
        case IDC_ST_TRAY: {
            BOOL on = FeSettingGetMinimizeToTray();
            FeSettingSetMinimizeToTray(on ? FALSE : TRUE);
            DoRefreshSetting();
            return 0;
        }
        }
        return 0;

    case WM_CONTEXTMENU: {
        HWND from = (HWND)wParam;
        int x = (short)LOWORD(lParam);
        int y = (short)HIWORD(lParam);
        if (x == -1 && y == -1) {
            RECT rc;
            GetWindowRect(from ? from : hWnd, &rc);
            x = rc.left + 40;
            y = rc.top + 40;
        }
        if (from == g_hKmList) {
            DoDriverContextMenu(hWnd, x, y);
            return 0;
        }
        if (from == g_hProc) {
            DoProcessContextMenu(hWnd, x, y);
            return 0;
        }
        if (from == g_hDetail && g_DetailTab == 0) {
            DoModuleContextMenu(hWnd, x, y);
            return 0;
        }
        if (from == g_hSvList) {
            DoServiceContextMenu(hWnd, x, y);
            return 0;
        }
        if (from == g_hSuList) {
            DoStartupContextMenu(hWnd, x, y);
            return 0;
        }
        break;
    }
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)lParam;
        if (nm->idFrom == IDC_MAIN_TABS && nm->code == TCN_SELCHANGE) {
            int page = (int)SendMessageA(g_hMainTabs, TCM_GETCURSEL, 0, 0);
            ShowPage(hWnd, page);
            if (page == 1)
                DoRefreshKernel();
            if (page == 6)
                DoRefreshStartup();
            if (page == 7)
                DoRefreshServices();
            if (page == 5)
                DoRefreshRegistry();
            if (page == 8)
                DoRefreshFiles();
            if (page == 13)
                DoRefreshOther();
            if (page == 9)
                DoRefreshExamination();
            if (page == 11)
                DoFireeyeAnalyse();
            if (page == 10)
                DoRefreshSetting();
            if (page == 12)
                DoTrojanScan();
            if (page == 2 || page == 3)
                DoRefreshHooks();
            return 0;
        }
        if (nm->idFrom == IDC_RG_TABS && nm->code == TCN_SELCHANGE) {
            HWND hPath, hGo;
            g_RgTab = (int)SendMessageA(g_hRgTabs, TCM_GETCURSEL, 0, 0);
            hPath = GetDlgItem(hWnd, IDC_RG_PATH);
            hGo = GetDlgItem(hWnd, IDC_RG_GO);
            if (hPath) {
                ShowWindow(hPath, g_RgTab == 0 ? SW_SHOW : SW_HIDE);
                if (g_RgTab == 0)
                    SetWindowTextA(hPath, g_RgPath);
                if (hGo)
                    SetWindowTextA(hGo, "Go");
                if (hGo)
                    ShowWindow(hGo, g_RgTab == 0 ? SW_SHOW : SW_HIDE);
            }
            DoRefreshRegistry();
            /* Key 子页多一行路径框，切子页时要重排 */
            {
                RECT rc;
                GetClientRect(hWnd, &rc);
                SendMessageA(hWnd, WM_SIZE, SIZE_RESTORED,
                             MAKELPARAM(rc.right, rc.bottom));
            }
            return 0;
        }
        if (nm->idFrom == IDC_KM_TABS && nm->code == TCN_SELCHANGE) {
            g_KmTab = (int)SendMessageA(g_hKmTabs, TCM_GETCURSEL, 0, 0);
            DoRefreshKernel();
            /* Restore / Restore All 只在 SSDT 子页显示 */
            {
                HWND b;
                BOOL showSsdt = (g_KmTab == 2 || g_KmTab == 3);
                b = GetDlgItem(hWnd, IDC_KM_RESTORE);
                if (b) ShowWindow(b, showSsdt ? SW_SHOW : SW_HIDE);
                b = GetDlgItem(hWnd, IDC_KM_RESTOREALL);
                if (b) ShowWindow(b, showSsdt ? SW_SHOW : SW_HIDE);
                b = GetDlgItem(hWnd, IDC_KM_DRVOP);
                if (b) ShowWindow(b, showSsdt ? SW_HIDE : SW_SHOW);
            }
            return 0;
        }
        if (nm->idFrom == IDC_NW_TREE && nm->code == TVN_SELCHANGED) {
            NMTREEVIEWA *tv = (NMTREEVIEWA *)lParam;
            if (tv->itemNew.lParam != (LPARAM)g_NwNode) {
                g_NwNode = (int)tv->itemNew.lParam;
                DoRefreshNetwork();
            }
            return 0;
        }
        if (nm->idFrom == IDC_NW_LIST && nm->code == NM_DBLCLK) {
            /* 原版 sub_1400A6840：仅节点 1 的恢复动作（cmd 0xE7） */
            if (g_NwNode == 1 &&
                ListView_GetNextItem(g_hNwList, -1, LVNI_SELECTED) >= 0)
                NwRestoreTdi();
            return 0;
        }
        if (nm->idFrom == IDC_PROCLIST && nm->code == LVN_COLUMNCLICK) {
            /* 第二步增量：列头点击排序（FeProcPage.c 缓存上排序重绘） */
            FeProcPageOnColumnClick(((NMLISTVIEW *)lParam)->iSubItem);
            return 0;
        }
        if (nm->idFrom == IDC_TABS && nm->code == TCN_SELCHANGE) {
            DoRefreshDetail();
        } else if (nm->idFrom == IDC_PROCLIST && nm->code == LVN_ITEMCHANGED) {
            NMLISTVIEW *lv = (NMLISTVIEW *)lParam;
            if ((lv->uChanged & LVIF_STATE) &&
                ((lv->uNewState & LVIS_SELECTED) || (lv->uOldState & LVIS_SELECTED)))
                DoRefreshDetail();
        }
        return 0;
    }

    case WM_TIMER:
        /* 第二步增量：统一刷新模型——auto-refresh 定时器（页模块经 g_AutoRefFn 注册） */
        if (wParam == FE_AUTOREF_TIMER_ID && g_AutoRefFn) {
            g_AutoRefFn();
            return 0;
        }
        break;

    case WM_DESTROY:
        KillTimer(hWnd, FE_AUTOREF_TIMER_ID);
        if (g_Client.Opened)
            XpchClose(&g_Client);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* Non-GUI mode so the same shape/skip logic can be exercised from a headless
   session (vmrun runProgramInGuest cannot show a window). */
int FeCliDispatch(const char *lpCmdLine);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow)
{
    WNDCLASSA wc;
    HWND hWnd;
    MSG msg;
    INITCOMMONCONTROLSEX icc;

    UNREFERENCED_PARAMETER(hPrev);

    /* 【2026-10-25 新增】本程序是 GUI 子系统（PE Subsystem=2），而所有
       --xxx-cli 入口都靠 printf 汇报。GUI 子系统进程默认**没有 stdout**：
       从 cmd 直接运行时 printf 全部丢弃，重定向到文件也拿不到内容。
       这曾让 --hotkeys-cli 表现为"完全无输出"，被误判成功能未实现。

       注意必须**先探测** stdout 是否已可用 —— 调用方常用
       `(prog) > file 2>&1` 由 cmd 先把句柄绑到文件，此时不能再用
       CONOUT$ 覆盖，否则反而把输出抢走。只有原本拿不到句柄时才补。 */
    if (lpCmdLine && strstr(lpCmdLine, "-cli")) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == NULL || hOut == INVALID_HANDLE_VALUE) {
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
                AllocConsole();
            {
                FILE *fDummy;
                freopen_s(&fDummy, "CONOUT$", "w", stdout);
                freopen_s(&fDummy, "CONOUT$", "w", stderr);
            }
        }
        setvbuf(stdout, NULL, _IONBF, 0);   /* CLI 模式不要缓冲，崩溃前也能拿到 */
    }

    /* CLI 分发已拆至 CliMain.c（2026-10-28）。调度器按原 if 链的源码顺序
       走链：命中返回退出码，全不命中（FE_CLI_NONE）落入下方 GUI 路径。 */
    {
        int CliRc = FeCliDispatch(lpCmdLine);
        if (CliRc != FE_CLI_NONE)
            return CliRc;
    }

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "XPCHunterFrontend";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassA(&wc);

    hWnd = CreateWindowA("XPCHunterFrontend", "XPCHunter Frontend - Process",
                         WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                         1000, 980, NULL, NULL, hInst, NULL);
    if (!hWnd)
        return 1;

    ShowWindow(hWnd, nShow);
    UpdateWindow(hWnd);

    /* 打开即连接并刷新进程列表 —— ARK 前端的行为就是一打开就能看到进程。
       连不上（驱动没启动）时 DoConnect 会在状态栏说明原因。 */
    DoConnect();
    DoRefreshProcs();

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}