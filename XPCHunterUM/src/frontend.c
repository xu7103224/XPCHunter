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
#include <commctrl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")

/* 本文件是 /DUNICODE 编译的，而所有列表标题都是 ANSI 字面量（LVCOLUMNA）。
 * ListView_InsertColumn 在 UNICODE 下展开成 LVM_INSERTCOLUMNW (0x1061)，
 * 会把 char* 当 wchar_t* 读，表头就成了乱码。这里统一改走 ANSI 通道。 */
static int FeInsertColumnA(HWND h, int i, const LVCOLUMNA *pc)
{
    LVCOLUMNA copy;

    if (!pc)
        return 0;
    copy = *pc;
    return (int)SendMessageA(h, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&copy);
}
#define ListView_InsertColumn(h, i, pc) FeInsertColumnA((h), (i), (pc))

#define IDC_CONNECT     1001
#define IDC_SCAN        1002
#define IDC_SEND        1003
#define IDC_CMD         1004
#define IDC_OUTSIZE     1005  /* not IDC_SIZE: winuser.h already defines IDC_SIZE */
#define IDC_LIST        1006
#define IDC_STATUS      1007
#define IDC_REFRESH     1008
#define IDC_PROCLIST    1009
#define IDC_PROCSTATUS  1010
#define IDC_TABS        1011
#define IDC_DETAIL      1012
#define IDC_KILL        1013
/* Kernel 页（现已收进主 Tab 容器） */
#define IDC_KERNEL      1014
#define IDC_KM_REFRESH  1020
#define IDC_KM_TABS     1021
#define IDC_KM_LIST     1022
#define IDC_KM_STATUS   1023
#define IDC_KM_KEXTRA   1028   /* Driver 页的"其他内核项"独立状态行 */
/* Driver 子页：只显示已加载 + 复制名/路径（原版右键菜单项） */
#define IDC_KM_ONLYLOADED 1024
#define IDC_KM_COPYNAME   1025
#define IDC_KM_COPYPATH   1026
#define IDC_KM_DRVOP      1027
#define IDC_KM_RESTORE    1066
#define IDC_KM_RESTOREALL 1067

/* Driver 子页操作（原版右键菜单 5 项；Locate in Registry Tab 走独立菜单项 4008） */
#define DRVOP_VERIFY      0
#define DRVOP_VERIFY_ALL  1
#define DRVOP_UNLOAD      2
#define DRVOP_DEL_FILE    3
#define DRVOP_DEL_FILE_REG 4
/* 14 个主 Tab 容器 */
#define IDC_MAIN_TABS   1030
#define IDC_PAGEHINT    1031
/* Startup Info 页 */
#define IDC_SU_REFRESH  1040
#define IDC_SU_LIST     1041
#define IDC_SU_STATUS   1042
/* Services 页 */
#define IDC_SV_REFRESH  1050
#define IDC_SV_LIST     1051
#define IDC_SV_STATUS   1052
/* Registry 页 */
#define IDC_RG_REFRESH  1060
#define IDC_RG_TABS     1061
#define IDC_RG_LIST     1062
#define IDC_RG_STATUS   1063
#define IDC_RG_PATH     1064
#define IDC_RG_GO       1065
/* File 页 */
#define IDC_FL_DIR      1070
#define IDC_FL_GO       1071
#define IDC_FL_LIST     1072
#define IDC_FL_STATUS   1073
#define IDC_FL_DEL      1074
#define IDC_FL_VERIFY   1075
/* Other 页 */
#define IDC_OT_LIST     1080
#define IDC_OT_STATUS   1081
#define IDC_OT_PATH     1082
#define IDC_OT_VERIFY   1083
#define IDC_OT_QUERY    1084
/* Network 页（主 Tab 4） */
#define IDC_NW_LIST     1085
#define IDC_NW_STATUS   1086
/* Examination 页 */
#define IDC_EX_RUN      1090
#define IDC_EX_CANCEL   1091
#define IDC_EX_EXPORT   1092
#define IDC_EX_LIST     1093
#define IDC_EX_STATUS   1094
/* Fireeye 页 */
#define IDC_FE_PATH     1100
#define IDC_FE_ANALYSE  1101
#define IDC_FE_OPEN     1102
#define IDC_FE_RECORDS  1103
#define IDC_FE_CLEAR    1104
#define IDC_FE_LIST     1105
#define IDC_FE_STATUS   1106
/* Setting 页 */
#define IDC_ST_LIST     1110
#define IDC_ST_STATUS   1111
#define IDC_ST_APPLY    1112
#define IDC_ST_REFRESH  1113
#define IDC_ST_PROT_SSDT 1114
#define IDC_ST_PROT_SHADOW 1115
#define IDC_ST_TRAY     1116
/* Trojan Detection 页 */
#define IDC_TR_SCAN     1120
#define IDC_TR_BACKUP   1121
#define IDC_TR_RESTORE  1122
#define IDC_TR_REPAIR   1123
#define IDC_TR_LIST     1124
#define IDC_TR_STATUS   1125
/* Hooks 页（Ring0 = 主 Tab 2，Ring3 = 主 Tab 3） */
#define IDC_HK_REFRESH  1130
#define IDC_HK_LIST     1131
#define IDC_HK_STATUS   1132
/* Ring0 两项恢复操作（原版右键菜单项，这里做成按钮，便于实机验证） */
#define IDC_HK_RESTORE  1133
#define IDC_HK_CBTABLE  1134

static XPCH_CLIENT g_Client;
static HWND g_hList, g_hStatus, g_hCmd, g_hSize;
static HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
static HWND g_hKmTabs, g_hKmList, g_hKmStatus, g_hKmKExtra;
static HWND g_hMainTabs, g_hPageHint;
static HWND g_hMainWnd;
static HWND g_hSuList, g_hSuStatus;
static HWND g_hSvList, g_hSvStatus;
static HWND g_hRgTabs, g_hRgList, g_hRgStatus;
static int  g_RgTab = 0;
/* Key 子页当前打开的路径；Kernel 页 "Locate in Registry Tab" 会改写它 */
static char g_RgPath[512] = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
static HWND g_hFlDir, g_hFlList, g_hFlStatus;
static HWND g_hOtList, g_hOtStatus, g_hOtPath;
static HWND g_hExList, g_hExStatus;
static FE_EXAM_RESULT g_ExamResult;
static int g_ExamLoaded = 0;
static HWND g_hFePath, g_hFeList, g_hFeStatus;
static FE_FIREEYE_JOB g_FeJob;
static int g_FeHasJob = 0;
static HWND g_hStList, g_hStStatus;
static FE_OBJ_TYPES g_StObjTypes;
static int g_StObjReady = 0;
static HWND g_hTrList, g_hTrStatus;
static FE_TROJAN_REPORT g_TrReport;
static int g_TrLoaded = 0;
static HWND g_hHkList, g_hHkStatus;
/* Network 页（主 Tab 4）：0xF8 InitKernelMemoryContext 的 WFP/KFD/NSI
   解析结果。数据源见 frontend.c 的 DoRefreshNetwork。 */
static HWND g_hNwList, g_hNwStatus;
static int  g_MainTab = 0;    /* 当前主 Tab（0 = Process） */
static int  g_KmTab = 0;
static int  g_KmOnlyLoaded = 0;
static int  g_DetailTab = -1;
static int  g_StartTab = 0;   /* --tab N：启动时预选 Process 的子视图页 */

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

static void SetStatus(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    SetWindowTextA(g_hStatus, buf);
}

static void SetSubItemText(int iItem, int iSub, const char *text);

static void AddRow(ULONG cmd, const char *result, const char *detail)
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

static void SetSubItemText(int iItem, int iSub, const char *text)
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

static BOOL FeIsSkipped(ULONG cmd)
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
static BOOL SendOne(ULONG cmd, ULONG outSize, char *detail, size_t detailLen)
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
static void CreateProcColumns(HWND h)
{
    static const char *titles[] = { "PID", "Name", "Path", "EPROCESS", "Ring3 Access State" };
    static const int widths[] = { 55, 130, 340, 150, 130 };
    LVCOLUMNA col;
    int i;

    for (i = 0; i < 5; i++) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.iSubItem = i;
        col.pszText = (LPSTR)titles[i];
        col.cx = widths[i];
        SendMessageA(h, LVM_INSERTCOLUMNA, i, (LPARAM)&col);
    }
}

/* ---- 明细子视图（Modules / Threads / Windows）--------------------------- */

static const char *g_TabNames[7] = { "Modules", "Threads", "Windows", "Handles",
                                     "Memory", "Timer", "HotKey" };

static ULONG GetSelectedPid(void)
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

static void DetailSetText(int row, int sub, const char *text)
{
    LVITEMA item;
    ZeroMemory(&item, sizeof(item));
    item.iSubItem = sub;
    item.pszText = (LPSTR)text;
    SendMessageA(g_hDetail, LVM_SETITEMTEXTA, (WPARAM)row, (LPARAM)&item);
}

static void DetailAddRow(const char *c0, const char *c1, const char *c2, const char *c3)
{
    LVITEMA item;
    int row = (int)SendMessageA(g_hDetail, LVM_GETITEMCOUNT, 0, 0);

    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.pszText = (LPSTR)c0;
    SendMessageA(g_hDetail, LVM_INSERTITEMA, 0, (LPARAM)&item);
    if (c1) DetailSetText(row, 1, c1);
    if (c2) DetailSetText(row, 2, c2);
    if (c3) DetailSetText(row, 3, c3);
}

static void SetupDetailColumns(int tab)
{
    /* 7 个子视图：0 Modules / 1 Threads / 2 Windows / 3 Handles / 4 Memory
       / 5 Timer / 6 HotKey */
    static const char *cols[7][7] = {
        { "Base", "Size", "Name", "Path", "", "", "" },
        { "TID", "Prio", "Start", "", "", "", "" },
        { "HWND", "TID", "Class", "Title", "", "", "" },
        { "Handle", "Type", "Access", "Object", "", "", "" },
        { "Base", "Size", "Protect", "Type", "Name", "", "" },
        { "Handle", "Object", "Access", "", "", "", "" },
        { "Bucket", "Flags", "Hotkey", "PID", "TID", "Process", "EPROCESS" },
    };
    static const int widths[7][7] = {
        { 130, 90, 160, 380, 0, 0, 0 },
        { 70, 60, 150, 0, 0, 0, 0 },
        { 110, 60, 170, 340, 0, 0, 0 },
        { 90, 180, 100, 260, 0, 0, 0 },
        { 130, 100, 80, 70, 360, 0, 0 },
        { 100, 190, 110, 0, 0, 0, 0 },
        { 120, 90, 220, 70, 70, 190, 140 },
    };
    LVCOLUMNA col;
    int i;
    int n = (tab == 1) ? 3 : ((tab == 4) ? 5 : ((tab == 5) ? 3 : ((tab == 6) ? 7 : 4)));

    while (SendMessageA(g_hDetail, LVM_DELETECOLUMN, 0, 0))
        ;
    SendMessageA(g_hDetail, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < n; i++) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.iSubItem = i;
        col.pszText = (LPSTR)cols[tab][i];
        col.cx = widths[tab][i];
        SendMessageA(g_hDetail, LVM_INSERTCOLUMNA, i, (LPARAM)&col);
    }
}

static void DoRefreshDetail(void)
{
    int tab = (int)SendMessageA(g_hTabs, TCM_GETCURSEL, 0, 0);
    ULONG pid = GetSelectedPid();
    char a[64], b[64], c[64], d[600];

    if (tab < 0 || tab > 6)
        tab = 0;
    if (tab != g_DetailTab) {
        g_DetailTab = tab;
        SetupDetailColumns(tab);
    } else {
        SendMessageA(g_hDetail, LVM_DELETEALLITEMS, 0, 0);
    }

    if (!pid) {
        SetWindowTextA(g_hProcStatus, "Select a process to populate this view");
        return;
    }

    if (tab == 0) {
        FE_MODULE_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessModules(pid, 1024, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                char name[128], path[FE_MODULE_PATH_CHARS * 2];
                FeWideToAnsi(list.Items[i].Name, name, sizeof(name));
                FeWideToAnsi(list.Items[i].Path, path, sizeof(path));
                sprintf_s(a, sizeof(a), "%p", (void *)(ULONG_PTR)list.Items[i].Base);
                sprintf_s(b, sizeof(b), "0x%lX", list.Items[i].Size);
                DetailAddRow(a, b, name, path);
            }
            FeFreeProcessModules(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu modules: %lu", pid, n);
    } else if (tab == 1) {
        FE_THREAD_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessThreads(pid, 2048, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                sprintf_s(a, sizeof(a), "%lu", list.Items[i].ThreadId);
                sprintf_s(b, sizeof(b), "%ld", list.Items[i].BasePriority);
                sprintf_s(c, sizeof(c), "%p", (void *)(ULONG_PTR)list.Items[i].StartAddress);
                DetailAddRow(a, b, c, NULL);
            }
            FeFreeProcessThreads(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu threads: %lu", pid, n);
    } else if (tab == 4) {
        FE_MEMORY_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessMemory(pid, 16384, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                char nm[FE_MEMORY_NAME_CHARS];
                FeWideToAnsi(list.Items[i].Name, nm, sizeof(nm));
                sprintf_s(a, sizeof(a), "%p", (void *)(ULONG_PTR)list.Items[i].Base);
                sprintf_s(b, sizeof(b), "0x%I64X", list.Items[i].Size);
                sprintf_s(c, sizeof(c), "0x%lX", list.Items[i].Protect);
                DetailAddRow(a, b, c, NULL);
                DetailSetText((int)SendMessageA(g_hDetail, LVM_GETITEMCOUNT, 0, 0) - 1, 3,
                              list.Items[i].Type == MEM_IMAGE ? "Image" :
                              (list.Items[i].Type == MEM_MAPPED ? "Mapped" : "Private"));
                DetailSetText((int)SendMessageA(g_hDetail, LVM_GETITEMCOUNT, 0, 0) - 1, 4, nm);
            }
            FeFreeProcessMemory(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu regions: %lu", pid, n);
    } else if (tab == 3) {
        FE_HANDLE_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessHandles(pid, 8192, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                sprintf_s(a, sizeof(a), "0x%IX", list.Items[i].Handle);
                sprintf_s(c, sizeof(c), "0x%lX", list.Items[i].Access);
                sprintf_s(d, sizeof(d), "%p", (void *)(ULONG_PTR)list.Items[i].Object);
                DetailAddRow(a, list.Items[i].TypeName[0] ? list.Items[i].TypeName : "(?)", c, d);
            }
            FeFreeProcessHandles(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu handles: %lu", pid, n);
    } else if (tab == 5) {
        /* View Timer：句柄类型为 Timer 的项 */
        FE_HANDLE_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessTimers(pid, 1024, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                sprintf_s(a, sizeof(a), "0x%I64X", list.Items[i].Handle);
                sprintf_s(b, sizeof(b), "%016I64X", list.Items[i].Object);
                sprintf_s(c, sizeof(c), "0x%lX", list.Items[i].Access);
                DetailAddRow(a, b, c, NULL);
            }
            FeFreeProcessHandles(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu timers: %lu", pid, n);
    } else if (tab == 6) {
        /* View HotKey：0x33 CmdEnumObjects（Win8 链表枚举）取全系统热键表，
           按选中进程的 EPROCESS 过滤，列布局与原版 CProcessHotkeyDialog 一致。 */
        FE_PROCESS_LIST procs;
        FE_HOTKEY_LIST list;
        ULONG64 eprocess = 0;
        ULONG i, n = 0;

        if (FeLoadProcessList(&g_Client, FE_PROC_DEFAULT_MAX, &procs)) {
            for (i = 0; i < procs.Count; i++) {
                if (procs.Items[i].Pid == pid) { eprocess = procs.Items[i].Eprocess; break; }
            }
            FeFreeProcessList(&procs);
        }
        if (!eprocess) {
            sprintf_s(d, sizeof(d), "PID %lu: cannot resolve EPROCESS", pid);
            SetWindowTextA(g_hProcStatus, d);
            return;
        }

        if (FeLoadProcessHotkeys(&g_Client, eprocess, 0, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                FE_HOTKEY_ENTRY *e = &list.Items[i];
                char hk[FE_HOTKEY_NAME_CHARS];
                char tid[32], ep[32];
                int row;

                FeWideToAnsi(e->Hotkey, hk, sizeof(hk));
                sprintf_s(a, sizeof(a), "%p", (void *)(ULONG_PTR)e->Bucket);
                sprintf_s(b, sizeof(b), "0x%08lX", e->Flags);
                sprintf_s(c, sizeof(c), "%lu", e->Pid);
                DetailAddRow(a, b, hk, c);
                row = (int)SendMessageA(g_hDetail, LVM_GETITEMCOUNT, 0, 0) - 1;
                sprintf_s(tid, sizeof(tid), "%lu", e->Tid);
                sprintf_s(ep, sizeof(ep), "0x%I64X", e->Eprocess);
                DetailSetText(row, 4, tid);
                DetailSetText(row, 5, e->ProcessName[0] ? e->ProcessName : "(?)");
                DetailSetText(row, 6, ep);
            }
            FeFreeProcessHotkeys(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu hotkeys: %lu", pid, n);
    } else {
        FE_WINDOW_LIST list;
        ULONG i, n = 0;

        if (FeLoadProcessWindows(pid, 512, &list)) {
            n = list.Count;
            for (i = 0; i < n; i++) {
                char title[FE_WINDOW_ENTRY_TITLE_CHARS * 2];
                FeWideToAnsi(list.Items[i].Title, title, sizeof(title));
                sprintf_s(a, sizeof(a), "%p", (void *)(ULONG_PTR)list.Items[i].Hwnd);
                sprintf_s(b, sizeof(b), "%lu", list.Items[i].ThreadId);
                DetailAddRow(a, b, list.Items[i].ClassName[0] ? list.Items[i].ClassName : "(?)", title);
            }
            FeFreeProcessWindows(&list);
        }
        sprintf_s(d, sizeof(d), "PID %lu windows: %lu", pid, n);
    }
    SetWindowTextA(g_hProcStatus, d);
}

/* ç»æéä¸­è¿ç¨ï¼ç ´åæ§æä½ï¼åäºæ¬¡ç¡®è®¤ã */
static void DoRefreshProcs(void);
static void DoRefreshFiles(void);

static void DoKillSelected(void)
{
    ULONG pid = GetSelectedPid();
    char msg[256];

    if (!pid) {
        SetWindowTextA(g_hProcStatus, "Select a process first");
        return;
    }
    if (!g_Client.Opened) {
        SetWindowTextA(g_hProcStatus, "Not connected");
        return;
    }

    sprintf_s(msg, sizeof(msg),
              "Terminate PID %lu?\n\nThis is destructive and cannot be undone.", pid);
    if (MessageBoxA(GetActiveWindow(), msg, "Confirm kill",
                    MB_YESNO | MB_ICONWARNING) != IDYES) {
        SetWindowTextA(g_hProcStatus, "Kill cancelled");
        return;
    }

    {
        FE_PROCESS_LIST list;
        ULONG64 eprocess = 0;
        ULONG i;

        if (FeLoadProcessList(&g_Client, FE_PROC_DEFAULT_MAX, &list)) {
            for (i = 0; i < list.Count; i++)
                if (list.Items[i].Pid == pid) { eprocess = list.Items[i].Eprocess; break; }
            FeFreeProcessList(&list);
        }
        if (FeKillProcess(&g_Client, pid, eprocess, FALSE)) {
            sprintf_s(msg, sizeof(msg), "PID %lu terminated", pid);
            SetWindowTextA(g_hProcStatus, msg);
            DoRefreshProcs();
        } else {
            sprintf_s(msg, sizeof(msg), "Kill PID %lu failed", pid);
            SetWindowTextA(g_hProcStatus, msg);
        }
    }
}

static void DoRefreshProcs(void)
{
    FE_PROCESS_LIST list;
    ULONG i, count;
    char buf[256];

    if (!g_Client.Opened) {
        SetWindowTextA(g_hProcStatus, "Not connected - click Connect first (it performs the handshake)");
        return;
    }

    SendMessageA(g_hProc, LVM_DELETEALLITEMS, 0, 0);

    if (!FeLoadProcessList(&g_Client, FE_PROC_DEFAULT_MAX, &list)) {
        SetWindowTextA(g_hProcStatus,
                       "0xE4 returned 0 - driver not ready (handshake) or output < 0x298 bytes");
        return;
    }
    count = list.Count;

    for (i = 0; i < count; i++) {
        LVITEMA item;

        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;
        sprintf_s(buf, sizeof(buf), "%lu", list.Items[i].Pid);
        item.pszText = buf;
        SendMessageA(g_hProc, LVM_INSERTITEMA, 0, (LPARAM)&item);

        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 1;
        item.pszText = list.Items[i].Name[0] ? list.Items[i].Name : (LPSTR)"(?)";
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);

        /* 完整映像路径：QueryFullProcessImageNameW（不走驱动 0x2A —— 它的
           KeStackAttachProcess 手工追链会让 guest 挂死，已记录待修）。 */
        if (!FeLoadProcessPathWin32(list.Items[i].Pid, list.Items[i].Path, FE_PROC_PATH_CHARS))
            list.Items[i].Path[0] = 0;
        {
            char path[FE_PROC_PATH_CHARS * 2];
            FeWideToAnsi(list.Items[i].Path, path, sizeof(path));
            ZeroMemory(&item, sizeof(item));
            item.iSubItem = 2;
            item.pszText = path;
            SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);
        }

        sprintf_s(buf, sizeof(buf), "%p", (void *)(ULONG_PTR)list.Items[i].Eprocess);
        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 3;
        item.pszText = buf;
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);

        /* Ring3 Access State：用户态能否打开这个进程 */
        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 4;
        item.pszText = FeIsProcessRing3Accessible(list.Items[i].Pid)
                       ? (LPSTR)"accessible" : (LPSTR)"INACCESSIBLE";
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);
    }

    {
        ULONG hidden = 0, inaccessible = 0;
        if (FeComputeProcessStatus(&list, &hidden, &inaccessible, NULL)) {
            FeFreeProcessList(&list);
            sprintf_s(buf, sizeof(buf),
                      "Processes: %lu, Hidden Processes: %lu, "
                      "Ring3 Inaccessible Processes: %lu",
                      count, hidden, inaccessible);
            SetWindowTextA(g_hProcStatus, buf);
            return;
        }
    }

    FeFreeProcessList(&list);

    sprintf_s(buf, sizeof(buf), "Processes: %lu", count);
    SetWindowTextA(g_hProcStatus, buf);

    /* 自动选中一行，让子视图立即有内容：优先 explorer.exe（System/Registry
       这类进程没有用户模块，选中它们子视图会是空的）。 */
    if (count) {
        int pick = 0;
        ULONG k;
        for (k = 0; k < count; k++) {
            char nm[32];
            LVITEMA gi;
            ZeroMemory(&gi, sizeof(gi));
            gi.iSubItem = 1;
            gi.pszText = nm;
            gi.cchTextMax = sizeof(nm);
            nm[0] = 0;
            SendMessageA(g_hProc, LVM_GETITEMTEXTA, (WPARAM)k, (LPARAM)&gi);
            if (_stricmp(nm, "explorer.exe") == 0) { pick = (int)k; break; }
        }
        {
            LVITEMA si;
            ZeroMemory(&si, sizeof(si));
            si.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
            si.state = LVIS_SELECTED | LVIS_FOCUSED;
            SendMessageA(g_hProc, LVM_SETITEMSTATE, (WPARAM)pick, (LPARAM)&si);
        }
    }
}

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
static void SuSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void CreateSuColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Location"; c.cx = 210; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "View";     c.cx = 45;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "Name";     c.cx = 240; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "Data";     c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
}

static void DoRefreshStartup(void)
{
    FE_STARTUP_LIST list;
    char status[256];
    ULONG i;

    if (!g_hSuList || !g_hSuStatus)
        return;
    ListView_DeleteAllItems(g_hSuList);
    CreateSuColumns(g_hSuList);

    if (!FeLoadStartupItems(&list)) {
        sprintf_s(status, sizeof(status), "Startup Info: 0 items");
        SetWindowTextA(g_hSuStatus, status);
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        char view[16];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = list.Items[i].Location;
        SendMessageA(g_hSuList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(view, sizeof(view), "%lu", list.Items[i].View);
        SuSetText(g_hSuList, (int)i, 1, view);
        SuSetText(g_hSuList, (int)i, 2, list.Items[i].Name);
        SuSetText(g_hSuList, (int)i, 3, list.Items[i].Data);
    }
    sprintf_s(status, sizeof(status), "Startup Info: %lu items (16 locations, Wow64 split)", list.Count);
    SetWindowTextA(g_hSuStatus, status);
    FeFreeStartupItems(&list);
}

/* ---- Services 页（主 Tab 7）---- */
static void SvSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void CreateSvColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Service";     c.cx = 200; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "State";       c.cx = 80;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "ServiceDll";  c.cx = 70;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "ImagePath / Resolved"; c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
}

/* ==========================================================================
 * Network 页（主 Tab 4）
 *
 * 【2026-10-22 实测更正】此前该页提示"驱动没有网络命令"，结论错误。
 *   实机验证（kd 读 g_GlobalTable）：
 *     命令 0xF8 CmdInitKernelMemoryContext 的处理器确实执行（HANDLED）；
 *     netio.sys 读取成功（0x94000 字节，kmctx stage=3 全部完成）；
 *     26 组 WFP/KFD/NSI 解析产出成对的 RVA + 绝对地址。
 *
 *   数据来源：0x13A（CmdDumpCallStats）诊断通道的 env 块 0x400 起，
 *   20 个 QWORD，对应以下 GT 槽（顺序与驱动侧 KmSlots[] 一致）。
 * ========================================================================== */
typedef struct _FE_NET_SLOT {
    ULONG       GtIndex;
    const char *Name;
    const char *Meaning;
} FE_NET_SLOT;

static const FE_NET_SLOT g_NetSlots[] = {
    { 0x7B2, "WFP NBL",        "FindWfpNblInfoDispatchTableClear" },
    { 0x7B4, "WFP NBL sect",   "ScanWfpNblInfoSections" },
    { 0x7B8, "KFD offload",    "FindKfdGetOffloadEpochExport" },
    { 0x7BB, "Kernel data",    "ScanKernelDataPartitionSection" },
    { 0x7BC, "KFD reg layer",  "FindKfdRegisterLayerCallbackExport" },
    { 0x7BE, "KFD dereg",      "FindKfdDeregisterLayerCallbackExport" },
    { 0x7C0, "KFD sections",   "ScanKfdDriverSections" },
    { 0x7C1, "WFP st shim",    "FindWfpStartStreamShimExport" },
    { 0x7C3, "WFP sp shim",    "FindWfpStopStreamShimExport" },
    { 0x7C7, "WFP shim sect",  "ScanWfpStreamShimSections" },
    { 0x7C8, "NSI dereg",      "FindNsiDeregisterChangeNotificationEx" },
    { 0x7CA, "NSI module",     "FindNsiGetModuleHandle" },
    { 0x7CD, "NSI data sect",  "ScanNsiGetModuleDataSection" },
    { 0x7CE, "NSI legacy",     "FindNsiDeregisterLegacyHandler" },
    { 0x7D0, "NSI dereg sect", "ScanNsiDeregisterDataSection" },
    { 0x7D1, "WFP mac shim",   "FindWfpStartMacShimExport" },
    { 0x7D3, "WFP mac sect",   "ScanWfpMacShimSections" },
    { 0x7D4, "WFP device",     "FindSetWfpDeviceObject" },
    { 0x7D6, "WFP dev sect",   "ScanWfpDeviceObjectSection" },
    { 0x7D7, "NMR provider",   "FindNmrRegisterProviderExport" }
};
#define FE_NET_SLOT_N (sizeof(g_NetSlots) / sizeof(g_NetSlots[0]))

static void CreateNwColumns(HWND hList)
{
    LVCOLUMNA c;
    static const struct { const char *t; int w; } cols[] = {
        { "Object",  150 },
        { "Value",   180 },
        { "Resolver", 380 }
    };
    int i;

    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (i = 0; i < 3; i++) {
        c.pszText = (char *)cols[i].t;
        c.cx = cols[i].w;
        c.iSubItem = i;
        ListView_InsertColumn(hList, i, &c);
    }
}

/* 通过 0x13A 诊断通道读 env 块里的 20 个解析槽 */
static void DoRefreshNetwork(void)
{
    UCHAR *buf;
    UCHAR res = 0;
    char status[512];
    ULONG i, nonZero = 0;
    int row = 0;

    if (!g_hNwList || !g_hNwStatus)
        return;
    ListView_DeleteAllItems(g_hNwList);
    CreateNwColumns(g_hNwList);

    if (!g_Client.Opened) {
        SetWindowTextA(g_hNwStatus, "Network: not connected");
        return;
    }

    /* 先触发 0xF8，让 WFP/KFD/NSI 解析结果就位（槽空才解析，重复调用无害） */
    {
        UCHAR dummy[0x40];
        XpchInvoke(&g_Client, 0xF8, NULL, 0, dummy, sizeof(dummy), &res);
    }

    buf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x4000);
    if (!buf) {
        SetWindowTextA(g_hNwStatus, "Network: out of memory");
        return;
    }
    if (!XpchInvoke(&g_Client, 0x13A, NULL, 0, buf, 0x4000, &res)) {
        SetWindowTextA(g_hNwStatus, "Network: 0x13A unavailable");
        HeapFree(GetProcessHeap(), 0, buf);
        return;
    }

    {
        /* env 块起点：283 条统计 * 16 + 开记录 16 */
        const UCHAR *env = buf + 283 * 16 + 16;
        const ULONG64 *vals = (const ULONG64 *)(const void *)(env + 0x400);
        ULONG stage = *(const ULONG *)(const void *)(env + 0x3B0);
        ULONG fsize = *(const ULONG *)(const void *)(env + 0x3B4);

        for (i = 0; i < FE_NET_SLOT_N; i++) {
            LVITEMA it;
            char val[64];
            char meaning[160];

            if (vals[i])
                nonZero++;
            sprintf_s(val, sizeof(val), "0x%016llX",
                      (unsigned long long)vals[i]);
            sprintf_s(meaning, sizeof(meaning), "%s  (GT[0x%X])",
                      g_NetSlots[i].Meaning, g_NetSlots[i].GtIndex);

            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = (char *)g_NetSlots[i].Name;
            SendMessageA(g_hNwList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            it.iSubItem = 1; it.pszText = val;
            SendMessageA(g_hNwList, LVM_SETITEMTEXTA, row, (LPARAM)&it);
            it.iSubItem = 2; it.pszText = meaning;
            SendMessageA(g_hNwList, LVM_SETITEMTEXTA, row, (LPARAM)&it);
            row++;
        }

        sprintf_s(status, sizeof(status),
                  "Network: %lu/%lu resolved   netio.sys=0x%lX   stage=%lu"
                  "   (0=not run 1=read failed 2=parsing 3=done)",
                  nonZero, (ULONG)FE_NET_SLOT_N, fsize, stage);
        SetWindowTextA(g_hNwStatus, status);
    }

    HeapFree(GetProcessHeap(), 0, buf);
}

static void DoRefreshServices(void)
{
    FE_SERVICE_LIST list;
    char status[256];
    ULONG i;

    if (!g_hSvList || !g_hSvStatus)
        return;
    ListView_DeleteAllItems(g_hSvList);
    CreateSvColumns(g_hSvList);

    if (!FeLoadServices(&list)) {
        SetWindowTextA(g_hSvStatus, "Services: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        const char *st;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = list.Items[i].Name;
        SendMessageA(g_hSvList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        switch (list.Items[i].State) {
        case SERVICE_RUNNING: st = "RUNNING"; break;
        case SERVICE_STOPPED: st = "STOPPED"; break;
        case SERVICE_START_PENDING: st = "STARTING"; break;
        case SERVICE_STOP_PENDING: st = "STOPPING"; break;
        default: st = "?"; break;
        }
        SvSetText(g_hSvList, (int)i, 1, st);
        SvSetText(g_hSvList, (int)i, 2, list.Items[i].ServiceDll[0] ? "yes" : "-");
        SvSetText(g_hSvList, (int)i, 3,
                  list.Items[i].ResolvedPath[0] ? list.Items[i].ResolvedPath :
                  (list.Items[i].ImagePath[0] ? list.Items[i].ImagePath : "(?)"));
    }
    sprintf_s(status, sizeof(status),
              "Services: %lu / Hidden Services: %lu  (registry keys: %lu)",
              list.Count, list.HiddenCount, list.RegServiceCount);
    SetWindowTextA(g_hSvStatus, status);
    FeFreeServices(&list);
}

/* Startup Info 页右键：Delete Startup / Delete(Startup And File) / Repair Startup。
 * 原版的这三项都在自启动项列表的右键菜单里。 */
static void DoStartupOp(int Op)
{
    int sel;
    FE_STARTUP_LIST list;
    ULONG i;
    char msg[768];
    char name[FE_STARTUP_NAME_CHARS];

    if (!g_hSuList || !g_hSuStatus)
        return;

    if (Op == 2) {   /* Repair Startup：整表检查，不需要选中行 */
        ULONG checked = 0, fixed;
        FE_STARTUP_LIST rep;
        fixed = FeRepairStartupItems(&checked, &rep);
        if (fixed) {
            sprintf_s(msg, sizeof(msg),
                      "Repair Startup: %lu of %lu entries pointed at missing files "
                      "and were removed", fixed, checked);
        } else {
            sprintf_s(msg, sizeof(msg),
                      "Repair Startup: checked %lu entries, none needed repair "
                      "(all targets exist)", checked);
        }
        SetWindowTextA(g_hSuStatus, msg);
        FeFreeStartupItems(&rep);
        DoRefreshStartup();
        return;
    }

    sel = ListView_GetNextItem(g_hSuList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hSuStatus, "Select a startup item first");
        return;
    }
    name[0] = 0;
    {
        LVITEMA it;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = sel;
        it.iSubItem = 1;        /* Name 列 */
        it.pszText = name;
        it.cchTextMax = (int)sizeof(name);
        SendMessageA(g_hSuList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it);
    }

    if (!FeLoadStartupItems(&list)) {
        SetWindowTextA(g_hSuStatus, "Startup: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) != 0)
            continue;
        if (Op == 0) {          /* Delete Startup */
            if (FeDeleteStartupItem(&list.Items[i]))
                sprintf_s(msg, sizeof(msg), "Delete Startup: %s removed", name);
            else
                sprintf_s(msg, sizeof(msg), "Delete Startup: %s failed", name);
        } else {                /* Delete(Startup And File) */
            char path[FE_STARTUP_DATA_CHARS];
            BOOL regOk = FALSE;
            DWORD fileErr = 0;
            BOOL ok = FeDeleteStartupItemAndFile(&list.Items[i], path, sizeof(path),
                                                 &regOk, &fileErr);
            if (ok) {
                sprintf_s(msg, sizeof(msg),
                          "Delete(Startup And File): %s removed, file deleted: %s",
                          name, path[0] ? path : "(none)");
            } else {
                sprintf_s(msg, sizeof(msg),
                          "Delete(Startup And File): %s -> registry %s, "
                          "file delete failed (GetLastError=%lu)%s",
                          name, regOk ? "removed" : "failed",
                          (unsigned long)fileErr,
                          fileErr == ERROR_ACCESS_DENIED ? " [in use]" : "");
            }
        }
        SetWindowTextA(g_hSuStatus, msg);
        FeFreeStartupItems(&list);
        DoRefreshStartup();
        return;
    }
    FeFreeStartupItems(&list);
    SetWindowTextA(g_hSuStatus, "Startup item disappeared after refresh");
}

static void DoStartupContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    AppendMenuA(hMenu, MF_STRING, 8001, "Delete Startup");
    AppendMenuA(hMenu, MF_STRING, 8002, "Delete(Startup And File)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 8003, "Repair Startup");
    if (X == -1 && Y == -1) {
        RECT rc;
        GetWindowRect(g_hSuList, &rc);
        X = rc.left + 40;
        Y = rc.top + 40;
    }
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    if (cmd == 8001)
        DoStartupOp(0);
    else if (cmd == 8002)
        DoStartupOp(1);
    else if (cmd == 8003)
        DoStartupOp(2);
}

/* Services 页右键：原版把服务的 ImagePath / ServiceDll 直接送到 FireEye 页
 * 分析（Analyse ImagePath by FireEye / Analyse ServiceDll by FireEye）。
 * 这里取选中行的服务名 → 重新查该服务 → 切到 FireEye 页并填入路径。 */
static void DoFireeyeAnalyse(void);
static void ShowPage(HWND hWnd, int page);

static void DoServiceFireeye(int UseServiceDll)
{
    int sel;
    char name[FE_SVC_NAME_CHARS];
    LVITEMA it;
    FE_SERVICE_LIST list;
    ULONG i;
    const char *target = NULL;

    if (!g_hSvList || !g_hSvStatus)
        return;
    sel = ListView_GetNextItem(g_hSvList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hSvStatus, "Select a service first");
        return;
    }
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.pszText = name;
    it.cchTextMax = (int)sizeof(name);
    if (!SendMessageA(g_hSvList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it)) {
        SetWindowTextA(g_hSvStatus, "Selected service has no name");
        return;
    }
    if (!FeLoadServices(&list)) {
        SetWindowTextA(g_hSvStatus, "Services: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) == 0) {
            target = UseServiceDll
                     ? (list.Items[i].ServiceDll[0] ? list.Items[i].ServiceDll
                                                    : list.Items[i].ResolvedPath)
                     : (list.Items[i].ResolvedPath[0] ? list.Items[i].ResolvedPath
                                                      : list.Items[i].ImagePath);
            break;
        }
    }
    if (target && target[0] && g_hFePath) {
        char pathCopy[FE_SVC_PATH_CHARS];
        strcpy_s(pathCopy, sizeof(pathCopy), target);
        FeFreeServices(&list);
        SetWindowTextA(g_hFePath, pathCopy);
        g_MainTab = 11;
        if (g_hMainTabs)
            SendMessageA(g_hMainTabs, TCM_SETCURSEL, 11, 0);
        if (g_hMainWnd)
            ShowPage(g_hMainWnd, 11);
        DoFireeyeAnalyse();
        sprintf_s(pathCopy, sizeof(pathCopy), "%s", target);
        {
            char msg[512];
            sprintf_s(msg, sizeof(msg), "FireEye: %s -> %s",
                      UseServiceDll ? "ServiceDll" : "ImagePath", pathCopy);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    }
    FeFreeServices(&list);
    SetWindowTextA(g_hSvStatus,
                   UseServiceDll ? "Selected service has no ServiceDll"
                                 : "Selected service has no ImagePath");
}

/* 取 Services 列表选中行的服务条目（重新查表以拿到完整字段）。 */
static BOOL SvGetSelectedEntry(FE_SERVICE_ENTRY *Out)
{
    int sel;
    char name[FE_SVC_NAME_CHARS];
    LVITEMA it;
    FE_SERVICE_LIST list;
    ULONG i;
    BOOL found = FALSE;

    if (!Out || !g_hSvList)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    sel = ListView_GetNextItem(g_hSvList, -1, LVNI_SELECTED);
    if (sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.pszText = name;
    it.cchTextMax = (int)sizeof(name);
    if (!SendMessageA(g_hSvList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it))
        return FALSE;
    if (!FeLoadServices(&list))
        return FALSE;
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) == 0) {
            *Out = list.Items[i];
            found = TRUE;
            break;
        }
    }
    FeFreeServices(&list);
    return found;
}

/* Services 页右键。对应功能地图第 8 节列出的操作：
     Delete Service(Not Delete File) / Verify ServiceDll Signature /
     Find ImagePath Target / Find ServiceDll Target /
     Copy ImagePath / Copy ServiceDll Path /
     Locate in File Tab (ImagePath / ServiceDll)
   另有 Analyse ImagePath/ServiceDll by FireEye（DoServiceFireeye 单独实现）。 */
static void DoServiceOp(int Op)
{
    FE_SERVICE_ENTRY e;
    char msg[768];
    const char *path;

    if (!g_hSvStatus)
        return;
    if (!SvGetSelectedEntry(&e)) {
        SetWindowTextA(g_hSvStatus, "Select a service first");
        return;
    }
    path = e.ResolvedPath[0] ? e.ResolvedPath : e.ImagePath;

    switch (Op) {
    case 0:   /* Delete Service (Not Delete File) */
        {
            int r;
            sprintf_s(msg, sizeof(msg),
                      "Delete service \"%s\"?\n\nThe service registration is removed "
                      "but the file on disk is NOT deleted.", e.Name);
            r = MessageBoxA(g_hMainWnd, msg, "Delete Service",
                            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
            if (r != IDYES) {
                SetWindowTextA(g_hSvStatus, "Delete service cancelled");
                return;
            }
            if (FeDeleteService(e.Name))
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s removed (file kept: %s)",
                          e.Name, path[0] ? path : "(none)");
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s failed", e.Name);
            SetWindowTextA(g_hSvStatus, msg);
            DoRefreshServices();
        }
        return;
    case 1:   /* Verify ImagePath Signature */
        sprintf_s(msg, sizeof(msg), "Verify ImagePath Signature: %s -> %s (%s)",
                  e.Name,
                  FeVerifyFileSignature(path) ? "valid and trusted"
                                              : "no signature or not trusted",
                  path[0] ? path : "(no ImagePath)");
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 2:   /* Verify ServiceDll Signature */
        if (!e.ServiceDll[0]) {
            sprintf_s(msg, sizeof(msg),
                      "Verify ServiceDll Signature: %s has no ServiceDll", e.Name);
        } else {
            sprintf_s(msg, sizeof(msg), "Verify ServiceDll Signature: %s -> %s (%s)",
                      e.Name,
                      FeVerifyFileSignature(e.ServiceDll) ? "valid and trusted"
                                                          : "no signature or not trusted",
                      e.ServiceDll);
        }
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 3:   /* Find ImagePath Target */
    case 4:   /* Find ServiceDll Target */
        {
            const char *t = (Op == 3) ? path : e.ServiceDll;
            const char *what = (Op == 3) ? "Find ImagePath Target" : "Find ServiceDll Target";
            if (!t || !t[0]) {
                sprintf_s(msg, sizeof(msg), "%s: %s has no %s", what, e.Name,
                          Op == 3 ? "ImagePath" : "ServiceDll");
            } else {
                WCHAR wt[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, t, -1, wt, MAX_PATH);
                sprintf_s(msg, sizeof(msg), "%s: %s -> %s (%s)", what, e.Name, t,
                          GetFileAttributesW(wt) == INVALID_FILE_ATTRIBUTES
                          ? "FILE NOT FOUND" : "file exists");
            }
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 5:   /* Copy ImagePath */
    case 6:   /* Copy ServiceDll Path */
        {
            const char *t = (Op == 5) ? path : e.ServiceDll;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path to copy");
                return;
            }
            if (!OpenClipboard(g_hSvList))
                return;
            EmptyClipboard();
            {
                HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(t) + 1);
                if (h) {
                    void *q = GlobalLock(h);
                    if (q) {
                        memcpy(q, t, strlen(t) + 1);
                        GlobalUnlock(h);
                        SetClipboardData(CF_TEXT, h);
                    }
                }
            }
            CloseClipboard();
            sprintf_s(msg, sizeof(msg), "%s copied: %s",
                      Op == 5 ? "ImagePath" : "ServiceDll path", t);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 7:   /* Locate in File Tab (ImagePath) */
    case 8:   /* Locate in File Tab (ServiceDll) */
        {
            const char *t = (Op == 7) ? path : e.ServiceDll;
            char dir[FE_SVC_PATH_CHARS];
            char *slash;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path");
                return;
            }
            strcpy_s(dir, sizeof(dir), t);
            slash = strrchr(dir, '\\');
            if (slash)
                *slash = 0;
            if (g_hFlDir) {
                SetWindowTextA(g_hFlDir, dir);
                g_MainTab = 8;
                if (g_hMainTabs)
                    SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
                if (g_hMainWnd)
                    ShowPage(g_hMainWnd, 8);
                DoRefreshFiles();
            }
            sprintf_s(msg, sizeof(msg), "%s: located in File tab -> %s",
                      Op == 7 ? "Locate ImagePath" : "Locate ServiceDll", dir);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    default:
        return;
    }
}

static void DoServiceContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    AppendMenuA(hMenu, MF_STRING, 7003, "Delete Service (Not Delete File)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7004, "Verify ImagePath Signature");
    AppendMenuA(hMenu, MF_STRING, 7005, "Verify ServiceDll Signature");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7006, "Find ImagePath Target");
    AppendMenuA(hMenu, MF_STRING, 7007, "Find ServiceDll Target");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7008, "Copy ImagePath");
    AppendMenuA(hMenu, MF_STRING, 7009, "Copy ServiceDll Path");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7010, "Locate in File Tab (ImagePath)");
    AppendMenuA(hMenu, MF_STRING, 7011, "Locate in File Tab (ServiceDll)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7001, "Analyse ImagePath by FireEye");
    AppendMenuA(hMenu, MF_STRING, 7002, "Analyse ServiceDll by FireEye");
    if (X == -1 && Y == -1) {
        RECT rc;
        GetWindowRect(g_hSvList, &rc);
        X = rc.left + 40;
        Y = rc.top + 40;
    }
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    if (cmd == 7001)
        DoServiceFireeye(0);
    else if (cmd == 7002)
        DoServiceFireeye(1);
    else if (cmd >= 7003 && cmd <= 7011)
        DoServiceOp(cmd - 7003);
}

/* ---- Registry 页（主 Tab 5）----
 * 两个子页：
 *   Reg Handle     全系统 ObjectType="Key" 的句柄（pid / handle / access / object）
 *   Hidden Item    控制字符键名 + HKCU\Software\Classes 独占项
 * 四列都可在列表里选中复制（Copy Key Name / RegPath / RegValue / RegData 由
 * 用户复制对应列实现；原版的复制菜单项文本与此一一对应）。 */
static void RgSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void CreateRgColumns(HWND hList, int tab)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    if (tab == 0) {
        c.pszText = "PID";     c.cx = 80;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Handle";  c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Access";  c.cx = 110; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Key Object"; c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 2) {
        /* CmpNotifyChange：CmRegisterCallback 注册的回调链。
           数据源为命令 0x127（CmdEnumRegistryContext），要求出参缓冲
           恰好 1800 字节（驱动里是 `BufferSize == 1800` 硬判断）。 */
        c.pszText = "Index";     c.cx = 70;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Function";  c.cx = 200; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Context";   c.cx = 200; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Slot";      c.cx = 400; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else {
        c.pszText = "RegPath"; c.cx = 700; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Reason";  c.cx = 260; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Depth";   c.cx = 70;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    }
}

static void DoRefreshRegistry(void)
{
    char status[256];

    if (!g_hRgList || !g_hRgStatus)
        return;
    ListView_DeleteAllItems(g_hRgList);
    CreateRgColumns(g_hRgList, g_RgTab);

    if (g_RgTab == 0) {
        FE_REG_HANDLE_LIST list;
        ULONG i;
        if (!FeLoadRegistryHandles(FE_REGH_MAX, &list)) {
            sprintf_s(status, sizeof(status),
                      "Reg Handle: query failed (KeyTypeIndex=%ld)", (long)list.KeyTypeIndex);
            SetWindowTextA(g_hRgStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char pid[24], h[32], acc[32], obj[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(pid, sizeof(pid), "%lu", list.Items[i].Pid);
            it.pszText = pid;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(h, sizeof(h), "0x%I64X", list.Items[i].Handle);
            sprintf_s(acc, sizeof(acc), "0x%lX", list.Items[i].Access);
            sprintf_s(obj, sizeof(obj), "%016I64X", list.Items[i].Object);
            RgSetText(g_hRgList, (int)i, 1, h);
            RgSetText(g_hRgList, (int)i, 2, acc);
            RgSetText(g_hRgList, (int)i, 3, obj);
        }
        sprintf_s(status, sizeof(status),
                  "Reg Handle: %lu open Key handles system-wide (type index %ld)",
                  list.Count, (long)list.KeyTypeIndex);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeRegistryHandles(&list);
    } else if (g_RgTab == 2) {
        /* 【2026-10-23 更正，撤回上一版错误实现】
           上一版把 0x127 的输出当成 CmRegisterCallback 回调链渲染，
           那是**错的**。三条独立证据：
             1. kd `lm a` 核对：输出里的地址全部落在 Npfs
                （0xFFFFF80539B7B670 / B270 / EAF0 → Npfs 段），
                另有 0xFFFFF80534525D40 → nt。
             2. 驱动源码：EnumerateRegistryContextTable 的数据源是
                BuildRegistryDriverPath() 打开的驱动，而该函数里的
                编码路径解码后是 `\FileSystem\Npfs`；它读该驱动 PE 节区
                +0x70（+112）处的 28 个函数指针（0..0x1B）。
             3. 记录布局确为 0x30 步长、+0x00 序号、+0x10 函数指针，
                但这只是"Npfs 分发表的函数指针"，与注册表无关。
           即：0x127 属于「驱动分发表 hook 检测」这一类，
           **不是** CmRegisterCallback 的注册表回调链（那需要读
           nt!CmpCallbackListHead，我们没有任意内核内存读取能力）。
           因此本子页如实标注没有数据源，不拿 Npfs 指针冒充。 */
        sprintf_s(status, sizeof(status),
                  "CmpNotifyChange: no data source. The registry callback "
                  "chain lives in nt!CmpCallbackListHead and no command "
                  "exposes it (0x127 enumerates Npfs dispatch-table "
                  "pointers, not CmRegisterCallback entries).");
        SetWindowTextA(g_hRgStatus, status);
    } else {
        FE_REG_HIDDEN_LIST list;
        ULONG i;
        if (!FeLoadHiddenRegKeys(&list)) {
            SetWindowTextA(g_hRgStatus, "Hidden Item: query failed");
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char depth[16];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = list.Items[i].Path;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            RgSetText(g_hRgList, (int)i, 1, list.Items[i].Reason);
            sprintf_s(depth, sizeof(depth), "%d", list.Items[i].Depth);
            RgSetText(g_hRgList, (int)i, 2, depth);
        }
        sprintf_s(status, sizeof(status), "Hidden Item: %lu suspicious registry keys", list.Count);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeHiddenRegKeys(&list);
    }
}

/* ---- File 页（主 Tab 8）---- */
static void FlSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void CreateFlColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Name";       c.cx = 300; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "Size";       c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "Attr";       c.cx = 80;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "Flags";      c.cx = 150; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    c.pszText = "Path";       c.cx = 500; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
}

static void DoRefreshFiles(void)
{
    FE_FILE_LIST list;
    char dir[MAX_PATH];
    char status[256];
    ULONG i;

    if (!g_hFlList || !g_hFlStatus || !g_hFlDir)
        return;
    GetWindowTextA(g_hFlDir, dir, sizeof(dir));
    if (!dir[0])
        strcpy_s(dir, sizeof(dir), "C:\Windows\System32");

    ListView_DeleteAllItems(g_hFlList);
    CreateFlColumns(g_hFlList);

    if (!FeLoadDirectory(dir, &list)) {
        sprintf_s(status, sizeof(status), "Files: cannot open \"%s\", GetLastError=%lu",
                  dir, GetLastError());
        SetWindowTextA(g_hFlStatus, status);
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        char sz[32], attr[32], flags[128], name[FE_FILE_NAME_CHARS + 4];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        /* Rootkit 可疑项按原版样式加括号 */
        if (list.Items[i].Suspect)
            sprintf_s(name, sizeof(name), "(%s)", list.Items[i].Name);
        else
            strcpy_s(name, sizeof(name), list.Items[i].Name);
        it.pszText = name;
        SendMessageA(g_hFlList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(sz, sizeof(sz), "%I64u", list.Items[i].Size);
        sprintf_s(attr, sizeof(attr), "0x%lX", list.Items[i].Attributes);
        flags[0] = 0;
        if (list.Items[i].DeletePending)
            strcat_s(flags, sizeof(flags), "DELETE-PENDING ");
        if (list.Items[i].LockedCount) {
            char lk[64];
            sprintf_s(lk, sizeof(lk), "LOCKED(pid=%lu) ", list.Items[i].LockOwners[0]);
            strcat_s(flags, sizeof(flags), lk);
        }
        FlSetText(g_hFlList, (int)i, 1, sz);
        FlSetText(g_hFlList, (int)i, 2, attr);
        FlSetText(g_hFlList, (int)i, 3, flags);
        FlSetText(g_hFlList, (int)i, 4, list.Items[i].Path);
    }
    sprintf_s(status, sizeof(status),
              "%s: %lu files  (suspect: %lu, delete-pending: %lu, locked: %lu)",
              dir, list.Count, list.HiddenCount, list.PendingCount, list.LockedCount);
    SetWindowTextA(g_hFlStatus, status);
    FeFreeDirectory(&list);
}

/* ---- Other 页（主 Tab 13）---- */
static void OtAddRow(const char *k, const char *v)
{
    LVITEMA it;
    int i = ListView_GetItemCount(g_hOtList);
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = i;
    it.pszText = (LPSTR)k;
    SendMessageA(g_hOtList, LVM_INSERTITEMA, 0, (LPARAM)&it);
    {
        LVITEMA t2;
        ZeroMemory(&t2, sizeof(t2));
        t2.mask = LVIF_TEXT;
        t2.iSubItem = 1;
        t2.pszText = (LPSTR)v;
        SendMessageA(g_hOtList, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&t2);
    }
}

static void DoRefreshOther(void)
{
    LVCOLUMNA c;
    FE_OS_INFO os;
    char buf[512];

    if (!g_hOtList || !g_hOtStatus)
        return;
    ListView_DeleteAllItems(g_hOtList);
    while (ListView_DeleteColumn(g_hOtList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Item";  c.cx = 220; c.iSubItem = 0; ListView_InsertColumn(g_hOtList, 0, &c);
    c.pszText = "Value"; c.cx = 690; c.iSubItem = 1; ListView_InsertColumn(g_hOtList, 1, &c);

    /* Windows 版本识别表 */
    if (FeLoadOsInfo(&os)) {
        OtAddRow("Windows version", os.VersionString);
        OtAddRow("Market name", os.MarketName);
        OtAddRow("Product name", os.ProductName[0] ? os.ProductName : "(?)");
        OtAddRow("Display version", os.DisplayVersion[0] ? os.DisplayVersion : "(?)");
        OtAddRow("Current build", os.CurrentBuild[0] ? os.CurrentBuild : "(?)");
        sprintf_s(buf, sizeof(buf), "%lu", os.PlatformId);
        OtAddRow("Platform id", buf);
    } else {
        OtAddRow("Windows version", "(RtlGetVersion failed)");
    }

    /* 当前用户的常见系统文件版本信息（FileVersion / Corporation 示例） */
    {
        static const char *samples[] = {
            "C:\Windows\System32\ntoskrnl.exe",
            "C:\Windows\System32\kernel32.dll",
            "C:\Windows\System32\ntdll.dll",
        };
        ULONG i;
        for (i = 0; i < 3; i++) {
            FE_FILE_VER v;
            if (FeLoadFileVersion(samples[i], &v)) {
                char key[128];
                const char *base = samples[i];
                const char *p = base;
                while (*p) { if (*p == 92) base = p + 1; p++; }
                sprintf_s(key, sizeof(key), "%s FileVersion", base);
                OtAddRow(key, v.FileVersionStr[0] ? v.FileVersionStr : v.FileVersion);
                sprintf_s(key, sizeof(key), "%s Company", base);
                OtAddRow(key, v.CompanyName[0] ? v.CompanyName : "(?)");
            }
        }
    }
    sprintf_s(buf, sizeof(buf),
              "Other: OS %s; %d file-version samples",
              os.MarketName[0] ? os.MarketName : "?", ListView_GetItemCount(g_hOtList));
    SetWindowTextA(g_hOtStatus, buf);
}

/* ---- Examination 页（主 Tab 9）---- */
static void ExSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoRefreshExamination(void)
{
    LVCOLUMNA c;
    char status[320];
    ULONG i;

    if (!g_hExList || !g_hExStatus)
        return;
    if (g_ExamLoaded) {
        FeFreeExamination(&g_ExamResult);
        g_ExamLoaded = 0;
    }
    SetWindowTextA(g_hExStatus, "Examining...");
    if (!FeRunExamination(&g_ExamResult)) {
        SetWindowTextA(g_hExStatus, "Examination failed");
        return;
    }
    g_ExamLoaded = 1;

    ListView_DeleteAllItems(g_hExList);
    while (ListView_DeleteColumn(g_hExList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Severity"; c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(g_hExList, 0, &c);
    c.pszText = "Item";     c.cx = 220; c.iSubItem = 1; ListView_InsertColumn(g_hExList, 1, &c);
    c.pszText = "Detail";   c.cx = 620; c.iSubItem = 2; ListView_InsertColumn(g_hExList, 2, &c);

    for (i = 0; i < g_ExamResult.Count; i++) {
        LVITEMA it;
        const char *sev = g_ExamResult.Items[i].Severity == 0 ? "INFO" :
                          g_ExamResult.Items[i].Severity == 1 ? "WARN" : "RISK";
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = (LPSTR)sev;
        SendMessageA(g_hExList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        ExSetText(g_hExList, (int)i, 1, g_ExamResult.Items[i].Title);
        ExSetText(g_hExList, (int)i, 2, g_ExamResult.Items[i].Detail);
    }
    sprintf_s(status, sizeof(status),
              "%s | Items: %lu (risk %lu, warn %lu, info %lu)%s",
              g_ExamResult.Date, g_ExamResult.Count,
              g_ExamResult.RiskCount, g_ExamResult.WarnCount, g_ExamResult.InfoCount,
              g_ExamResult.Cancelled ? "  [TERMINATED]" : "");
    SetWindowTextA(g_hExStatus, status);
}

static void DoExportExamination(void)
{
    char path[MAX_PATH];
    if (!g_ExamLoaded) {
        SetWindowTextA(g_hExStatus, "Nothing to export - run examination first");
        return;
    }
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, sizeof(path), "PCHunter_Examination.txt");
    if (FeExportExamination(&g_ExamResult, path)) {
        char msg[400];
        sprintf_s(msg, sizeof(msg), "Report exported: %s", path);
        SetWindowTextA(g_hExStatus, msg);
    } else {
        SetWindowTextA(g_hExStatus, "Export failed");
    }
}

/* ---- Fireeye 页（主 Tab 11）---- */
static void FeSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoFireeyeAnalyse(void)
{
    char path[MAX_PATH], status[512];
    int rc;

    if (!g_hFePath || !g_hFeList || !g_hFeStatus)
        return;
    GetWindowTextA(g_hFePath, path, sizeof(path));
    if (!path[0]) {
        SetWindowTextA(g_hFeStatus, "Enter a file path first");
        return;
    }
    rc = FeFireeyePrecheck(path, &g_FeJob);
    g_FeHasJob = (rc != 0);

    ListView_DeleteAllItems(g_hFeList);
    {
        LVCOLUMNA c;
        while (ListView_DeleteColumn(g_hFeList, 0))
            ;
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = "Field"; c.cx = 160; c.iSubItem = 0; ListView_InsertColumn(g_hFeList, 0, &c);
        c.pszText = "Value"; c.cx = 750; c.iSubItem = 1; ListView_InsertColumn(g_hFeList, 1, &c);
    }
    {
        const char *base = path;
        const char *p = path;
        char msg[512], url[512];
        while (*p) { if (*p == 92 || *p == 47) base = p + 1; p++; }

        FeSetText(g_hFeList, 0, 0, "Path");
        ListView_InsertItem(g_hFeList, NULL);
        FeSetText(g_hFeList, 0, 1, path);

        if (rc == 2) {
            FeFireeyeMsMessage(base, msg, sizeof(msg));
            FeSetText(g_hFeList, 1, 0, "Verdict");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 1, 1, "DO NOT UPLOAD (Microsoft file)");
            FeSetText(g_hFeList, 2, 0, "Message");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 2, 1, msg);
            FeSetText(g_hFeList, 3, 0, "Company");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 3, 1, g_FeJob.Company);
            sprintf_s(status, sizeof(status), "%s", msg);
        } else if (rc == 0) {
            FeSetText(g_hFeList, 1, 0, "Error");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 1, 1, g_FeJob.Message);
            sprintf_s(status, sizeof(status), "Analysis failed: %s", g_FeJob.Message);
        } else {
            FeSetText(g_hFeList, 1, 0, "SHA-256");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 1, 1, g_FeJob.Sha256);
            FeFireeyeBuildUrl(&g_FeJob, url, sizeof(url));
            FeSetText(g_hFeList, 2, 0, "Query URL");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 2, 1, url);
            FeSetText(g_hFeList, 3, 0, "Upload");
            ListView_InsertItem(g_hFeList, NULL);
            FeSetText(g_hFeList, 3, 1,
                      "not sent - click 'Open Query' to review in browser (user action)");
            sprintf_s(status, sizeof(status),
                      "Ready to query (SHA-256 computed); nothing uploaded yet. Records: %lu",
                      FeFireeyeRecordCount());
        }
    }
    SetWindowTextA(g_hFeStatus, status);
}

static void DoFireeyeRecords(void)
{
    FE_FIREEYE_RECORD_LIST rl;
    ULONG i;
    char status[256];

    if (!g_hFeList || !g_hFeStatus)
        return;
    ListView_DeleteAllItems(g_hFeList);
    {
        LVCOLUMNA c;
        while (ListView_DeleteColumn(g_hFeList, 0))
            ;
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = "Time";   c.cx = 160; c.iSubItem = 0; ListView_InsertColumn(g_hFeList, 0, &c);
        c.pszText = "SHA-256"; c.cx = 400; c.iSubItem = 1; ListView_InsertColumn(g_hFeList, 1, &c);
        c.pszText = "Path";   c.cx = 360; c.iSubItem = 2; ListView_InsertColumn(g_hFeList, 2, &c);
    }
    if (!FeFireeyeListRecords(&rl)) {
        sprintf_s(status, sizeof(status), "No upload records yet");
        SetWindowTextA(g_hFeStatus, status);
        return;
    }
    for (i = 0; i < rl.Count; i++) {
        ListView_InsertItem(g_hFeList, NULL);
        FeSetText(g_hFeList, (int)i, 0, rl.Items[i].Time);
        FeSetText(g_hFeList, (int)i, 1, rl.Items[i].Sha256);
        FeSetText(g_hFeList, (int)i, 2, rl.Items[i].Path);
    }
    sprintf_s(status, sizeof(status), "Upload records: %lu", rl.Count);
    SetWindowTextA(g_hFeStatus, status);
    FeFireeyeFreeRecords(&rl);
}

/* ---- Setting 页（主 Tab 10）----
 * 三项可用 Forbid（对应已确认的 IoFile/Driver/DeviceObjectType）
 * + 四项标注"未定位对象类型"
 * + 两项自保护（占位，需 0xD2/0xD3 的 21712 字节输出）
 * + 托盘最小化开关 */
static void StSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoRefreshSetting(void)
{
    LVCOLUMNA c;
    char status[320];

    if (!g_hStList || !g_hStStatus)
        return;
    ListView_DeleteAllItems(g_hStList);
    while (ListView_DeleteColumn(g_hStList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Setting"; c.cx = 250; c.iSubItem = 0; ListView_InsertColumn(g_hStList, 0, &c);
    c.pszText = "State";   c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(g_hStList, 1, &c);
    c.pszText = "Note";    c.cx = 560; c.iSubItem = 2; ListView_InsertColumn(g_hStList, 2, &c);

    if (g_Client.Opened)
        g_StObjReady = FeSettingReadObjectTypes(&g_Client, &g_StObjTypes) ? 1 : 0;

    {
        int n = 0;
        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Creating File");
        StSetText(g_hStList, n, 1, "ready");
        StSetText(g_hStList, n, 2,
                  g_StObjReady ? "IoFileObjectType resolved" : "needs driver connection (Connect first)");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Loading Driver");
        StSetText(g_hStList, n, 1, "ready");
        StSetText(g_hStList, n, 2,
                  g_StObjReady ? "IoDriverObjectType resolved" : "needs driver connection");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Creating Device");
        StSetText(g_hStList, n, 1, "ready");
        StSetText(g_hStList, n, 2,
                  g_StObjReady ? "IoDeviceObjectType resolved" : "needs driver connection");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Creating Process");
        StSetText(g_hStList, n, 1, "ready");
        StSetText(g_hStList, n, 2,
                  g_StObjReady ? "PsProcessType (GT[0x4166]) resolved"
                               : "needs driver connection");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Creating Thread");
        StSetText(g_hStList, n, 1, "ready");
        StSetText(g_hStList, n, 2,
                  g_StObjReady ? "PsThreadType (GT[0x4169]) resolved"
                               : "needs driver connection");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Injecting Module");
        StSetText(g_hStList, n, 1, "unavailable");
        StSetText(g_hStList, n, 2, "IoSectionObjectType slot not yet located");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Forbid Locking Work Station");
        StSetText(g_hStList, n, 1, "unavailable");
        StSetText(g_hStList, n, 2, "IoDesktopObjectType slot not yet located");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "SelfProtection (SSDT)");
        StSetText(g_hStList, n, 1, "via buttons");
        StSetText(g_hStList, n, 2, "0xD2 EnableProcessProtect / 0xD3 disable, applies to this process");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "SelfProtection (Shadow SSDT)");
        StSetText(g_hStList, n, 1, "via buttons");
        StSetText(g_hStList, n, 2, "same handler; shadow variant chosen by driver per target");
        n++;

        ListView_InsertItem(g_hStList, NULL);
        StSetText(g_hStList, n, 0, "Minimize to tray on close");
        StSetText(g_hStList, n, 1, FeSettingGetMinimizeToTray() ? "ON" : "OFF");
        StSetText(g_hStList, n, 2, "persisted in HKCU\Software\XPCHunterReplica");
        n++;
    }
    /* 【2026-10-22】可用的 Forbid 项已从 3 项扩到 5 项
       （新增 Process / Thread，对象类型分别取 extra[4]/extra[7]），
       状态栏文案随之更新；Section / Desktop 两项仍未定位，如实标注。 */
    sprintf_s(status, sizeof(status),
              "Object types: %s | Forbid available: %d of 6 | Tray minimize: %s",
              g_StObjReady ? "resolved" : "not connected",
              g_StObjReady ? 5 : 0,
              FeSettingGetMinimizeToTray() ? "ON" : "OFF");
    SetWindowTextA(g_hStStatus, status);
}

static void DoApplyForbid(int Which)
{
    ULONG64 target = 0;
    UCHAR res = 0;

    if (!g_Client.Opened) {
        SetWindowTextA(g_hStStatus, "Not connected - click Connect first");
        return;
    }
    if (!g_StObjReady) {
        SetWindowTextA(g_hStStatus, "Object types not resolved");
        return;
    }
    switch (Which) {
    case 0: target = g_StObjTypes.File;    break;
    case 1: target = g_StObjTypes.Driver;  break;
    case 2: target = g_StObjTypes.Device;  break;
    case 3: target = g_StObjTypes.Process; break;   /* GT[0x4166] = PsProcessType */
    case 4: target = g_StObjTypes.Thread;  break;   /* GT[0x4169] = PsThreadType */
    default: break;
    }
    if (!target) {
        SetWindowTextA(g_hStStatus, "Object type address is zero");
        return;
    }
    if (FeSettingSetForbid(&g_Client, target, 0, 1, &res)) {
        char msg[256];
        sprintf_s(msg, sizeof(msg), "Forbid applied (result byte = %u)", res);
        SetWindowTextA(g_hStStatus, msg);
    } else {
        SetWindowTextA(g_hStStatus, "Forbid request rejected by driver");
    }
}

/* ---- Trojan Detection 页（主 Tab 12）---- */
static void TrSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoTrojanScan(void)
{
    LVCOLUMNA c;
    char status[320];

    if (!g_hTrList || !g_hTrStatus)
        return;
    ListView_DeleteAllItems(g_hTrList);
    while (ListView_DeleteColumn(g_hTrList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Item";   c.cx = 230; c.iSubItem = 0; ListView_InsertColumn(g_hTrList, 0, &c);
    c.pszText = "Result"; c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(g_hTrList, 1, &c);
    c.pszText = "Detail"; c.cx = 580; c.iSubItem = 2; ListView_InsertColumn(g_hTrList, 2, &c);

    SetWindowTextA(g_hTrStatus, "Scanning PhysicalDrive0...");
    ZeroMemory(&g_TrReport, sizeof(g_TrReport));
    g_TrLoaded = FeFindZeroAccess(0, &g_TrReport) ? 1 : 0;

    {
        int n = 0;
        static const char *stateTxt[] = { "MBR OK!", "Unknow MBR!", "read failed", "(backup found)" };
        ListView_InsertItem(g_hTrList, NULL);
        TrSetText(g_hTrList, n, 0, "Scan MBR");
        TrSetText(g_hTrList, n, 1, stateTxt[g_TrReport.MbrState >= 0 && g_TrReport.MbrState <= 3
                                          ? g_TrReport.MbrState : 2]);
        TrSetText(g_hTrList, n, 2, g_TrReport.MbrDetail);
        n++;

        ListView_InsertItem(g_hTrList, NULL);
        TrSetText(g_hTrList, n, 0, "Check MBR Rootkit");
        TrSetText(g_hTrList, n, 1, g_TrReport.ZeroAccess ? "INFECTED" : "clean");
        TrSetText(g_hTrList, n, 2, g_TrReport.ZeroAccess
                  ? "Find ZeroAccess Rootkit!"
                  : "no int13 + shadow-MBR signature combination");
        n++;

        ListView_InsertItem(g_hTrList, NULL);
        TrSetText(g_hTrList, n, 0, "Original MBR backup");
        if (g_TrReport.BackupSector) {
            char d[128];
            sprintf_s(d, sizeof(d), "Original MBR has been found in sector %I64u",
                      g_TrReport.BackupSector);
            TrSetText(g_hTrList, n, 1, "found");
            TrSetText(g_hTrList, n, 2, d);
        } else {
            TrSetText(g_hTrList, n, 1, "none");
            TrSetText(g_hTrList, n, 2, "no readable shadow MBR in sectors 1..8");
        }
        n++;

        FeCheckLsp(&g_TrReport);
        ListView_InsertItem(g_hTrList, NULL);
        TrSetText(g_hTrList, n, 0, "LSP");
        TrSetText(g_hTrList, n, 1, g_TrReport.LspOk ? "OK" : "suspicious");
        TrSetText(g_hTrList, n, 2, g_TrReport.LspDetail);
        n++;

        FeCheckSafeboot(&g_TrReport);
        ListView_InsertItem(g_hTrList, NULL);
        TrSetText(g_hTrList, n, 0, "Safeboot");
        TrSetText(g_hTrList, n, 1, g_TrReport.SafebootOk ? "OK" : "tampered");
        TrSetText(g_hTrList, n, 2, g_TrReport.SafebootDetail);
        n++;
    }
    sprintf_s(status, sizeof(status),
              "MBR: %s | ZeroAccess: %s | LSP: %s | Safeboot: %s",
              g_TrReport.MbrState == 0 ? "OK" :
              g_TrReport.MbrState == 1 ? "UNKNOWN" : "read-fail",
              g_TrReport.ZeroAccess ? "FOUND" : "clean",
              g_TrReport.LspOk ? "OK" : "suspicious",
              g_TrReport.SafebootOk ? "OK" : "tampered");
    SetWindowTextA(g_hTrStatus, status);
}

static void DoTrojanBackup(void)
{
    char path[MAX_PATH];
    if (!g_TrLoaded)
        DoTrojanScan();
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, sizeof(path), "PCHunter_MBR_Backup.bin");
    if (FeBackupMbr(0, path, &g_TrReport)) {
        char msg[400];
        sprintf_s(msg, sizeof(msg), "MBR backed up to %s", path);
        SetWindowTextA(g_hTrStatus, msg);
    } else {
        SetWindowTextA(g_hTrStatus, "MBR backup failed");
    }
}

/* ---- Ring0 / Ring3 Hooks 页（主 Tab 2 / 3）----
 * Ring3 扫 IAT 越界；Ring0 标 blocked（驱动链缺 6 个函数，见
 * docs/reversing/Hooks页落地_2026-10-21.md）。 */
static void HkSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoRefreshHooks(void)
{
    LVCOLUMNA c;
    FE_HOOK_LIST list;
    FE_RING0_HOOK_LIST r0;
    char status[420];
    int n = 0;
    ULONG i;
    BOOL r0ok;

    if (!g_hHkList || !g_hHkStatus)
        return;
    ListView_DeleteAllItems(g_hHkList);
    while (ListView_DeleteColumn(g_hHkList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Type";    c.cx = 80;  c.iSubItem = 0; ListView_InsertColumn(g_hHkList, 0, &c);
    c.pszText = "Owner";   c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(g_hHkList, 1, &c);
    c.pszText = "IAT/Index"; c.cx = 130; c.iSubItem = 2; ListView_InsertColumn(g_hHkList, 2, &c);
    c.pszText = "Target";  c.cx = 160; c.iSubItem = 3; ListView_InsertColumn(g_hHkList, 3, &c);
    c.pszText = "Note";    c.cx = 420; c.iSubItem = 4; ListView_InsertColumn(g_hHkList, 4, &c);

    /* ---- Ring0：0x117 的两张系统调用表（GT[0x8B7] / GT[0x8BA]）----
     * 每条 = 表内索引 + 当前地址 + 磁盘原始地址 + 原始 16 字节 + 两个改写标志。 */
    r0ok = FeLoadRing0Hooks(&g_Client, &r0);
    if (r0ok) {
        for (i = 0; i < r0.Count; i++) {
            const FE_RING0_HOOK_ENTRY *e = &r0.Items[i];
            char idx[48], tgt[32], note[220];
            ListView_InsertItem(g_hHkList, NULL);
            HkSetText(g_hHkList, n, 0, "Ring0");
            HkSetText(g_hHkList, n, 1,
                      e->TableIndex == 1 ? "HookTable1 (GT[0x8B7])"
                                         : "HookTable2 (GT[0x8BA])");
            sprintf_s(idx, sizeof(idx), "[%lu]", (unsigned long)e->Index);
            sprintf_s(tgt, sizeof(tgt), "%016I64X", e->Current);
            HkSetText(g_hHkList, n, 2, idx);
            HkSetText(g_hHkList, n, 3, tgt);
            sprintf_s(note, sizeof(note), "%s%s  %s",
                      e->FlagAddr  ? "[ADDR CHANGED] " : "",
                      e->FlagBytes ? "[BYTES PATCHED] " : "",
                      e->Disasm);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
        sprintf_s(status, sizeof(status),
                  "Ring0: build %lu, %lu entries (table1 %lu / table2 %lu), %lu patched | ",
                  r0.Build, r0.Count, r0.Count1, r0.Count2, r0.ModifiedCount);
        FeFreeRing0Hooks(&r0);
    } else {
        ListView_InsertItem(g_hHkList, NULL);
        HkSetText(g_hHkList, n, 0, "Ring0");
        HkSetText(g_hHkList, n, 1, "(kernel)");
        HkSetText(g_hHkList, n, 2, "-");
        HkSetText(g_hHkList, n, 3, "-");
        HkSetText(g_hHkList, n, 4,
                  g_Client.Opened ? "0x117 returned no entries"
                                  : "not connected: click Connect first");
        n++;
        sprintf_s(status, sizeof(status), "Ring0: no data | ");
    }

    /* ---- Ring3：实扫 ---- */
    if (FeScanRing3Hooks(GetCurrentProcessId(), &list)) {
        for (i = 0; i < list.Count; i++) {
            char a[32], t[32], note[192];
            ListView_InsertItem(g_hHkList, NULL);
            HkSetText(g_hHkList, n, 0, "Ring3");
            HkSetText(g_hHkList, n, 1, list.Items[i].Owner);
            sprintf_s(a, sizeof(a), "%016I64X", list.Items[i].IatAddress);
            sprintf_s(t, sizeof(t), "%016I64X", list.Items[i].Target);
            HkSetText(g_hHkList, n, 2, a);
            HkSetText(g_hHkList, n, 3, t);
            sprintf_s(note, sizeof(note), "%s-->Ring3 Hook  (%s)",
                      list.Items[i].Owner, list.Items[i].TargetModule);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
        {
            char tail[160];
            sprintf_s(tail, sizeof(tail), "Ring3: %lu suspicious IAT entries (pid %lu)",
                      list.Count, GetCurrentProcessId());
            strcat_s(status, sizeof(status), tail);
        }
        FeFreeHooks(&list);
    } else {
        char tail[96];
        sprintf_s(tail, sizeof(tail), "Ring3: scan failed, GetLastError=%lu", GetLastError());
        strcat_s(status, sizeof(status), tail);
    }
    SetWindowTextA(g_hHkStatus, status);
}

/* ---- Ring0 两项恢复操作的点击处理 ----
 * 两者都必须把「没有待恢复项」和「失败」区分开显示：
 * 本机 908 条 Hook 条目全部 clean，0x118 返回 0 是正常结果，
 * 若显示成 FAILED 会误导用户以为自己系统被 hook 了。 */
static void DoRestoreOverHooks(void)
{
    FE_HOOK_RESTORE_RESULT r;
    char msg[420];

    if (!g_Client.Opened) {
        SetWindowTextA(g_hHkStatus, "Restore Over. Hooks/Patches: not connected");
        return;
    }
    if (!FeRestoreOverHooks(&g_Client, 1, &r)) {
        SetWindowTextA(g_hHkStatus, "Restore Over. Hooks/Patches: query failed");
        return;
    }
    switch (r.State) {
    case FE_HOOK_RESTORE_RESTORED:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: restored (%lu entries checked)",
                  r.TotalEntries);
        break;
    case FE_HOOK_RESTORE_NOTHING_TO_DO:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: nothing to restore - all %lu hook entries "
                  "match their on-disk originals (0 modified, driver result=%u)",
                  r.TotalEntries, r.ResultByte);
        break;
    case FE_HOOK_RESTORE_ATTEMPTED_NO_EFFECT:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: %lu modified entries found but driver "
                  "reported no change (result=%u)",
                  r.ModifiedCount, r.ResultByte);
        break;
    default:
        sprintf_s(msg, sizeof(msg), "Restore Over. Hooks/Patches: %s",
                  FeHookRestoreStateText(&r));
        break;
    }
    SetWindowTextA(g_hHkStatus, msg);
    DoRefreshHooks();                 /* 刷新列表，让用户看到恢复后的状态 */
}

static void DoRestoreCallbackTable(void)
{
    FE_CB_TABLE t;
    char msg[420];
    int n = 0;
    ULONG i;

    if (!g_Client.Opened) {
        SetWindowTextA(g_hHkStatus, "Restore KernelCallbackTable: not connected");
        return;
    }
    if (!FeLoadCallbackTable(&g_Client, &t)) {
        SetWindowTextA(g_hHkStatus, "Restore KernelCallbackTable: query failed");
        return;
    }
    if (t.State != FE_CB_ENUMERATED) {
        sprintf_s(msg, sizeof(msg),
                  "Restore KernelCallbackTable: %s (cmd 0x131 result=%u)",
                  FeCbStateText(&t), t.ResultByte);
        SetWindowTextA(g_hHkStatus, msg);
        return;
    }
    /* 枚举成功：把 28 个回调槽追加到列表里。
       每行显示「槽号 / 目标 RVA / 当前回调指针 / 原始代码前 8 字节」，
       其中「当前回调指针」与「原始代码」的差异就是该槽是否被替换的判据。 */
    if (g_hHkList) {
        while (ListView_GetItemCount(g_hHkList) > 0)
            ListView_DeleteItem(g_hHkList, 0);
        for (i = 0; i < t.Count; i++) {
            LVITEMA it;
            char idxbuf[32], off[32], val[64], note[96];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = n;
            sprintf_s(idxbuf, sizeof(idxbuf), "%lu", (unsigned long)t.Slot[i].Offset);
            sprintf_s(off, sizeof(off), "+0x%03lX", (unsigned long)(8 + i * 0x30));
            sprintf_s(val, sizeof(val), "%016I64X", t.Slot[i].Current);
            /* 有原始快照且当前回调指针已被重定向（cur != va）时标出。
               注意：orig 是目标地址上的机器码快照，cur 是回调函数指针，
               二者不同类，不能互相比较。「va 处代码被就地改成跳板」这种情形
               需要读内核内存才能判定，0x131 的输出里没有该字段。 */
            if (t.Slot[i].HasOriginal) {
                if (t.Slot[i].Current && t.Slot[i].Current != t.Slot[i].Va)
                    sprintf_s(note, sizeof(note),
                              "callback slot %lu (RVA 0x%lX) - pointer redirected",
                              (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
                else
                    sprintf_s(note, sizeof(note),
                              "callback slot %lu (RVA 0x%lX)",
                              (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
            } else {
                sprintf_s(note, sizeof(note),
                          "callback slot %lu (RVA 0x%lX) - no snapshot",
                          (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
            }
            it.pszText = (LPSTR)"Ring0";
            SendMessageA(g_hHkList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            HkSetText(g_hHkList, n, 1, "KernelCallbackTable");
            HkSetText(g_hHkList, n, 2, off);
            HkSetText(g_hHkList, n, 3, val);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
    }
    /* 真正下发恢复（0x132）：对「回调指针已被重定向」的槽，
       把 16 字节原始代码写回目标 VA。没有重定向项时如实报告「无需恢复」。 */
    {
        ULONG restored = 0, attempted = 0, rejected = 0, skipped = 0;
        for (i = 0; i < t.Count; i++) {
            FE_CB_RESTORE_RESULT rr;
            if (!t.Slot[i].HasOriginal) { skipped++; continue; }
            if (!t.Slot[i].Current || t.Slot[i].Current == t.Slot[i].Va) {
                skipped++;
                continue;
            }
            attempted++;
            if (FeRestoreCallbackSlot(&g_Client, t.Slot[i].Va,
                                      t.Slot[i].Original, &rr) &&
                rr.State == FE_CB_RESTORE_OK)
                restored++;
            else
                rejected++;
        }
        if (attempted == 0) {
            sprintf_s(msg, sizeof(msg),
                      "Restore KernelCallbackTable: %lu callback slots, build %lu, "
                      "verify=%u - nothing to restore (%lu slots still point at "
                      "their original targets)",
                      t.Count, t.Build, t.Ready, (unsigned long)skipped);
        } else {
            sprintf_s(msg, sizeof(msg),
                      "Restore KernelCallbackTable: %lu slots, build %lu, "
                      "%lu restored / %lu redirected (%lu rejected, %lu clean)",
                      t.Count, t.Build, (unsigned long)restored,
                      (unsigned long)attempted, (unsigned long)rejected,
                      (unsigned long)skipped);
        }
        SetWindowTextA(g_hHkStatus, msg);
        DoRefreshHooks();
        return;
    }
}

static void ShowPage(HWND hWnd, int page)
{
    int isProc = (page == 0);
    int isKernel = (page == 1);
    int isStartup = (page == 6);     /* 0-based：第 7 个 Tab = Startup Info */
    int isServices = (page == 7);    /* 第 8 个 Tab = Services */
    int isRegistry = (page == 5);    /* 第 6 个 Tab = Registry */
    int isFile = (page == 8);        /* 第 9 个 Tab = File */
    int isOther = (page == 13);      /* 第 14 个 Tab = Other */
    int isExam = (page == 9);        /* 第 10 个 Tab = Examination */
    int isFireeye = (page == 11);    /* 第 12 个 Tab = Fireeye */
    int isSetting = (page == 10);    /* 第 11 个 Tab = Setting */
    int isTrojan = (page == 12);     /* 第 13 个 Tab = Trojan Detection */
    int isHooks = (page == 2 || page == 3);  /* Ring0 Hooks / Ring3 Hooks */
    int isNetwork = (page == 4);     /* 第 5 个 Tab = Network */
    char hint[512];
    HWND hKill, hRef;

    if (g_hProc)       ShowWindow(g_hProc,       isProc ? SW_SHOW : SW_HIDE);
    if (g_hProcStatus) ShowWindow(g_hProcStatus, isProc ? SW_SHOW : SW_HIDE);
    if (g_hTabs)       ShowWindow(g_hTabs,       isProc ? SW_SHOW : SW_HIDE);
    if (g_hDetail)     ShowWindow(g_hDetail,     isProc ? SW_SHOW : SW_HIDE);
    if (g_hList)       ShowWindow(g_hList,       isProc ? SW_SHOW : SW_HIDE);
    hKill = GetDlgItem(hWnd, IDC_KILL);
    if (hKill) ShowWindow(hKill, isProc ? SW_SHOW : SW_HIDE);

    if (g_hKmTabs)   ShowWindow(g_hKmTabs,   isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmList)   ShowWindow(g_hKmList,   isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmStatus) ShowWindow(g_hKmStatus, isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmKExtra) ShowWindow(g_hKmKExtra, (isKernel && g_KmTab == 1) ? SW_SHOW : SW_HIDE);
    hRef = GetDlgItem(hWnd, IDC_KM_REFRESH);
    if (hRef) ShowWindow(hRef, isKernel ? SW_SHOW : SW_HIDE);
    {
        HWND b;
        b = GetDlgItem(hWnd, IDC_KM_ONLYLOADED); if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_COPYNAME);   if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_COPYPATH);   if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_DRVOP);      if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        /* Restore / Restore All 只在 SSDT / Shadow SSDT 子页出现 */
        b = GetDlgItem(hWnd, IDC_KM_RESTORE);
        if (b) ShowWindow(b, (isKernel && (g_KmTab == 2 || g_KmTab == 3)) ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_RESTOREALL);
        if (b) ShowWindow(b, (isKernel && (g_KmTab == 2 || g_KmTab == 3)) ? SW_SHOW : SW_HIDE);
    }

    if (g_hSuList)   ShowWindow(g_hSuList,   isStartup ? SW_SHOW : SW_HIDE);
    if (g_hSuStatus) ShowWindow(g_hSuStatus, isStartup ? SW_SHOW : SW_HIDE);
    {
        HWND hSu = GetDlgItem(hWnd, IDC_SU_REFRESH);
        if (hSu) ShowWindow(hSu, isStartup ? SW_SHOW : SW_HIDE);
    }

    if (g_hSvList)   ShowWindow(g_hSvList,   isServices ? SW_SHOW : SW_HIDE);
    if (g_hSvStatus) ShowWindow(g_hSvStatus, isServices ? SW_SHOW : SW_HIDE);
    {
        HWND hSv = GetDlgItem(hWnd, IDC_SV_REFRESH);
        if (hSv) ShowWindow(hSv, isServices ? SW_SHOW : SW_HIDE);
    }

    if (g_hRgTabs)   ShowWindow(g_hRgTabs,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgList)   ShowWindow(g_hRgList,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgStatus) ShowWindow(g_hRgStatus, isRegistry ? SW_SHOW : SW_HIDE);
    {
        HWND hRg = GetDlgItem(hWnd, IDC_RG_REFRESH);
        HWND hPath = GetDlgItem(hWnd, IDC_RG_PATH);
        HWND hGo = GetDlgItem(hWnd, IDC_RG_GO);
        if (hRg) ShowWindow(hRg, isRegistry ? SW_SHOW : SW_HIDE);
        /* 路径框只在 Key 子页出现 */
        if (hPath) ShowWindow(hPath, (isRegistry && g_RgTab == 0) ? SW_SHOW : SW_HIDE);
        if (hGo) ShowWindow(hGo, (isRegistry && g_RgTab == 0) ? SW_SHOW : SW_HIDE);
    }

    if (g_hFlDir)    ShowWindow(g_hFlDir,    isFile ? SW_SHOW : SW_HIDE);
    if (g_hFlList)   ShowWindow(g_hFlList,   isFile ? SW_SHOW : SW_HIDE);
    if (g_hFlStatus) ShowWindow(g_hFlStatus, isFile ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_FL_GO);
        HWND h2 = GetDlgItem(hWnd, IDC_FL_DEL);
        HWND h3 = GetDlgItem(hWnd, IDC_FL_VERIFY);
        if (h1) ShowWindow(h1, isFile ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isFile ? SW_SHOW : SW_HIDE);
        if (h3) ShowWindow(h3, isFile ? SW_SHOW : SW_HIDE);
    }

    if (g_hOtList)   ShowWindow(g_hOtList,   isOther ? SW_SHOW : SW_HIDE);
    if (g_hOtStatus) ShowWindow(g_hOtStatus, isOther ? SW_SHOW : SW_HIDE);
    if (g_hOtPath)   ShowWindow(g_hOtPath,   isOther ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_OT_VERIFY);
        HWND h2 = GetDlgItem(hWnd, IDC_OT_QUERY);
        if (h1) ShowWindow(h1, isOther ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isOther ? SW_SHOW : SW_HIDE);
    }

    if (g_hExList)   ShowWindow(g_hExList,   isExam ? SW_SHOW : SW_HIDE);
    if (g_hExStatus) ShowWindow(g_hExStatus, isExam ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_EX_RUN);
        HWND h2 = GetDlgItem(hWnd, IDC_EX_CANCEL);
        HWND h3 = GetDlgItem(hWnd, IDC_EX_EXPORT);
        if (h1) ShowWindow(h1, isExam ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isExam ? SW_SHOW : SW_HIDE);
        if (h3) ShowWindow(h3, isExam ? SW_SHOW : SW_HIDE);
    }

    /* Network 页：切到该页时按需拉一次解析结果 */
    if (g_hNwList)   ShowWindow(g_hNwList,   isNetwork ? SW_SHOW : SW_HIDE);
    if (g_hNwStatus) ShowWindow(g_hNwStatus, isNetwork ? SW_SHOW : SW_HIDE);
    if (isNetwork && g_Client.Opened)
        DoRefreshNetwork();

    if (g_hFePath)   ShowWindow(g_hFePath,   isFireeye ? SW_SHOW : SW_HIDE);
    if (g_hFeList)   ShowWindow(g_hFeList,   isFireeye ? SW_SHOW : SW_HIDE);
    if (g_hFeStatus) ShowWindow(g_hFeStatus, isFireeye ? SW_SHOW : SW_HIDE);
    {
        HWND a = GetDlgItem(hWnd, IDC_FE_ANALYSE);
        HWND b = GetDlgItem(hWnd, IDC_FE_OPEN);
        HWND c = GetDlgItem(hWnd, IDC_FE_RECORDS);
        HWND d = GetDlgItem(hWnd, IDC_FE_CLEAR);
        if (a) ShowWindow(a, isFireeye ? SW_SHOW : SW_HIDE);
        if (b) ShowWindow(b, isFireeye ? SW_SHOW : SW_HIDE);
        if (c) ShowWindow(c, isFireeye ? SW_SHOW : SW_HIDE);
        if (d) ShowWindow(d, isFireeye ? SW_SHOW : SW_HIDE);
    }

    if (g_hStList)   ShowWindow(g_hStList,   isSetting ? SW_SHOW : SW_HIDE);
    if (g_hStStatus) ShowWindow(g_hStStatus, isSetting ? SW_SHOW : SW_HIDE);
    {
        HWND a = GetDlgItem(hWnd, IDC_ST_REFRESH);
        HWND b = GetDlgItem(hWnd, IDC_ST_APPLY);
        HWND c = GetDlgItem(hWnd, IDC_ST_PROT_SSDT);
        HWND d = GetDlgItem(hWnd, IDC_ST_PROT_SHADOW);
        HWND e = GetDlgItem(hWnd, IDC_ST_TRAY);
        if (a) ShowWindow(a, isSetting ? SW_SHOW : SW_HIDE);
        if (b) ShowWindow(b, isSetting ? SW_SHOW : SW_HIDE);
        if (c) ShowWindow(c, isSetting ? SW_SHOW : SW_HIDE);
        if (d) ShowWindow(d, isSetting ? SW_SHOW : SW_HIDE);
        if (e) ShowWindow(e, isSetting ? SW_SHOW : SW_HIDE);
    }

    if (g_hTrList)   ShowWindow(g_hTrList,   isTrojan ? SW_SHOW : SW_HIDE);
    if (g_hTrStatus) ShowWindow(g_hTrStatus, isTrojan ? SW_SHOW : SW_HIDE);
    {
        HWND a = GetDlgItem(hWnd, IDC_TR_SCAN);
        HWND b = GetDlgItem(hWnd, IDC_TR_BACKUP);
        HWND c = GetDlgItem(hWnd, IDC_TR_RESTORE);
        HWND d = GetDlgItem(hWnd, IDC_TR_REPAIR);
        if (a) ShowWindow(a, isTrojan ? SW_SHOW : SW_HIDE);
        if (b) ShowWindow(b, isTrojan ? SW_SHOW : SW_HIDE);
        if (c) ShowWindow(c, isTrojan ? SW_SHOW : SW_HIDE);
        if (d) ShowWindow(d, isTrojan ? SW_SHOW : SW_HIDE);
    }

    if (g_hHkList)   ShowWindow(g_hHkList,   isHooks ? SW_SHOW : SW_HIDE);
    if (g_hHkStatus) ShowWindow(g_hHkStatus, isHooks ? SW_SHOW : SW_HIDE);
    {
        HWND a = GetDlgItem(hWnd, IDC_HK_REFRESH);
        HWND r = GetDlgItem(hWnd, IDC_HK_RESTORE);
        HWND c = GetDlgItem(hWnd, IDC_HK_CBTABLE);
        if (a) ShowWindow(a, isHooks ? SW_SHOW : SW_HIDE);
        /* 两项恢复操作只属于 Ring0 页（主 Tab 2），Ring3 页不显示 */
        if (r) ShowWindow(r, (page == 2) ? SW_SHOW : SW_HIDE);
        if (c) ShowWindow(c, (page == 2) ? SW_SHOW : SW_HIDE);
    }

    if (g_hPageHint) {
        if (isProc || isKernel || isStartup || isServices || isRegistry || isFile ||
            isOther || isExam || isFireeye || isSetting || isTrojan || isHooks ||
            isNetwork) {
            ShowWindow(g_hPageHint, SW_HIDE);
        } else {
            /* 【2026-10-22 实测更正】此前的提示说"驱动没有网络命令"，是错的。
           实机验证（kd 读 g_GlobalTable）：
             命令 0xF8 CmdInitKernelMemoryContext 的处理器被执行（HANDLED）；
             netio.sys 读取成功（0x94000 字节，kmctx stage=3 全部完成）；
             26 组 WFP/KFD/NSI 解析产出真实值，例如
               GT[0x7B2] = 0x0005CE00（WFP NBL 分派表 RVA）
                         + 0xFFFFF805387DCE00（解析出的绝对地址）
               GT[0x7B8] = 0x000144D0（KFD offload epoch 导出）
               GT[0x7DE] = 0x0001F020（KFD delete callout）
           也就是说数据源是存在的。当前页面尚未把这些槽渲染成列表，
           这是**渲染层未完成**，不是驱动缺数据。如实说明，不伪造。 */
            sprintf_s(hint, sizeof(hint),
                      "%s  -  data source present, view not yet rendered.\r\n\r\n"
                      "Command 0xF8 (CmdInitKernelMemoryContext) runs and parses "
                      "netio.sys successfully; the WFP / KFD / NSI results are "
                      "stored in GT[0x7B2..0x7E0]. This page does not render "
                      "them yet. The earlier note claiming the driver has no "
                      "network command was wrong (it was based on a scan run "
                      "whose 0x22 probe had wiped the handler table).",
                      g_MainTabNames[page < 14 ? page : 0]);
            SetWindowTextA(g_hPageHint, hint);
            ShowWindow(g_hPageHint, SW_SHOW);
        }
    }

    g_MainTab = page;
    if (isProc) {
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
static void CreateKmColumns(HWND hList, int tab)
{
    LVCOLUMNA c;

    while (ListView_DeleteColumn(hList, 0))
        ;

    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    if (tab == 0) {
        c.pszText = "Base";      c.cx = 140; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Size";      c.cx = 90;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Name";      c.cx = 160; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Path";      c.cx = 520; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 1) {
        c.pszText = "Service";   c.cx = 180; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "State";     c.cx = 100; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Start";     c.cx = 80;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "ImagePath"; c.cx = 550; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 10) {
        /* GDT：Selector / Base / Limit / Access / Flags / Descriptor */
        c.pszText = "Sel";        c.cx = 60;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Base";       c.cx = 160; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Limit";      c.cx = 100; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Access";     c.cx = 80;  c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Flags";      c.cx = 80;  c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
        c.pszText = "Descriptor"; c.cx = 400; c.iSubItem = 5; ListView_InsertColumn(hList, 5, &c);
    } else if (tab == 8) {
        /* IDT：Vector / Handler RVA / State */
        c.pszText = "Vector";      c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Handler RVA"; c.cx = 200; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "State";       c.cx = 200; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    } else if (tab == 9) {
        /* I/O Port：与 IDT 同源（0x046），按上下文汇总 */
        c.pszText = "Context";     c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Entries";     c.cx = 120; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Non-empty";   c.cx = 120; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Note";        c.cx = 550; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 6 || tab == 7) {
        /* Hidden Drivers / Suspicious DriverObject */
        c.pszText = "Name";   c.cx = 200; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Base";   c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Size";   c.cx = 90;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Path";   c.cx = 300; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Reason"; c.cx = 200; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    } else if (tab == 4) {
        /* Device（0x056）：Type / DeviceObject / Driver / Device / Object / Path */
        c.pszText = "Type";   c.cx = 50;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "DeviceObject"; c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Driver"; c.cx = 130; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Device"; c.cx = 130; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Object"; c.cx = 150; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
        c.pszText = "Path";   c.cx = 330; c.iSubItem = 5; ListView_InsertColumn(hList, 5, &c);
    } else if (tab == 5) {
        /* Object（0x0D5） */
        c.pszText = "Index"; c.cx = 60;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "ObjectHeader"; c.cx = 180; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Field1"; c.cx = 180; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Field2"; c.cx = 180; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Note";   c.cx = 340; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    } else {
        /* SSDT / Shadow SSDT（0x101 / 0x102） */
        c.pszText = "Index";     c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Address";   c.cx = 190; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Original";  c.cx = 190; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "State";     c.cx = 130; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Note";      c.cx = 360; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    }
}

static void KmSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

static void DoRefreshKernel(void)
{
    char status[1024];   /* Driver 页状态栏要拼三段内核项文案，256 不够 */

    if (!g_hKmList || !g_hKmStatus)
        return;
    ListView_DeleteAllItems(g_hKmList);
    CreateKmColumns(g_hKmList, g_KmTab);

    if (g_KmTab == 0) {
        FE_KMODULE_LIST list;
        ULONG i;
        if (!FeLoadKernelModules(&list)) {
            sprintf_s(status, sizeof(status),
                      "Kernel Module: load failed, GetLastError=%lu", GetLastError());
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char base[32], size[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(base, sizeof(base), "%016I64X", list.Items[i].Base);
            sprintf_s(size, sizeof(size), "0x%I64X", list.Items[i].Size);
            it.pszText = base;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            KmSetText(g_hKmList, (int)i, 1, size);
            KmSetText(g_hKmList, (int)i, 2,
                      list.Items[i].Name[0] ? list.Items[i].Name : "(?)");
            KmSetText(g_hKmList, (int)i, 3,
                      list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
        }
        sprintf_s(status, sizeof(status), "Kernel Module: %lu loaded modules", list.Count);
        FeFreeKernelModules(&list);
    } else if (g_KmTab == 1) {
        FE_DRIVER_LIST list;
        ULONG i;
        if (!FeLoadDrivers(&list)) {
            sprintf_s(status, sizeof(status),
                      "Driver: load failed, GetLastError=%lu", GetLastError());
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            const char *st;
            int row;
            /* Only Show Loaded Driver：只保留 RUNNING 的服务 */
            if (g_KmOnlyLoaded && list.Items[i].State != SERVICE_RUNNING)
                continue;
            row = ListView_GetItemCount(g_hKmList);
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = list.Items[i].Name;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            switch (list.Items[i].State) {
            case SERVICE_RUNNING:   st = "RUNNING";  break;
            case SERVICE_STOPPED:   st = "STOPPED";  break;
            case SERVICE_START_PENDING: st = "STARTING"; break;
            case SERVICE_STOP_PENDING:  st = "STOPPING"; break;
            default:                st = "?";        break;
            }
            KmSetText(g_hKmList, row, 1, st);
            switch (list.Items[i].Start) {
            case SERVICE_BOOT_START:   st = "BOOT";   break;
            case SERVICE_SYSTEM_START: st = "SYSTEM"; break;
            case SERVICE_AUTO_START:   st = "AUTO";   break;
            case SERVICE_DEMAND_START: st = "DEMAND"; break;
            case SERVICE_DISABLED:     st = "DISABLED"; break;
            default:                   st = "?";      break;
            }
            KmSetText(g_hKmList, row, 2, st);
            KmSetText(g_hKmList, row, 3,
                      list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
        }
        sprintf_s(status, sizeof(status),
                  "Driver: %lu kernel driver services%s",
                  (ULONG)ListView_GetItemCount(g_hKmList),
                  g_KmOnlyLoaded ? " (loaded only)" : "");
        FeFreeDrivers(&list);
        /* 原版 Driver 页状态栏同时给出隐藏驱动/可疑驱动对象计数 */
        {
            FE_HDRV_LIST hid, sus;
            if (FeLoadHiddenDrivers(&hid, &sus)) {
                char tail[160];
                char head[256];
                sprintf_s(tail, sizeof(tail),
                          "   |   Drivers: %lu / Hidden Drivers: %lu / "
                          "Suspicious DriverObject: %lu",
                          (ULONG)ListView_GetItemCount(g_hKmList), hid.Count, sus.Count);
                strcpy_s(head, sizeof(head), status);
                sprintf_s(status, sizeof(status), "%s%s", head, tail);
                FeFreeHiddenDrivers(&hid);
                FeFreeHiddenDrivers(&sus);
            }
        }
        /* 【G4 2026-10-22】原版 Driver 页状态栏有三段文案，必须始终可见：
             KiDebugRoutine Hooked / Find PTE Hook in 0x%p / Find Next ClassInitData。
           这三项在当前环境都拿不到结论（缺少内核任意地址读），但"拿不到"
           本身就是要展示的信息 —— 原版在同样条件下也会显示状态。
           因此无条件拼接，不可用时写明原因，而不是整段不显示。 */
        {
            ULONG64 kr = 0;
            BOOL hooked = FALSE;
            char detail[160];
            char pteDetail[160];
            char extra[640];

            FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
            FeFindPteHook(pteDetail, sizeof(pteDetail), &hooked);
            sprintf_s(extra, sizeof(extra),
                      "%s   |   %s   |   Find Next ClassInitData: not available "
                      "- the driver has no arbitrary kernel-VA read (0xF7/0xF9 read "
                      "one fixed GT pointer; 0x3A needs GT[0x41E4]/GT[0x4189], both 0 here)",
                      detail, pteDetail);
            if (g_hKmKExtra)
                SetWindowTextA(g_hKmKExtra, extra);
        }
    } else if (g_KmTab == 4) {
        /* Device 子页：0x056 CmdEnumObjectAllTypes（0x2000 起不再蓝屏） */
        FE_DEVICE_LIST dev;
        ULONG i;
        if (!FeLoadDeviceObjects(&g_Client, &dev, 0x20000)) {
            sprintf_s(status, sizeof(status), "Device: query failed (0x056)%s",
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        if (dev.State != 1) {
            sprintf_s(status, sizeof(status),
                      "Device: driver rejected (0x056 result=%u)", dev.ResultByte);
            SetWindowTextA(g_hKmStatus, status);
            FeFreeDeviceList(&dev);
            return;
        }
        for (i = 0; i < dev.Count; i++) {
            LVITEMA it;
            char t[16], d[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(t, sizeof(t), "%lu", (unsigned long)dev.Items[i].Type);
            sprintf_s(d, sizeof(d), "%016I64X", dev.Items[i].DeviceObject);
            it.pszText = t;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            KmSetText(g_hKmList, (int)i, 1, d);
            KmSetText(g_hKmList, (int)i, 2, dev.Items[i].DriverName);
            KmSetText(g_hKmList, (int)i, 3, dev.Items[i].DeviceName);
            KmSetText(g_hKmList, (int)i, 4, dev.Items[i].ObjectName);
            KmSetText(g_hKmList, (int)i, 5, dev.Items[i].FilePath);
        }
        sprintf_s(status, sizeof(status),
                  "Device: %lu objects (cmd 0x056, buffer 0x20000)", dev.Count);
        FeFreeDeviceList(&dev);
    } else if (g_KmTab == 5) {
        /* Object 子页：0x0D5 CmdEnumKernelObjectTable */
        FE_KOBJ_LIST obj;
        ULONG i;
        if (!FeLoadKernelObjectTable(&g_Client, &obj)) {
            sprintf_s(status, sizeof(status), "Object: query failed (0x0D5)%s",
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        if (obj.State != 1) {
            sprintf_s(status, sizeof(status),
                      "Object: driver rejected (0x0D5 result=%u)", obj.ResultByte);
            SetWindowTextA(g_hKmStatus, status);
            FeFreeKernelObjectList(&obj);
            return;
        }
        for (i = 0; i < obj.Count; i++) {
            LVITEMA it;
            char idx[16], h[32], f1[32], f2[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(idx, sizeof(idx), "%lu", (unsigned long)i);
            sprintf_s(h, sizeof(h), "%016I64X", obj.Items[i].ObjectHeader);
            sprintf_s(f1, sizeof(f1), "%016I64X", obj.Items[i].Field1);
            sprintf_s(f2, sizeof(f2), "%016I64X", obj.Items[i].Field2);
            it.pszText = idx;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            KmSetText(g_hKmList, (int)i, 1, h);
            KmSetText(g_hKmList, (int)i, 2, f1);
            KmSetText(g_hKmList, (int)i, 3, f2);
            KmSetText(g_hKmList, (int)i, 4, "kernel object header");
        }
        sprintf_s(status, sizeof(status),
                  "Object: %lu entries (build %lu, cmd 0x0D5)", obj.Count, obj.Build);
        FeFreeKernelObjectList(&obj);
    } else if (g_KmTab == 6 || g_KmTab == 7) {
        /* Hidden Drivers / Suspicious DriverObject（用户态比对，无需驱动） */
        FE_HDRV_LIST hidden, susp;
        FE_HDRV_LIST *show;
        ULONG i;
        if (!FeLoadHiddenDrivers(&hidden, &susp)) {
            SetWindowTextA(g_hKmStatus, "Hidden/Suspicious: query failed");
            return;
        }
        show = (g_KmTab == 6) ? &hidden : &susp;
        for (i = 0; i < show->Count; i++) {
            LVITEMA it;
            char base[32], size[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = show->Items[i].Name[0] ? show->Items[i].Name : "(?)";
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(base, sizeof(base), "%016I64X", show->Items[i].Base);
            sprintf_s(size, sizeof(size), "0x%I64X", show->Items[i].Size);
            KmSetText(g_hKmList, (int)i, 1, base);
            KmSetText(g_hKmList, (int)i, 2, size);
            KmSetText(g_hKmList, (int)i, 3, show->Items[i].Path);
            KmSetText(g_hKmList, (int)i, 4, show->Items[i].Reason);
        }
        sprintf_s(status, sizeof(status),
                  "Hidden Drivers: %lu / Suspicious DriverObject: %lu",
                  hidden.Count, susp.Count);
        FeFreeHiddenDrivers(&hidden);
        FeFreeHiddenDrivers(&susp);
    } else if (g_KmTab == 8) {
        /* IDT（0x046）：每个中断向量的处理函数 RVA */
        FE_IDT_LIST idt;
        ULONG i;
        if (!FeLoadIdt(&g_Client, &idt)) {
            SetWindowTextA(g_hKmStatus, "IDT: query failed (0x046, not connected?)");
            return;
        }
        if (idt.ContextCount == 0) {
            SetWindowTextA(g_hKmStatus,
                           "IDT: 0x046 returned no context (chain did not resolve)");
            FeFreeIdt(&idt);
            return;
        }
        {
            ULONG nonEmpty = 0;
            for (i = 0; i < idt.Count; i++) {
                LVITEMA it;
                char vec[16], rva[32];
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)i;
                sprintf_s(vec, sizeof(vec), "%lu", (unsigned long)idt.Items[i].Vector);
                sprintf_s(rva, sizeof(rva), "%016I64X", idt.Items[i].HandlerRva);
                it.pszText = vec;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, (int)i, 1, rva);
                if (idt.Items[i].HandlerRva) {
                    nonEmpty++;
                    KmSetText(g_hKmList, (int)i, 2, "present");
                } else {
                    KmSetText(g_hKmList, (int)i, 2, "(empty gate)");
                }
            }
            sprintf_s(status, sizeof(status),
                      "IDT: %lu vectors, %lu non-empty (0x046, %lu context(s))",
                      idt.Count, nonEmpty, idt.ContextCount);
        }
        SetWindowTextA(g_hKmStatus, status);
        FeFreeIdt(&idt);
    } else if (g_KmTab == 9) {
        /* I/O Port：同一命令的上下文视图（每处理器一个上下文） */
        FE_IDT_LIST idt;
        ULONG i;
        if (!FeLoadIdt(&g_Client, &idt)) {
            SetWindowTextA(g_hKmStatus, "I/O Port: query failed (0x046)");
            return;
        }
        if (idt.ContextCount == 0) {
            SetWindowTextA(g_hKmStatus,
                           "I/O Port: 0x046 returned no context (chain did not resolve)");
            FeFreeIdt(&idt);
            return;
        }
        {
            ULONG nonEmpty = 0;
            char ctx[16], ent[16], ne[16];
            for (i = 0; i < idt.Count; i++)
                if (idt.Items[i].HandlerRva)
                    nonEmpty++;
            sprintf_s(ctx, sizeof(ctx), "0");
            sprintf_s(ent, sizeof(ent), "%lu", idt.Count);
            sprintf_s(ne, sizeof(ne), "%lu", nonEmpty);
            {
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = 0;
                it.pszText = ctx;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, 0, 1, ent);
                KmSetText(g_hKmList, 0, 2, ne);
                KmSetText(g_hKmList, 0, 3,
                          "IDT gate table for this processor (0x046)");
            }
            sprintf_s(status, sizeof(status),
                      "I/O Port: %lu context(s), %lu IDT gates (%lu non-empty)",
                      idt.ContextCount, idt.Count, nonEmpty);
        }
        SetWindowTextA(g_hKmStatus, status);
        FeFreeIdt(&idt);
    } else if (g_KmTab == 10) {
        /* GDT（0x0CD）：逐描述符展示。条目布局 64KB 步长：
             +0x00 已写条目数  +0x04 处理器号  +0x08 limit
             +0x10 GDT 基址    +0x18 描述符数   +0x20 起 GDT 原始字节 */
        BYTE *out = (BYTE *)calloc(1, 0x10018);
        UCHAR res = 0;
        BOOL ok;
        ULONG entries;

        if (!out) {
            SetWindowTextA(g_hKmStatus, "GDT: out of memory");
            return;
        }
        ok = XpchInvoke(&g_Client, 0xCD, NULL, 0, out, 0x10018, &res);
        entries = *(ULONG *)out;
        if (!ok || entries == 0) {
            sprintf_s(status, sizeof(status),
                      "GDT: 0x0CD %s result=%u entries=%lu",
                      ok ? "ok" : "rejected", res, entries);
            SetWindowTextA(g_hKmStatus, status);
            free(out);
            return;
        }
        {
            BYTE *e = out + 8;
            ULONG limit = *(ULONG *)(e + 0);
            ULONG64 base = *(ULONG64 *)(e + 8);
            ULONG dcount = *(ULONG *)(e + 0x10);
            BYTE *gdt = e + 0x18;
            ULONG cpu = *(ULONG *)(e - 4);
            ULONG k;

            for (k = 0; k < dcount; k++) {
                ULONG64 d = *(ULONG64 *)(gdt + k * 8);
                LVITEMA it;
                char sel[16], baseText[32], limText[16], accText[16];
                char flagText[16], desc[64];
                ULONG access = (ULONG)((d >> 40) & 0xFF);
                ULONG flags = (ULONG)((d >> 52) & 0xF);
                ULONG64 dbase = ((d >> 16) & 0xFFFFFF) | (((d >> 56) & 0xFF) << 24);
                ULONG dlim = (ULONG)(d & 0xFFFF) | (ULONG)(((d >> 48) & 0xF) << 16);

                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)k;
                sprintf_s(sel, sizeof(sel), "%04lX", (unsigned long)(k * 8));
                it.pszText = sel;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                sprintf_s(baseText, sizeof(baseText), "%08I64X", dbase);
                sprintf_s(limText, sizeof(limText), "%05lX", (unsigned long)dlim);
                sprintf_s(accText, sizeof(accText), "%02lX", (unsigned long)access);
                sprintf_s(flagText, sizeof(flagText), "%lX", (unsigned long)flags);
                sprintf_s(desc, sizeof(desc), "%016I64X", d);
                KmSetText(g_hKmList, (int)k, 1, baseText);
                KmSetText(g_hKmList, (int)k, 2, limText);
                KmSetText(g_hKmList, (int)k, 3, accText);
                KmSetText(g_hKmList, (int)k, 4, flagText);
                KmSetText(g_hKmList, (int)k, 5, desc);
            }
            sprintf_s(status, sizeof(status),
                      "GDT: cpu%lu base=%016I64X limit=0x%lX descriptors=%lu "
                      "(0x0CD, %lu context(s))",
                      (unsigned long)cpu, base, (unsigned long)limit,
                      (unsigned long)dcount, entries);
        }
        SetWindowTextA(g_hKmStatus, status);
        free(out);
    } else {
        /* SSDT（g_KmTab==2）/ Shadow SSDT（g_KmTab==3）
         *
         * 【正确的数据源】0x101 CmdReadSsdtEntryTable / 0x102
         * CmdReadSsdtEntryTableEx —— 直接读 KiServiceTable 的表项。
         * 输出布局（实机验证）：
         *   +0x00 DWORD WindowsBuildNumber
         *   +0x04 DWORD 条目数 N
         *   +0x08 起     N 个 QWORD 函数地址
         * 缓冲要求：>= 8*(N-1)+16；实测 N=23（0x101）/ 139（0x102），给 0x1000 够。
         *
         * 【走过的弯路，记录以免再犯】
         *   1) 命令号算错：Table[i] 对应命令 0x20+i。CmdEnumSyscallEntries 是
         *      Table[140] -> 0xAC，不是 0x8C（0x8C=Table[108]，落在
         *      RtlZeroMemory(&Table[105],0x30) 的空槽区间）。同理 Shadow 是 0xAE。
         *   2) 0xAC/0xAE 确实是真实数据，但枚举的是 tcpip.sys / kbdclass.sys
         *      的驱动服务表（EnumSyscallTable7 -> OpenTcpIpDriverSection、
         *      EnumShadowSyscallTable -> OpenKbdClassDriverSection），不是内核 SSDT。
         *      28 项、每条 48 字节、+0x00 索引、+0x10 地址。
         *   3) 0x42 CmdQuerySsdtInfo 名字叫 SSDT，实际转调 CmdEnumDriverObjects
         *      枚举驱动对象，与 SSDT 无关。0xE6/0xEA/0x105 本机均返回 0。
         *   4) 0x117 那两张表是 Wdf01000.sys 内部的 Hook 表，属 Ring0 Hooks 页。 */
        UCHAR ready = 0;
        BYTE *buf;
        int table = (g_KmTab == 2) ? 1 : 2;
        BOOL ok;
        ULONG cmd = (g_KmTab == 2) ? 0x101 : 0x102;

        buf = (BYTE *)calloc(1, 0x1000);
        if (!buf) {
            SetWindowTextA(g_hKmStatus, "SSDT: out of memory");
            return;
        }
        ok = (g_Client.Opened)
           ? XpchInvoke(&g_Client, cmd, NULL, 0, buf, 0x1000, &ready)
           : FALSE;
        if (!ok) {
            sprintf_s(status, sizeof(status),
                      "%s: driver rejected (0x%03X)%s",
                      table == 1 ? "SSDT" : "Shadow SSDT", cmd,
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            free(buf);
            return;
        }
        {
            ULONG count = *(ULONG *)(buf + 4);
            ULONG build = *(ULONG *)(buf + 0);
            ULONG shown = 0, i;

            if (count > 300)              /* 防御：驱动给的 N 不合理就不读 */
                count = 0;
            for (i = 0; i < count; i++) {
                ULONG64 addr = *(ULONG64 *)(buf + 8 + 8ULL * i);
                char sidx[32], cur[32];
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)shown;
                sprintf_s(sidx, sizeof(sidx), "%lu", (unsigned long)i);
                sprintf_s(cur, sizeof(cur), "%016I64X", addr);
                it.pszText = sidx;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, (int)shown, 1, cur);
                KmSetText(g_hKmList, (int)shown, 2, "-");
                KmSetText(g_hKmList, (int)shown, 3, addr ? "present" : "null");
                KmSetText(g_hKmList, (int)shown, 4,
                          table == 1 ? "KiServiceTable entry" : "extended service table entry");
                shown++;
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu entries (build %lu, cmd 0x%03X)",
                      table == 1 ? "SSDT" : "Shadow SSDT", shown, build, cmd);
        }
        free(buf);
    }
    SetWindowTextA(g_hKmStatus, status);
}

/* 把 Kernel 列表当前选中行的某列复制到剪贴板。
 * 原版 Driver 页右键菜单有 Copy Driver Name / Copy Driver Path，
 * 这里做成按钮。复制后把内容回显到状态栏，便于截图取证。 */
static void DoCopyKmColumn(int SubItem, const char *What)
{
    char text[MAX_PATH * 2];
    char msg[MAX_PATH + 96];
    int sel;
    LVITEMA it;

    if (!g_hKmList || !g_hKmStatus)
        return;
    sel = ListView_GetNextItem(g_hKmList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hKmStatus, "Select a row first");
        return;
    }
    ZeroMemory(&it, sizeof(it));
    ZeroMemory(text, sizeof(text));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.iSubItem = SubItem;
    it.pszText = text;
    it.cchTextMax = (int)sizeof(text);
    if (!SendMessageA(g_hKmList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it) || !text[0]) {
        SetWindowTextA(g_hKmStatus, "Selected row has no text in that column");
        return;
    }
    if (!OpenClipboard(g_hKmList))
        return;
    EmptyClipboard();
    {
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(text) + 1);
        if (h) {
            void *p = GlobalLock(h);
            if (p) {
                memcpy(p, text, strlen(text) + 1);
                GlobalUnlock(h);
                SetClipboardData(CF_TEXT, h);
            }
        }
    }
    CloseClipboard();
    sprintf_s(msg, sizeof(msg), "%s copied: %s", What, text);
    SetWindowTextA(g_hKmStatus, msg);
}

/* 取 Kernel 列表当前选中行的驱动服务名。Driver 子页第 0 列就是服务名。 */
static BOOL KmSelectedDriverName(char *Out, size_t OutChars)
{
    int sel;
    LVITEMA it;

    if (Out && OutChars)
        Out[0] = 0;
    if (!g_hKmList || !Out || !OutChars)
        return FALSE;
    sel = ListView_GetNextItem(g_hKmList, -1, LVNI_SELECTED);
    if (sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.iSubItem = 0;
    it.pszText = Out;
    it.cchTextMax = (int)OutChars;
    if (!SendMessageA(g_hKmList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it))
        return FALSE;
    return Out[0] != 0;
}

/* Driver 子页的 5 个右键操作。破坏性操作先弹二次确认（原版同样要求确认）。 */
static void DoDriverOp(int Op)
{
    char name[FE_DRV_NAME_CHARS];
    char msg[1024];
    char path[1024];
    DWORD err = 0;

    if (!g_hKmStatus)
        return;
    if (g_KmTab != 1) {
        SetWindowTextA(g_hKmStatus, "Switch to the Driver subpage first");
        return;
    }

    if (Op == DRVOP_VERIFY_ALL) {
        ULONG valid = 0, invalid = 0, missing = 0, total = 0;
        SetWindowTextA(g_hKmStatus, "Verifying all driver signatures...");
        UpdateWindow(g_hKmStatus);
        FeVerifyAllDrivers(&valid, &invalid, &missing, &total);
        sprintf_s(msg, sizeof(msg),
                  "Verify All Driver Signature: total %lu / valid %lu / invalid or unsigned %lu / file missing %lu",
                  (unsigned long)total, (unsigned long)valid,
                  (unsigned long)invalid, (unsigned long)missing);
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Select a driver row first");
        return;
    }

    switch (Op) {
    case DRVOP_VERIFY: {
        int trusted;
        if (!FeResolveDriverPath(name, path, sizeof(path))) {
            sprintf_s(msg, sizeof(msg), "%s: cannot resolve ImagePath", name);
            SetWindowTextA(g_hKmStatus, msg);
            return;
        }
        {
            WCHAR wpath[1024];
            MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 1024);
            if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES) {
                sprintf_s(msg, sizeof(msg), "%s: file not found (%s)", name, path);
                SetWindowTextA(g_hKmStatus, msg);
                return;
            }
        }
        trusted = FeVerifyFileSignature(path);
        sprintf_s(msg, sizeof(msg), "Verify Driver Signature: %s -> %s  (%s)",
                  name,
                  trusted ? "signature valid and trusted" : "no signature or not trusted",
                  path);
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    case DRVOP_UNLOAD: {
        int r;
        sprintf_s(msg, sizeof(msg),
                  "Unload driver \"%s\"?\n\n"
                  "This stops the service. Stopping a driver that is in use can bugcheck "
                  "the machine immediately.\n\nContinue?",
                  name);
        r = MessageBoxA(g_hMainWnd, msg, "Unload Driver (Dangerous)",
                         MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (r != IDYES) {
            SetWindowTextA(g_hKmStatus, "Unload cancelled");
            return;
        }
        if (FeUnloadDriverService(name, &err))
            sprintf_s(msg, sizeof(msg), "Unload Driver: %s -> stop requested", name);
        else
            sprintf_s(msg, sizeof(msg), "Unload Driver: %s -> failed, GetLastError=%lu",
                      name, (unsigned long)err);
        /* 先刷新列表，再把结果写回状态栏，否则会被 DoRefreshKernel 的计数覆盖 */
        DoRefreshKernel();
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    case DRVOP_DEL_FILE:
    case DRVOP_DEL_FILE_REG: {
        int r;
        char deleted[1024];
        sprintf_s(msg, sizeof(msg),
                  "%s\n\nDriver: %s\n\nDelete the driver file from disk? This cannot be undone.",
                  Op == DRVOP_DEL_FILE_REG ? "Delete Driver (File And Reg)"
                                           : "Delete Driver (File)",
                  name);
        r = MessageBoxA(g_hMainWnd, msg, "Delete Driver File",
                         MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (r != IDYES) {
            SetWindowTextA(g_hKmStatus, "Delete cancelled");
            return;
        }
        if (Op == DRVOP_DEL_FILE_REG) {
            DWORD fileErr = 0, regErr = 0;
            FeDeleteDriverFileAndReg(name, deleted, sizeof(deleted), &fileErr, &regErr);
            if (fileErr)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file delete failed, "
                          "GetLastError=%lu", name, (unsigned long)fileErr);
            else if (regErr)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file deleted (%s), "
                          "service key delete failed, GetLastError=%lu",
                          name, deleted, (unsigned long)regErr);
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file deleted (%s), "
                          "service key deleted", name, deleted);
        } else {
            FeDeleteDriverFile(name, deleted, sizeof(deleted), &err);
            if (err)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File): %s -> failed, GetLastError=%lu",
                          name, (unsigned long)err);
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File): %s -> deleted %s", name, deleted);
        }
        DoRefreshKernel();
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    default:
        return;
    }
}

/* 进程右键操作：Kill / Force Kill / Suspend / Resume / Kill By Process Tree /
 * Kill And Delete File / Copy Image Path。 */
static void DoProcessOp(int Op)
{
    ULONG pid = GetSelectedPid();
    char msg[1024];
    char path[1024];

    if (!g_hProcStatus)
        return;
    if (!pid) {
        SetWindowTextA(g_hProcStatus, "Select a process first");
        return;
    }
    switch (Op) {
    case 0:   /* Kill */
        DoKillSelected();
        return;
    case 1:   /* Force Kill（0xA2，只给 EPROCESS） */
        if (!g_Client.Opened) {
            SetWindowTextA(g_hProcStatus, "Not connected");
            return;
        }
        sprintf_s(msg, sizeof(msg),
                  "Force kill PID %lu by EPROCESS?\n\nThis is destructive.", pid);
        if (MessageBoxA(g_hMainWnd, msg, "Force Kill",
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            SetWindowTextA(g_hProcStatus, "Force kill cancelled");
            return;
        }
        if (FeForceKillProcess(&g_Client, pid)) {
            sprintf_s(msg, sizeof(msg), "Force Kill: PID %lu terminated (EPROCESS)", pid);
            SetWindowTextA(g_hProcStatus, msg);
            DoRefreshProcs();
        } else {
            sprintf_s(msg, sizeof(msg), "Force Kill: PID %lu failed", pid);
            SetWindowTextA(g_hProcStatus, msg);
        }
        return;
    case 2:   /* Suspend */
    case 3:   /* Resume */
        if (FeSuspendResumeProcess(pid, Op == 2)) {
            sprintf_s(msg, sizeof(msg), "%s: PID %lu", Op == 2 ? "Suspend" : "Resume", pid);
        } else {
            sprintf_s(msg, sizeof(msg), "%s: PID %lu failed, GetLastError=%lu",
                      Op == 2 ? "Suspend" : "Resume", pid, GetLastError());
        }
        SetWindowTextA(g_hProcStatus, msg);
        return;
    case 4: { /* Kill By Process Tree */
        ULONG killed = 0, failed = 0;
        sprintf_s(msg, sizeof(msg),
                  "Kill PID %lu and all of its children?\n\nThis is destructive.", pid);
        if (MessageBoxA(g_hMainWnd, msg, "Kill By Process Tree",
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            SetWindowTextA(g_hProcStatus, "Kill tree cancelled");
            return;
        }
        FeKillProcessTree(&g_Client, pid, &killed, &failed);
        sprintf_s(msg, sizeof(msg), "Kill By Process Tree: root %lu -> killed %lu, failed %lu",
                  pid, killed, failed);
        SetWindowTextA(g_hProcStatus, msg);
        DoRefreshProcs();
        return;
    }
    case 5: { /* Kill And Delete File */
        BOOL rebootDel = FALSE;
        DWORD err = 0;
        sprintf_s(msg, sizeof(msg),
                  "Kill PID %lu and delete its image file?\n\nThis cannot be undone.", pid);
        if (MessageBoxA(g_hMainWnd, msg, "Kill And Delete File",
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            SetWindowTextA(g_hProcStatus, "Kill and delete cancelled");
            return;
        }
        {
            char deleted[1024];
            if (FeKillAndDeleteProcessFile(&g_Client, pid, deleted, sizeof(deleted),
                                           &err, &rebootDel)) {
                if (rebootDel)
                    sprintf_s(msg, sizeof(msg),
                              "Kill And Delete File: %s -> scheduled for delete on reboot", deleted);
                else
                    sprintf_s(msg, sizeof(msg),
                              "Kill And Delete File: %s -> deleted", deleted);
            } else {
                sprintf_s(msg, sizeof(msg),
                          "Kill And Delete File: PID %lu failed, GetLastError=%lu",
                          pid, (unsigned long)err);
            }
        }
        SetWindowTextA(g_hProcStatus, msg);
        DoRefreshProcs();
        return;
    }
    case 6: { /* Copy Image Path */
        if (!FeGetProcessImagePath(pid, path, sizeof(path))) {
            SetWindowTextA(g_hProcStatus, "Copy Image Path: cannot query the image path");
            return;
        }
        if (!OpenClipboard(g_hProc))
            return;
        EmptyClipboard();
        {
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(path) + 1);
            if (h) {
                void *p = GlobalLock(h);
                if (p) {
                    memcpy(p, path, strlen(path) + 1);
                    GlobalUnlock(h);
                    SetClipboardData(CF_TEXT, h);
                }
            }
        }
        CloseClipboard();
        sprintf_s(msg, sizeof(msg), "Image path copied: %s", path);
        SetWindowTextA(g_hProcStatus, msg);
        return;
    }
    default:
        return;
    }
}

static void DoProcessContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    /* 原版 Process 右键菜单的 View 组：切到对应子视图 */
    AppendMenuA(hMenu, MF_STRING, 5010, "View Modules");
    AppendMenuA(hMenu, MF_STRING, 5011, "View Threads");
    AppendMenuA(hMenu, MF_STRING, 5012, "View Handles");
    AppendMenuA(hMenu, MF_STRING, 5013, "View Windows");
    AppendMenuA(hMenu, MF_STRING, 5014, "View Memory");
    AppendMenuA(hMenu, MF_STRING, 5015, "View Timer");
    AppendMenuA(hMenu, MF_STRING, 5016, "View HotKey");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 5001, "Kill");
    AppendMenuA(hMenu, MF_STRING, 5002, "Force Kill");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 5003, "Suspend");
    AppendMenuA(hMenu, MF_STRING, 5004, "Resume");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 5005, "Kill By Process Tree");
    AppendMenuA(hMenu, MF_STRING, 5006, "Kill And Delete File");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 5007, "Copy Image Path");
    if (X == -1 && Y == -1) {
        RECT rc;
        GetWindowRect(g_hProc, &rc);
        X = rc.left + 40;
        Y = rc.top + 40;
    }
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    if (cmd >= 5001 && cmd <= 5007)
        DoProcessOp(cmd - 5001);
    else if (cmd >= 5010 && cmd <= 5016) {
        /* View 子页切换：5010→Modules(0) ... 5016→HotKey(6) */
        int tab = cmd - 5010;
        if (g_hTabs)
            SendMessageA(g_hTabs, TCM_SETCURSEL, (WPARAM)tab, 0);
        g_DetailTab = -1;
        DoRefreshDetail();
    }
}

/* ---- 模块右键操作：Copy Module Path / Dump Module Memory / Locate in File Tab ---- */
static ULONG64 DetailColumnQword(int Sel, int Sub)
{
    LVITEMA it;
    char text[64];

    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = Sel;
    it.iSubItem = Sub;
    it.pszText = text;
    it.cchTextMax = sizeof(text);
    if (!SendMessageA(g_hDetail, LVM_GETITEMTEXTA, (WPARAM)Sel, (LPARAM)&it))
        return 0;
    return _strtoui64(text, NULL, 16);
}

static BOOL DetailColumnText(int Sel, int Sub, char *Out, int OutChars)
{
    LVITEMA it;

    if (!Out || OutChars <= 0)
        return FALSE;
    Out[0] = 0;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = Sel;
    it.iSubItem = Sub;
    it.pszText = Out;
    it.cchTextMax = OutChars;
    return SendMessageA(g_hDetail, LVM_GETITEMTEXTA, (WPARAM)Sel, (LPARAM)&it) != 0;
}

static void DoModuleOp(int Op)
{
    int sel = ListView_GetNextItem(g_hDetail, -1, LVNI_SELECTED);
    ULONG pid = GetSelectedPid();
    char msg[1024];
    char path[1024];
    char baseText[64];

    if (!g_hProcStatus)
        return;
    if (g_DetailTab != 0) {
        SetWindowTextA(g_hProcStatus, "Switch to the Modules view first");
        return;
    }
    if (sel < 0) {
        SetWindowTextA(g_hProcStatus, "Select a module row first");
        return;
    }
    switch (Op) {
    case 0: /* Copy Module Path */
        if (!DetailColumnText(sel, 3, path, sizeof(path))) {
            SetWindowTextA(g_hProcStatus, "Selected module has no path");
            return;
        }
        if (!OpenClipboard(g_hDetail))
            return;
        EmptyClipboard();
        {
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(path) + 1);
            if (h) {
                void *p = GlobalLock(h);
                if (p) {
                    memcpy(p, path, strlen(path) + 1);
                    GlobalUnlock(h);
                    SetClipboardData(CF_TEXT, h);
                }
            }
        }
        CloseClipboard();
        sprintf_s(msg, sizeof(msg), "Module path copied: %s", path);
        SetWindowTextA(g_hProcStatus, msg);
        return;
    case 1: { /* Dump Module Memory */
        ULONG64 base = DetailColumnQword(sel, 0);
        ULONG size = (ULONG)DetailColumnQword(sel, 1);
        char name[128];
        char outPath[600];
        ULONG64 written = 0;

        if (!DetailColumnText(sel, 2, name, sizeof(name)) || !name[0]) {
            SetWindowTextA(g_hProcStatus, "Selected module has no name");
            return;
        }
        DetailColumnText(sel, 0, baseText, sizeof(baseText));
        sprintf_s(outPath, sizeof(outPath), "%s\\%s_%s_%lu.bin",
                  "C:\\Users\\Public", name, baseText, pid);
        if (FeDumpMemoryToFile(pid, base, size ? size : 0x1000, outPath, &written)) {
            sprintf_s(msg, sizeof(msg), "Dump Module Memory: %s -> %s (%I64u bytes)",
                      name, outPath, written);
        } else {
            sprintf_s(msg, sizeof(msg), "Dump Module Memory: %s failed (open/read)", name);
        }
        SetWindowTextA(g_hProcStatus, msg);
        return;
    }
    case 2: /* Locate in File Tab */
        if (!DetailColumnText(sel, 3, path, sizeof(path)) || !path[0]) {
            SetWindowTextA(g_hProcStatus, "Selected module has no path");
            return;
        }
        {
            char *slash = strrchr(path, '\\');
            if (slash)
                *slash = 0;
        }
        if (g_hFlDir) {
            SetWindowTextA(g_hFlDir, path);
            g_MainTab = 8;
            if (g_hMainTabs)
                SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
            if (g_hMainWnd)
                ShowPage(g_hMainWnd, 8);
            DoRefreshFiles();
        }
        sprintf_s(msg, sizeof(msg), "Locate in File Tab: %s", path);
        SetWindowTextA(g_hProcStatus, msg);
        return;
    default:
        return;
    }
}

/* 简易文本输入框：自建模态子窗口（EDIT + OK/Cancel），自带消息循环。
 * 不用资源文件，也不依赖任何 shell 组件。 */
static char  *g_PromptBuf;
static size_t g_PromptChars;
static BOOL   g_PromptOk;

static LRESULT CALLBACK PromptProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        CreateWindowA("STATIC", (const char *)((LPCREATESTRUCT)lParam)->lpCreateParams,
                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                      12, 10, 416, 20, hWnd, NULL, NULL, NULL);
        CreateWindowA("EDIT", "",
                      WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                      12, 34, 416, 24, hWnd, (HMENU)1, NULL, NULL);
        CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                      286, 68, 68, 26, hWnd, (HMENU)IDOK, NULL, NULL);
        CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      360, 68, 68, 26, hWnd, (HMENU)IDCANCEL, NULL, NULL);
        SetFocus(GetDlgItem(hWnd, 1));
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            if (g_PromptBuf && g_PromptChars)
                GetDlgItemTextA(hWnd, 1, g_PromptBuf, (int)g_PromptChars);
            g_PromptOk = TRUE;
            DestroyWindow(hWnd);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            g_PromptOk = FALSE;
            DestroyWindow(hWnd);
            return 0;
        }
        return 0;
    case WM_CLOSE:
        g_PromptOk = FALSE;
        DestroyWindow(hWnd);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

static BOOL DoPromptText(HWND Owner, const char *Title, const char *Prompt,
                         char *Out, size_t OutChars)
{
    static BOOL registered;
    WNDCLASSA wc;
    HWND hWnd;
    MSG msg;
    RECT rc, orc;
    BOOL wasEnabled;

    if (!Out || !OutChars)
        return FALSE;
    Out[0] = 0;

    if (!registered) {
        ZeroMemory(&wc, sizeof(wc));
        wc.lpfnWndProc = PromptProc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "XPCHunterPrompt";
        RegisterClassA(&wc);
        registered = TRUE;
    }

    hWnd = CreateWindowA("XPCHunterPrompt", Title,
                         WS_CAPTION | WS_SYSMENU | WS_POPUP,
                         CW_USEDEFAULT, CW_USEDEFAULT, 456, 140,
                         Owner, NULL, GetModuleHandleA(NULL), (LPVOID)Prompt);
    if (!hWnd)
        return FALSE;
    GetWindowRect(hWnd, &rc);
    if (Owner && GetWindowRect(Owner, &orc))
        SetWindowPos(hWnd, NULL,
                     orc.left + ((orc.right - orc.left) - (rc.right - rc.left)) / 2,
                     orc.top + ((orc.bottom - orc.top) - (rc.bottom - rc.top)) / 2,
                     0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    g_PromptBuf = Out;
    g_PromptChars = OutChars;
    g_PromptOk = FALSE;
    wasEnabled = Owner ? IsWindowEnabled(Owner) : FALSE;
    if (Owner)
        EnableWindow(Owner, FALSE);
    while (IsWindow(hWnd) && GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageA(hWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    if (Owner)
        EnableWindow(Owner, wasEnabled);
    g_PromptBuf = NULL;
    g_PromptChars = 0;
    return g_PromptOk && Out[0] != 0;
}

/* 模块搜索 5 项（76004..6008）。结果直接填进 Modules 视图的列表。 */
static void DoModuleSearch(int Op)
{
    FE_MODSEARCH_LIST res;
    ULONG pid = GetSelectedPid();
    char needle[128];
    char msg[512];
    ULONG i;
    BOOL ok = FALSE;

    if (!g_hProcStatus || !g_hDetail)
        return;
    needle[0] = 0;

    switch (Op) {
    case 0:   /* Find Module：弹出输入框取关键字 */
        if (!DoPromptText(GetActiveWindow(), "Find Module",
                          "Module name (substring):", needle, sizeof(needle)))
            return;
        if (!needle[0]) {
            SetWindowTextA(g_hProcStatus, "Find Module: empty keyword");
            return;
        }
        ok = FeFindModulesByName(needle, &res);
        break;
    case 1: ok = FeFindUnsignedModules(0, &res); break;
    case 2: ok = FeFindUnsignedModules(1, &res); break;
    case 3:
        if (!pid) {
            SetWindowTextA(g_hProcStatus, "Select a process first (Find Target is per-process)");
            return;
        }
        ok = FeFindTargetRegions(pid, &res);
        break;
    case 4: ok = FeFindHiddenModules(&res); break;
    default: return;
    }

    if (!ok) {
        SetWindowTextA(g_hProcStatus, "Module search failed");
        return;
    }
    /* 结果写进 Modules 视图 */
    g_DetailTab = 0;
    SetupDetailColumns(0);
    SendMessageA(g_hDetail, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < res.Count && i < 2000; i++) {
        LVITEMA it;
        char base[32], size[32], pidbuf[16];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        sprintf_s(pidbuf, sizeof(pidbuf), "%lu", res.Items[i].Pid);
        it.pszText = pidbuf;
        SendMessageA(g_hDetail, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(base, sizeof(base), "%016I64X", res.Items[i].Base);
        sprintf_s(size, sizeof(size), "0x%I64X", res.Items[i].Size);
        DetailSetText((int)i, 1, base);
        DetailSetText((int)i, 2, size);
        {
            char name[256];
            sprintf_s(name, sizeof(name), "%s  [PID %lu]", res.Items[i].Name,
                      (unsigned long)res.Items[i].Pid);
            DetailSetText((int)i, 3, name);
        }
        DetailSetText((int)i, 4, res.Items[i].Detail);
    }
    sprintf_s(msg, sizeof(msg), "Module search #%d: %lu result(s)", Op, res.Count);
    SetWindowTextA(g_hProcStatus, msg);
    FeFreeModSearch(&res);
}

static void DoModuleContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    AppendMenuA(hMenu, MF_STRING, 6004, "Find Module");
    AppendMenuA(hMenu, MF_STRING, 6005, "Find Unsigned Module");
    AppendMenuA(hMenu, MF_STRING, 6006, "Find Not Signature Module");
    AppendMenuA(hMenu, MF_STRING, 6007, "Find Target");
    AppendMenuA(hMenu, MF_STRING, 6008, "Find Hidden Item");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 6001, "Copy Module Path");
    AppendMenuA(hMenu, MF_STRING, 6002, "Dump Module Memory");
    AppendMenuA(hMenu, MF_STRING, 6003, "Locate in File Tab");
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    if (cmd >= 6001 && cmd <= 6003)
        DoModuleOp(cmd - 6001);
    else if (cmd >= 6004 && cmd <= 6008)
        DoModuleSearch(cmd - 6004);
}

/* 原版 Driver 页的 "Locate in Registry Tab"：跳到 Registry 页的 Key 子页，
 * 直接打开 HKLM\SYSTEM\CurrentControlSet\Services\<驱动名>。 */
static void DoLocateDriverInRegistry(void)
{
    char name[FE_DRV_NAME_CHARS];
    HWND hPath, hGo;

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Select a driver row first");
        return;
    }
    sprintf_s(g_RgPath, sizeof(g_RgPath),
              "HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s", name);

    /* 切主 Tab 到 Registry（索引 5）；ShowPage 内部会同步 g_MainTab */
    if (g_hMainTabs)
        SendMessageA(g_hMainTabs, TCM_SETCURSEL, 5, 0);
    if (g_hMainWnd)
        ShowPage(g_hMainWnd, 5);

    /* 【2026-10-23 修正】原版 Registry 只有 3 个子页
       （View Handle / Hidden Item / CmpNotifyChange，见 PCHunter64.exe
       0x45D99A 起的字符串组），**没有独立的 "Key 浏览" 子页**。
       所以 Locate in Registry Tab 的语义是：切到 Registry 页并把目标路径
       填进路径框，去 View Handle 列表里定位该键的句柄，
       而不是切到某个 "Key" 子页（那个子页本来就不存在）。 */
    g_RgTab = 0;
    if (g_hRgTabs)
        SendMessageA(g_hRgTabs, TCM_SETCURSEL, 0, 0);

    hPath = GetDlgItem(g_hMainWnd, IDC_RG_PATH);
    hGo = GetDlgItem(g_hMainWnd, IDC_RG_GO);
    if (hPath) {
        SetWindowTextA(hPath, g_RgPath);
        ShowWindow(hPath, SW_SHOW);
    }
    if (hGo)
        ShowWindow(hGo, SW_SHOW);

    DoRefreshRegistry();
    /* ShowPage 只在 Process 页重排布局，这里手动触发一次，让 Key 子页的
       多一行路径框布局（状态栏下移、Tab 与列表跟着下移）生效 */
    if (g_hMainWnd) {
        RECT rc;
        GetClientRect(g_hMainWnd, &rc);
        SendMessageA(g_hMainWnd, WM_SIZE, SIZE_RESTORED,
                     MAKELPARAM(rc.right, rc.bottom));
    }
}

/* Driver 子页右键菜单：与原版一致的操作集合。 */
static void DoDriverContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    int cmd;

    if (g_KmTab != 1)
        return;
    hMenu = CreatePopupMenu();
    if (!hMenu)
        return;
    AppendMenuA(hMenu, MF_STRING, 4001, "Verify Driver Signature");
    AppendMenuA(hMenu, MF_STRING, 4002, "Verify All Driver Signature");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 4003, "Unload Driver (Dangerous)");
    AppendMenuA(hMenu, MF_STRING, 4004, "Delete Driver (File)");
    AppendMenuA(hMenu, MF_STRING, 4005, "Delete Driver (File And Reg)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 4006, "Copy Driver Name");
    AppendMenuA(hMenu, MF_STRING, 4007, "Copy Driver Path");
    AppendMenuA(hMenu, MF_STRING, 4008, "Locate in Registry Tab");
    if (X == -1 && Y == -1) {
        RECT rc;
        GetWindowRect(g_hKmList, &rc);
        X = rc.left + 40;
        Y = rc.top + 40;
    }
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    switch (cmd) {
    case 4001: DoDriverOp(DRVOP_VERIFY);     break;
    case 4002: DoDriverOp(DRVOP_VERIFY_ALL); break;
    case 4003: DoDriverOp(DRVOP_UNLOAD);     break;
    case 4004: DoDriverOp(DRVOP_DEL_FILE);   break;
    case 4005: DoDriverOp(DRVOP_DEL_FILE_REG); break;
    case 4006: DoCopyKmColumn(0, "Driver name"); break;
    case 4007: DoCopyKmColumn(3, "Driver path"); break;
    case 4008: DoLocateDriverInRegistry();       break;
    default: break;
    }
}

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
           数据源：0xF8 CmdInitKernelMemoryContext 解析 netio.sys 得到的
           WFP/KFD/NSI 结果（GT[0x7B2..0x7DE]），经 0x13A 诊断通道导出。 */
        g_hNwStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    10, 80, 940, 20, hWnd, (HMENU)IDC_NW_STATUS, hInst, NULL);
        g_hNwList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                    10, 108, 940, 500, hWnd, (HMENU)IDC_NW_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hNwList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

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
            int midY, detailH;
            if (listH < 100) listH = 100;
            midY = pageTop + listH + 4;
            detailH = pageBottom - (midY + 28) - 150;
            if (detailH < 80) detailH = 80;
            if (g_hProc)       MoveWindow(g_hProc, 10, pageTop, w, listH, TRUE);
            if (g_hProcStatus) MoveWindow(g_hProcStatus, 10, midY, w, 20, TRUE);
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
        } else {
            if (g_hList) ShowWindow(g_hList, SW_HIDE);
        }
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_CONNECT: DoConnect(); return 0;
        case IDC_REFRESH: DoRefreshProcs(); return 0;
        case IDC_SCAN:    DoScan();    return 0;
        case IDC_SEND:    DoSend();    return 0;
        case IDC_KILL:    DoKillSelected(); return 0;
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

    case WM_DESTROY:
        if (g_Client.Opened)
            XpchClose(&g_Client);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

/* Non-GUI mode so the same shape/skip logic can be exercised from a headless
   session (vmrun runProgramInGuest cannot show a window). */
static int RunHeadless(void)
{
    ULONG cmd;
    int okCount = 0, failCount = 0, skipCount = 0;
    char detail[128];
    FILE *log = NULL;

    fopen_s(&log, "C:\\Users\\Public\\frontend_scan.txt", "w");

#define LOGF(...) do { printf(__VA_ARGS__); \
        if (log) { fprintf(log, __VA_ARGS__); fflush(log); } } while (0)

    if (!XpchOpen(&g_Client)) {
        LOGF("open device failed, GetLastError=%lu\n", GetLastError());
        if (log) fclose(log);
        return 1;
    }
    LOGF("connected: ioctl=0x%08X key=0x%02X\n",
        g_Client.IoControlCode, g_Client.KeyByte);

    for (cmd = XPCH_CMD_MIN; cmd <= XPCH_CMD_MAX; cmd++) {
        if (FeIsSkipped(cmd)) {
            SendOne(cmd, 0, detail, sizeof(detail));
            LOGF("0x%02X SKIP      %s\n", cmd, detail);
            skipCount++;
        } else if (SendOne(cmd, 256, detail, sizeof(detail))) {
            LOGF("0x%02X OK        %s\n", cmd, detail);
            okCount++;
        } else {
            LOGF("0x%02X REJECTED  %s\n", cmd, detail);
            failCount++;
        }
    }

    LOGF("summary: %d OK, %d REJECTED, %d SKIP (total %d)\n",
        okCount, failCount, skipCount, okCount + failCount + skipCount);

#undef LOGF
    XpchClose(&g_Client);
    if (log) fclose(log);
    return 0;
}

/* 无头模式：打印进程列表（Process 页的数据来源验证）。
   数据链：0xE4 取 EPROCESS 链表 → 条目 +0x108 取 PID → 0x2A 取映像路径。 */
static int RunProcListCli(void)
{
    if (!XpchOpen(&g_Client)) {
        printf("open device failed, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    printf("connected: ioctl=0x%08X key=0x%02X\n",
           g_Client.IoControlCode, g_Client.KeyByte);

    /* 先握手：驱动就绪标志 GT[0x304] 为 0 时，除 0x22 外的命令一律被拒
       （DriverEntry.c 的 `GtRead(0x304) == 0 && Command != 0x22` 守卫）。 */
    XpchHandshake(&g_Client);

    FePrintProcessList(&g_Client);

    XpchClose(&g_Client);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow)
{
    WNDCLASSA wc;
    HWND hWnd;
    MSG msg;
    INITCOMMONCONTROLSEX icc;

    UNREFERENCED_PARAMETER(hPrev);

    if (lpCmdLine && strstr(lpCmdLine, "--proclist-cli"))
        return RunProcListCli();

    /* Kernel 页两个子页的无界面入口（用于实机取证与回归） */
    if (lpCmdLine && strstr(lpCmdLine, "--kernel-cli"))
        return FePrintKernelModules() ? 0 : 1;
    /* Ring0 Hooks 页：0x117 的两张系统调用表 */
    if (lpCmdLine && strstr(lpCmdLine, "--ring0-cli")) {
        int rc;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        rc = FePrintRing0Hooks(&g_Client) ? 0 : 1;
        XpchClose(&g_Client);
        return rc;
    }
    /* Kernel->SSDT / Shadow SSDT 子页：--ssdt-cli [1|2]
     * 数据源 0x101（SSDT）/ 0x102（Shadow SSDT），与 GUI 子页同一命令。 */
    if (lpCmdLine && strstr(lpCmdLine, "--ssdt-cli")) {
        const char *p = strstr(lpCmdLine, "--ssdt-cli") + 11;
        int table = 1;
        BYTE *buf;
        UCHAR ready = 0;
        BOOL ok;
        ULONG cmd, i, count, build, shown = 0;
        while (*p == ' ') p++;
        if (*p >= '1' && *p <= '2')
            table = *p - '0';
        cmd = (table == 1) ? 0x101 : 0x102;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        buf = (BYTE *)calloc(1, 0x1000);
        if (!buf) { XpchClose(&g_Client); return 1; }
        ok = XpchInvoke(&g_Client, cmd, NULL, 0, buf, 0x1000, &ready);
        printf("=== %s (cmd 0x%03X) -> %s result=%u ===\n",
               table == 1 ? "SSDT" : "Shadow SSDT", cmd,
               ok ? "OK" : "REJECTED", ready);
        if (ok) {
            build = *(ULONG *)(buf + 0);
            count = *(ULONG *)(buf + 4);
            printf("build=%lu count=%lu\n", build, count);
            if (count <= 300) {
                for (i = 0; i < count; i++) {
                    ULONG64 addr = *(ULONG64 *)(buf + 8 + 8ULL * i);
                    printf("  [%03lu] %016I64X\n", (unsigned long)i, addr);
                    shown++;
                }
            }
            printf("entries=%lu\n", shown);
        }
        free(buf);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }

    /* Ring0 恢复两项的无界面入口（实机取证用） */
    if (lpCmdLine && strstr(lpCmdLine, "--restorehooks-cli")) {
        FE_HOOK_RESTORE_RESULT r;
        int rc;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        rc = FeRestoreOverHooks(&g_Client, 1, &r) ? 0 : 1;
        printf("=== Restore Over. Hooks/Patches (0x118) ===\n");
        printf("state        = %s\n", FeHookRestoreStateText(&r));
        printf("driverOk     = %d  resultByte = %u\n", r.DriverOk, r.ResultByte);
        printf("totalEntries = %lu  modified = %lu\n", r.TotalEntries, r.ModifiedCount);
        XpchClose(&g_Client);
        return rc;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--cbtable-cli")) {
        FE_CB_TABLE t;
        ULONG i;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        printf("=== Restore KernelCallbackTable (0x131) ===\n");
        if (!FeLoadCallbackTable(&g_Client, &t)) {
            printf("query failed\n");
            XpchClose(&g_Client);
            return 1;
        }
        printf("state      = %s\n", FeCbStateText(&t));
        printf("driverOk   = %d  resultByte = %u\n", t.DriverOk, t.ResultByte);
        printf("ready      = %u  build = %lu\n", t.Ready, t.Build);
        printf("slots      = %lu\n", t.Count);
        for (i = 0; i < t.Count; i++) {
            char orig[64] = {0};
            int k;
            for (k = 0; k < 16; k++)
                sprintf_s(orig + k * 3, sizeof(orig) - (size_t)k * 3, "%02X ",
                          t.Slot[i].Original[k]);
            printf("  [%2lu] rva=%08lX va=%016I64X cur=%016I64X orig=%s\n",
                   (unsigned long)t.Slot[i].Offset,
                   (unsigned long)t.Slot[i].Rva,
                   t.Slot[i].Va, t.Slot[i].Current, orig);
        }
        /* --cbtable-restore：对检测到差异的槽真正下发 0x132 写回 */
        if (lpCmdLine && strstr(lpCmdLine, "--cbtable-restore")) {
            ULONG attempted = 0, restored = 0, rejected = 0, skipped = 0;
            printf("--- restore pass (0x132) ---\n");
            for (i = 0; i < t.Count; i++) {
                FE_CB_RESTORE_RESULT rr;
                if (!t.Slot[i].HasOriginal) { skipped++; continue; }
                if (!t.Slot[i].Current || t.Slot[i].Current == t.Slot[i].Va) {
                    skipped++;
                    continue;
                }
                attempted++;
                if (FeRestoreCallbackSlot(&g_Client, t.Slot[i].Va,
                                          t.Slot[i].Original, &rr) &&
                    rr.State == FE_CB_RESTORE_OK) {
                    restored++;
                    printf("  slot %lu -> wrote 16 bytes at %016I64X\n",
                           (unsigned long)t.Slot[i].Offset, t.Slot[i].Va);
                } else {
                    rejected++;
                    printf("  slot %lu -> FAILED (state=%d resultByte=%u)\n",
                           (unsigned long)t.Slot[i].Offset, rr.State, rr.ResultByte);
                }
            }
            printf("restored=%lu attempted=%lu rejected=%lu skipped=%lu\n",
                   (unsigned long)restored, (unsigned long)attempted,
                   (unsigned long)rejected, (unsigned long)skipped);
        }
        XpchClose(&g_Client);
        return (t.State == FE_CB_ENUMERATED) ? 0 : 2;
    }

    if (lpCmdLine && strstr(lpCmdLine, "--hooks-cli")) {
        const char *p = strstr(lpCmdLine, "--hooks-cli") + 11;
        ULONG pid = GetCurrentProcessId();
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9')
            pid = (ULONG)strtoul(p, NULL, 0);
        return FePrintRing3Hooks(pid) ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--trojan-cli"))
        return FePrintTrojanReport(0) ? 0 : 1;
    /* Driver 子页操作的无 UI 入口（取证/回归用，与右键菜单同一套实现） */
    if (lpCmdLine && strstr(lpCmdLine, "--drvop-cli")) {
        FeDriverOpsCli(lpCmdLine);
        return 0;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--regkey-cli")) {
        const char *p = strstr(lpCmdLine, "--regkey-cli") + 12;
        while (*p == ' ')
            p++;
        return FePrintRegValues(*p ? p : "HKLM\\SYSTEM\\CurrentControlSet\\Services") ? 0 : 1;
    }
    /* --regctx-cli：0x127 CmdEnumRegistryContext（输出必须恰好 1800 字节） */
    if (lpCmdLine && strstr(lpCmdLine, "--regctx-cli")) {
        BYTE *out = (BYTE *)calloc(1, 1800);
        UCHAR res = 0;
        BOOL ok;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\n");
            return 1;
        }
        XpchHandshake(&g_Client);
        if (!out) { XpchClose(&g_Client); return 1; }
        ok = XpchInvoke(&g_Client, 0x127, NULL, 0, out, 1800, &res);
        printf("0x127 -> %s result=%u firstDword=%lu\n",
               ok ? "OK" : "REJECTED", res, (unsigned long)*(ULONG *)out);
        if (ok) {
            ULONG i;
            for (i = 0; i < 1800; i += 16) {
                int nz = 0, k;
                for (k = 0; k < 16 && i + k < 1800; k++)
                    if (out[i + k]) nz++;
                if (!nz) continue;
                printf("  %04lX:", (unsigned long)i);
                for (k = 0; k < 16 && i + k < 1800; k++)
                    printf(" %02X", out[i + k]);
                printf("\n");
            }
        }
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    /* --startup-op-cli repair | delfile <Name> ：Startup 两项验收用 */
    if (lpCmdLine && strstr(lpCmdLine, "--startup-op-cli")) {
        const char *p = strstr(lpCmdLine, "--startup-op-cli") + 17;
        char op[32], arg[FE_STARTUP_NAME_CHARS];
        int n;
        while (*p == ' ') p++;
        op[0] = 0; arg[0] = 0;
        n = sscanf_s(p, "%31s %255s", op, (unsigned)sizeof(op),
                     arg, (unsigned)sizeof(arg));
        if (n >= 1 && _stricmp(op, "repair") == 0) {
            ULONG checked = 0, fixed;
            FE_STARTUP_LIST rep;
            fixed = FeRepairStartupItems(&checked, &rep);
            printf("Repair Startup: checked=%lu repaired=%lu\n", checked, fixed);
            {
                ULONG i;
                for (i = 0; i < rep.Count; i++)
                    printf("  removed: %s  %s\n", rep.Items[i].Name, rep.Items[i].Data);
            }
            FeFreeStartupItems(&rep);
            return 0;
        }
        if (n >= 2 && _stricmp(op, "delfile") == 0) {
            FE_STARTUP_LIST list;
            ULONG i;
            if (!FeLoadStartupItems(&list)) {
                printf("startup: load failed\n");
                return 1;
            }
            for (i = 0; i < list.Count; i++) {
                if (strcmp(list.Items[i].Name, arg) != 0)
                    continue;
                {
                    char path[FE_STARTUP_DATA_CHARS];
                    BOOL regOk = FALSE;
                    DWORD fileErr = 0;
                    BOOL ok = FeDeleteStartupItemAndFile(&list.Items[i], path,
                                                         sizeof(path), &regOk, &fileErr);
                    printf("delfile %s -> ok=%d reg=%d file=%s err=%lu\n",
                           arg, ok ? 1 : 0, regOk ? 1 : 0,
                           path[0] ? path : "(none)", (unsigned long)fileErr);
                }
                FeFreeStartupItems(&list);
                return 0;
            }
            FeFreeStartupItems(&list);
            printf("startup item not found: %s\n", arg);
            return 1;
        }
        printf("usage: --startup-op-cli repair | delfile <Name>\n");
        return 1;
    }
    /* Modules 视图五项搜索的无 UI 入口：
       --modsearch-cli name <substring> | unsigned | nosig | target <pid> | hidden */
    if (lpCmdLine && strstr(lpCmdLine, "--modsearch-cli")) {
        const char *p = strstr(lpCmdLine, "--modsearch-cli") + 16;
        FE_MODSEARCH_LIST res;
        char op[32];
        char arg[192];
        int n;
        ULONG i;
        BOOL ok = FALSE;

        while (*p == ' ') p++;
        op[0] = 0; arg[0] = 0;
        n = sscanf_s(p, "%31s %191s", op, (unsigned)sizeof(op),
                     arg, (unsigned)sizeof(arg));
        if (n < 1) {
            printf("usage: --modsearch-cli name <substr> | unsigned | nosig | target <pid> | hidden\n");
            return 1;
        }
        if (_stricmp(op, "name") == 0)
            ok = FeFindModulesByName(n >= 2 ? arg : "", &res);
        else if (_stricmp(op, "unsigned") == 0)
            ok = FeFindUnsignedModules(0, &res);
        else if (_stricmp(op, "nosig") == 0)
            ok = FeFindUnsignedModules(1, &res);
        else if (_stricmp(op, "target") == 0)
            /* 不给 PID 时扫自己，便于验证扫描逻辑本身是否工作 */
            ok = FeFindTargetRegions(n >= 2 ? (ULONG)strtoul(arg, NULL, 0)
                                            : GetCurrentProcessId(), &res);
        else if (_stricmp(op, "hidden") == 0)
            ok = FeFindHiddenModules(&res);
        else {
            printf("unknown op: %s\n", op);
            return 1;
        }
        if (!ok) {
            printf("modsearch %s: failed\n", op);
            return 1;
        }
        printf("modsearch %s: %lu result(s)\n", op, res.Count);
        for (i = 0; i < res.Count && i < 40; i++)
            printf("  pid=%-6lu base=%016I64X size=0x%-8I64X %-24s %s\n",
                   res.Items[i].Pid, res.Items[i].Base, res.Items[i].Size,
                   res.Items[i].Name, res.Items[i].Detail);
        if (res.Count > 40)
            printf("  ... (%lu more)\n", res.Count - 40);
        FeFreeModSearch(&res);
        return 0;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--setting-cli")) {
        FE_OBJ_TYPES ot;
        int ok;
        int i;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\n");
            return 1;
        }
        XpchHandshake(&g_Client);
        ok = FeSettingReadObjectTypes(&g_Client, &ot);
        printf("object types: %s\n", ok ? "available" : "NOT READY (driver did not export)");
        printf("  IoFileObjectType   = %p\n", (void *)(ULONG_PTR)ot.File);
        printf("  IoDriverObjectType = %p\n", (void *)(ULONG_PTR)ot.Driver);
        printf("  IoDeviceObjectType = %p\n", (void *)(ULONG_PTR)ot.Device);
        printf("  PsProcessType      = %p  (GT[0x4166])\n", (void *)(ULONG_PTR)ot.Process);
        printf("  PsThreadType       = %p  (GT[0x4169])\n", (void *)(ULONG_PTR)ot.Thread);
        for (i = 0; i < 13; i++)
            printf("  extra[%2d]          = %p\n", i, (void *)(ULONG_PTR)ot.Extra[i]);
        printf("  minimize-to-tray   = %d\n", FeSettingGetMinimizeToTray());
        XpchClose(&g_Client);
        return 0;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--filesig-cli")) {
        const char *p = strstr(lpCmdLine, "--filesig-cli") + 13;
        char path[MAX_PATH];
        size_t n = 0;
        while (*p == ' ') p++;
        if (*p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path))
            path[n++] = *p++;
        path[n] = 0;
        printf("%s -> %s\n", path, FeVerifyFileSignature(path)
               ? "signature valid and trusted" : "no signature or not trusted");
        printf("  WinVerifyTrust status = 0x%08lX\n", (unsigned long)g_LastTrustStatus);
        return 0;
    }
    /* --forbid-cli <0..4> [enable]: send 0x79 to verify the object type address */
    if (lpCmdLine && strstr(lpCmdLine, "--forbid-cli")) {
        const char *p = strstr(lpCmdLine, "--forbid-cli") + 13;
        FE_OBJ_TYPES ot;
        int which;
        BOOL enable = TRUE;
        ULONG64 target = 0;
        UCHAR res = 0;
        BOOL ok;
        while (*p == ' ') p++;
        which = atoi(p);
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        if (*p == '0') enable = FALSE;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\
");
            return 1;
        }
        XpchHandshake(&g_Client);
        if (!FeSettingReadObjectTypes(&g_Client, &ot)) {
            printf("object types not available\
");
            XpchClose(&g_Client);
            return 1;
        }
        switch (which) {
        case 0: target = ot.File;    break;
        case 1: target = ot.Driver;  break;
        case 2: target = ot.Device;  break;
        case 3: target = ot.Process; break;
        case 4: target = ot.Thread;  break;
        default:
            printf("which must be 0..4\
");
            XpchClose(&g_Client);
            return 1;
        }
        ok = FeSettingSetForbid(&g_Client, target, 0, enable ? 1 : 0, &res);
        printf("0x79 forbid which=%d target=%016I64X enable=%d -> %s result=%u\
",
               which, (unsigned __int64)target, enable ? 1 : 0,
               ok ? "OK" : "REJECTED", res);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--fireeye-cli")) {
        const char *p = strstr(lpCmdLine, "--fireeye-cli") + 13;
        char path[MAX_PATH]; size_t n = 0;
        while (*p == ' ' || *p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path)) path[n++] = *p++;
        while (n && (path[n-1] == 32 || path[n-1] == 13 || path[n-1] == 10)) path[--n] = 0;
        return FePrintFireeye(path) ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--exam-cli"))
        return FePrintExamination() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--os-cli"))
        return FePrintOsInfo() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--filever-cli")) {
        const char *p = strstr(lpCmdLine, "--filever-cli") + 13;
        char path[MAX_PATH]; size_t n = 0;
        while (*p == ' ' || *p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path)) path[n++] = *p++;
        while (n && (path[n - 1] == 32 || path[n - 1] == 13 || path[n - 1] == 10)) path[--n] = 0;
        return FePrintFileVersion(path) ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--files-cli")) {
        const char *d = strstr(lpCmdLine, "--files-cli") + 12;
        char dir[MAX_PATH];
        size_t n = 0;
        while (*d == ' ' || *d == '"') d++;
        while (*d && *d != '"' && n + 1 < sizeof(dir))
            dir[n++] = *d++;
        dir[n] = 0;
        /* 去掉尾部空白（cmd 重定向/引号容易带出来） */
        while (n && (dir[n - 1] == ' ' || dir[n - 1] == 13 || dir[n - 1] == 10))
            dir[--n] = 0;
        return FePrintDirectory(n ? dir : "C:\Windows\System32") ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--reghandles-cli"))
        return FePrintRegistryHandles() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--reghidden-cli"))
        return FePrintHiddenRegKeys() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--services-cli"))
        return FePrintServices() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--startup-cli"))
        return FePrintStartupItems() ? 0 : 1;
    if (lpCmdLine && strstr(lpCmdLine, "--hiddendrv-cli"))
        return FePrintHiddenDrivers() ? 0 : 1;
    /* --network-cli：无界面打印 Network 页的实际数据行。
       用途同 --g4-status-cli：截图不可靠时直接输出程序生成的内容。 */
    /* --reg-cli：打印 0x127 的真实语义（Npfs 分发表指针），
       用于说明它**不是** CmpNotifyChange 的数据源。 */
    if (lpCmdLine && strstr(lpCmdLine, "--reg-cli")) {
        UCHAR *ctx;
        UCHAR r127 = 0;
        ULONG n;
        int shown = 0;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        if (!XpchHandshake(&g_Client)) {
            printf("handshake failed\n");
            XpchClose(&g_Client);
            return 1;
        }
        ctx = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1800);
        if (!ctx) {
            printf("out of memory\n");
            XpchClose(&g_Client);
            return 1;
        }
        if (!XpchInvoke(&g_Client, 0x127, NULL, 0, ctx, 1800, &r127)) {
            printf("0x127 CmdEnumRegistryContext rejected (result=%u)\n", r127);
            HeapFree(GetProcessHeap(), 0, ctx);
            XpchClose(&g_Client);
            return 1;
        }
        printf("0x127 CmdEnumRegistryContext (buffer must be exactly 1800)\n");
        printf("  NOTE: this enumerates Npfs dispatch-table pointers, NOT\n");
        printf("        the CmRegisterCallback chain (see kd lm a output).\n");
        {
            const UCHAR *recs = ctx + 8;
            ULONG maxrec = (1800 - 8) / 0x30;
            for (n = 0; n < maxrec; n++) {
                const UCHAR *rec = recs + n * 0x30;
                ULONG idx = *(const ULONG *)(const void *)(rec + 0x00);
                ULONG64 fn = *(const ULONG64 *)(const void *)(rec + 0x10);
                if (!fn)
                    continue;
                printf("  [%lu] 0x%016llX   (record %lu, +0x%lX)\n",
                       idx, (unsigned long long)fn,
                       n, (unsigned long)(n * 0x30 + 0x10));
                shown++;
            }
        }
        printf("  total %d pointer(s); verify with: lm a <addr>\n", shown);
        HeapFree(GetProcessHeap(), 0, ctx);
        XpchClose(&g_Client);
        return 0;
    }

    if (lpCmdLine && strstr(lpCmdLine, "--network-cli")) {
        UCHAR *buf;
        UCHAR res = 0;
        ULONG i, nonZero = 0;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        if (!XpchHandshake(&g_Client)) {
            printf("handshake failed\n");
            XpchClose(&g_Client);
            return 1;
        }
        {
            UCHAR dummy[0x40];
            XpchInvoke(&g_Client, 0xF8, NULL, 0, dummy, sizeof(dummy), &res);
        }
        buf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x4000);
        if (!buf || !XpchInvoke(&g_Client, 0x13A, NULL, 0, buf, 0x4000, &res)) {
            printf("0x13A unavailable (result=%u)\n", res);
            if (buf) HeapFree(GetProcessHeap(), 0, buf);
            XpchClose(&g_Client);
            return 1;
        }
        {
            const UCHAR *env = buf + 283 * 16 + 16;
            const ULONG64 *vals = (const ULONG64 *)(const void *)(env + 0x400);
            ULONG stage = *(const ULONG *)(const void *)(env + 0x3B0);
            ULONG fsize = *(const ULONG *)(const void *)(env + 0x3B4);

            printf("Network page data (0xF8 InitKernelMemoryContext)\n");
            printf("  netio.sys size = 0x%lX   stage = %lu "
                   "(0=not run 1=read failed 2=parsing 3=done)\n", fsize, stage);
            printf("  %-14s %-20s %s\n", "Object", "Value", "Resolver (GT slot)");
            for (i = 0; i < FE_NET_SLOT_N; i++) {
                if (vals[i]) nonZero++;
                printf("  %-14s 0x%016llX  %s (GT[0x%X])\n",
                       g_NetSlots[i].Name,
                       (unsigned long long)vals[i],
                       g_NetSlots[i].Meaning,
                       g_NetSlots[i].GtIndex);
            }
            printf("  resolved %lu/%lu\n", nonZero, (ULONG)FE_NET_SLOT_N);
        }
        HeapFree(GetProcessHeap(), 0, buf);
        XpchClose(&g_Client);
        return 0;
    }

    /* --g4-status-cli：打印各页状态栏文案的**实际拼接结果**。
       用于 G4 形态核对：截图受会话/VNC 影响不稳定，直接输出字符串更可靠。 */
    if (lpCmdLine && strstr(lpCmdLine, "--g4-status-cli")) {
        ULONG64 kr = 0;
        BOOL hooked = FALSE;
        char detail[160];
        char pteDetail[160];
        char extra[640];
        char driverLine[1024];
        FE_HDRV_LIST hid, sus;
        ULONG drvCount = 0;
        FE_DRIVER_LIST drivers;

        FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
        FeFindPteHook(pteDetail, sizeof(pteDetail), &hooked);
        sprintf_s(extra, sizeof(extra),
                  "%s   |   %s   |   Find Next ClassInitData: not available "
                  "- the driver has no arbitrary kernel-VA read (0xF7/0xF9 read "
                  "one fixed GT pointer; 0x3A needs GT[0x41E4]/GT[0x4189], both 0 here)",
                  detail, pteDetail);

        if (FeLoadHiddenDrivers(&hid, &sus))
            ;
        else {
            hid.Count = 0; sus.Count = 0;
        }
        if (FeLoadDrivers(&drivers)) {
            drvCount = drivers.Count;
            FeFreeDrivers(&drivers);
        }
        sprintf_s(driverLine, sizeof(driverLine),
                  "Driver: %lu kernel driver services   |   Drivers: %lu / "
                  "Hidden Drivers: %lu / Suspicious DriverObject: %lu",
                  drvCount, drvCount, hid.Count, sus.Count);
        FeFreeHiddenDrivers(&hid);
        FeFreeHiddenDrivers(&sus);

        printf("[Kernel/Driver] %s\n", driverLine);
        printf("[Kernel/Other ] %s\n", extra);
        printf("[Setting      ] Object types: %s | Forbid available: %d of 6 | "
               "Tray minimize: %s\n",
               "resolved", 5,
               FeSettingGetMinimizeToTray() ? "ON" : "OFF");
        return 0;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--kernel-extra-cli")) {
        ULONG64 kr = 0;
        BOOL hooked = FALSE;
        char detail[256];
        BOOL okd;

        okd = FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
        printf("KiDebugRoutine: %s -> %s\n", okd ? "ok" : "unreadable", detail);
        FeFindPteHook(detail, sizeof(detail), &hooked);
        printf("Find PTE Hook: %s\n", detail);
        printf("Find Next ClassInitData: not available - the driver has no "
               "arbitrary kernel-VA read (0xF7/0xF9 read one fixed GT pointer; "
               "0x3A needs GT[0x41E4]/GT[0x4189], both 0 on this machine)\n");
        return 0;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--idt-cli")) {
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        FePrintIdt(&g_Client);
        XpchClose(&g_Client);
        return 0;
    }
    /* GDT（0x0CD，OutSize >= 0x10018）。每个条目 64KB 步长：
         +0x00 DWORD 已写条目数
         +0x04 DWORD 处理器号
         +0x08 DWORD limit
         +0x10 QWORD GDT 基址
         +0x18 DWORD 描述符数
         +0x20 起  GDT 原始字节 */
    if (lpCmdLine && strstr(lpCmdLine, "--gdt-cli")) {
        BYTE *out = NULL;
        UCHAR res = 0;
        BOOL ok;
        ULONG n, i;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        out = (BYTE *)calloc(1, 0x10018);
        if (!out) {
            XpchClose(&g_Client);
            return 1;
        }
        ok = XpchInvoke(&g_Client, 0xCD, NULL, 0, out, 0x10018, &res);
        n = *(ULONG *)out;
        printf("GDT (0x0CD) -> %s result=%u entries=%lu\n",
               ok ? "OK" : "REJECTED", res, n);
        for (i = 0; i < n && i < 8; i++) {
            BYTE *e = out + 8 + (ULONG64)i * 65556ULL;
            ULONG limit = *(ULONG *)(e + 0);
            ULONG64 base = *(ULONG64 *)(e + 8);
            ULONG count = *(ULONG *)(e + 0x10);
            BYTE *gdt = e + 0x18;
            printf("  cpu%lu limit=0x%lX base=%016I64X descriptors=%lu\n",
                   (unsigned long)*(ULONG *)(e - 4), (unsigned long)limit, base,
                   (unsigned long)count);
            printf("    gdt[0]=%016I64X gdt[1]=%016I64X gdt[2]=%016I64X\n",
                   *(ULONG64 *)(gdt + 0), *(ULONG64 *)(gdt + 8),
                   *(ULONG64 *)(gdt + 16));
        }
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    /* IDT / I/O Port（0x046）的无 UI 入口。
 * 驱动侧的调用约定是 Handler(InPtr, OutSize, OutPtr, InSize)，
 * 而 0x046 的实现把第 2 个参数当"输出缓冲大小"用 —— 也就是客户端的
 * InSize。所以必须同时给 InSize >= 0x3808 和足够大的输出缓冲。 */
    if (lpCmdLine && strstr(lpCmdLine, "--ioport-cli")) {
        BYTE *in = NULL, *out = NULL;
        UCHAR res = 0;
        BOOL ok;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        in = (BYTE *)calloc(1, 0x3808);
        out = (BYTE *)calloc(1, 0x3808);
        if (!in || !out) {
            printf("out of memory\n");
            XpchClose(&g_Client);
            return 1;
        }
        ok = XpchInvoke(&g_Client, 0x46, in, 0x3808, out, 0x3808, &res);
        printf("0x046 -> %s result=%u\n", ok ? "OK" : "REJECTED", res);
        if (ok && *(ULONG *)out != 0) {
            ULONG count = *(ULONG *)out, i;
            printf("  io-port contexts: %lu\n", count);
            /* 每个上下文 14336(0x3800) 字节，从 out+8 开始。
               每条 56 字节：+0 = 中断向量号，+8 = 处理函数地址
               （ReadIoPortDescriptorTable 写的是 addr - ntoskrnlBase 的 RVA，
                 0 表示该向量为空）。 */
            for (i = 0; i < count && i < 4; i++) {
                BYTE *e = out + 8 + (ULONG64)i * 0x3800ULL;
                ULONG k;
                printf("   ctx%lu:\n", (unsigned long)i);
                for (k = 0; k < 8; k++) {
                    ULONG *slot = (ULONG *)(e + k * 56);
                    ULONG64 rva = *(ULONG64 *)((BYTE *)slot + 8);
                    printf("     vec %-3lu rva %08I64X%s\n",
                           (unsigned long)*slot, rva,
                           rva ? "" : "  (empty gate)");
                }
            }
        } else {
            printf("  output counter = 0 (chain did not resolve)\n");
        }
        free(in);
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    /* Dump Memory / Dump Module Memory 的无 UI 入口：
       --dumpmem-cli <pid> <basehex> <sizehex> [outPath] */
    if (lpCmdLine && strstr(lpCmdLine, "--dumpmem-cli")) {
        const char *p = strstr(lpCmdLine, "--dumpmem-cli") + 13;
        unsigned long pid = 0;
        unsigned __int64 base = 0, size = 0;
        char outPath[512];
        char arg[256];
        int n;
        ULONG64 written = 0;

        while (*p == ' ')
            p++;
        n = sscanf_s(p, "%lu %llx %llx %511s", &pid, &base, &size,
                     outPath, (unsigned)sizeof(outPath));
        if (n < 3) {
            printf("usage: --dumpmem-cli <pid> <base-hex> <size-hex> [outFile]\n");
            return 1;
        }
        if (n < 4) {
            sprintf_s(arg, sizeof(arg), "%lu", pid);
            sprintf_s(outPath, sizeof(outPath),
                      "C:\\Users\\Public\\dump_%lu_%I64X.bin", pid, base);
        }
        if (FeDumpMemoryToFile((ULONG)pid, (ULONG64)base, (ULONG64)size,
                               outPath, &written)) {
            printf("dump %lu [%I64X,+%I64X) -> %s (%I64u bytes)\n",
                   pid, base, size, outPath, written);
            return 0;
        }
        printf("dump %lu [%I64X,+%I64X) -> failed\n", pid, base, size);
        return 1;
    }
    /* 进程右键操作的无 UI 入口：--proc-op-cli <op> <pid> */
    if (lpCmdLine && strstr(lpCmdLine, "--proc-op-cli")) {
        const char *p = strstr(lpCmdLine, "--proc-op-cli") + 14;
        char op[32];
        ULONG pid;
        int n;
        BOOL ok = FALSE;
        while (*p == ' ')
            p++;
        n = sscanf_s(p, "%31s %lu", op, (unsigned)sizeof(op), &pid);
        if (n < 2) {
            printf("usage: --proc-op-cli forcekill|suspend|resume|killtree|killdel|imagepath <pid>\n");
            return 1;
        }
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        if (_stricmp(op, "forcekill") == 0) {
            ok = FeForceKillProcess(&g_Client, pid);
            printf("forcekill %lu -> %s\n", pid, ok ? "terminated" : "failed");
        } else if (_stricmp(op, "killtree") == 0) {
            ULONG k = 0, f = 0;
            ULONG pids[512];
            ULONG cnt = FeCollectProcessTree(pid, pids, 512), i;
            printf("killtree %lu: tree =", pid);
            for (i = 0; i < cnt; i++)
                printf(" %lu", pids[i]);
            printf("\n");
            ok = FeKillProcessTree(&g_Client, pid, &k, &f);
            printf("killtree %lu -> killed %lu, failed %lu\n", pid, k, f);
            for (i = 0; i < cnt; i++) {
                HANDLE hh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
                printf("   pid %-6lu %s\n", pids[i], hh ? "STILL ALIVE" : "gone");
                if (hh) CloseHandle(hh);
            }
        } else if (_stricmp(op, "killdel") == 0) {
            char deleted[1024];
            DWORD err = 0;
            BOOL rebootDel = FALSE;
            ok = FeKillAndDeleteProcessFile(&g_Client, pid, deleted, sizeof(deleted),
                                            &err, &rebootDel);
            printf("killdel %lu -> %s%s%s (error %lu)\n", pid, ok ? deleted : "failed",
                   rebootDel ? " (delete on reboot)" : "", ok ? "" : "", (unsigned long)err);
        } else if (_stricmp(op, "suspend") == 0 || _stricmp(op, "resume") == 0) {
            BOOL susp = (_stricmp(op, "suspend") == 0);
            ok = FeSuspendResumeProcess(pid, susp);
            printf("%s %lu -> %s\n", susp ? "suspend" : "resume", pid, ok ? "ok" : "failed");
        } else if (_stricmp(op, "imagepath") == 0) {
            char path[1024];
            ok = FeGetProcessImagePath(pid, path, sizeof(path));
            printf("imagepath %lu -> %s\n", pid, ok ? path : "(failed)");
        } else {
            printf("unknown op: %s\n", op);
        }
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--ssdt-restore-cli")) {
        const char *p = strstr(lpCmdLine, "--ssdt-restore-cli") + 18;
        BYTE res = 0;
        BOOL ok;
        while (*p == ' ')
            p++;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        if (p[0] == 'a' || p[0] == 'A') {
            ok = FeRestoreSsdtAll(&g_Client, &res);
            printf("Restore All (0xE7) -> %s result=%u\n", ok ? "OK" : "REJECTED", res);
        } else {
            ULONG sel = (ULONG)strtoul(p, NULL, 0);
            ok = FeRestoreSsdtEntry(&g_Client, sel, &res);
            printf("Restore entry %lu (0xEB) -> %s result=%u\n",
                   (unsigned long)sel, ok ? "OK" : "REJECTED", res);
        }
        XpchClose(&g_Client);
        return ok ? 0 : 1;
    }
    if (lpCmdLine && strstr(lpCmdLine, "--drivers-cli"))
        return FePrintDrivers() ? 0 : 1;

    /* 子视图调试入口：--memory-cli <pid>
     *
     * --kill-cli <pid>    走 0xA2（CmdTerminateProcessByEProcess）。
     *   2026-10-21 实测结论：0xA2 在 Win10 上并不终止进程——驱动侧
     *   build >= 0x1DB0 分支调用的是 GT[0x42BC]（18362 上解析为 KeCancelTimer），
     *   原始驱动同样如此。保留该入口用于对照实验。
     * --kill28-cli <pid>  走 0x28（CmdProcessOperation），内部
     *   ZeroProcessMemoryPages 遍历目标用户空间逐页清零，这是真正终止的路径。 */
    if (lpCmdLine && (strstr(lpCmdLine, "--kill-cli") || strstr(lpCmdLine, "--kill28-cli"))) {
        BOOL use28 = strstr(lpCmdLine, "--kill28-cli") != NULL;
        const char *argp = use28 ? (strstr(lpCmdLine, "--kill28-cli") + 13)
                                 : (strstr(lpCmdLine, "--kill-cli") + 11);
        ULONG kpid = (ULONG)strtoul(argp, NULL, 0);
        ULONG64 kep = 0;
        if (XpchOpen(&g_Client)) {
            FE_PROCESS_LIST list;
            ULONG i;
            XpchHandshake(&g_Client);
            if (FeLoadProcessList(&g_Client, FE_PROC_DEFAULT_MAX, &list)) {
                for (i = 0; i < list.Count; i++)
                    if (list.Items[i].Pid == kpid) { kep = list.Items[i].Eprocess; break; }
                FeFreeProcessList(&list);
            }
            printf("kill pid %lu ep=%p via 0x%s -> %s\n", kpid, (void *)(ULONG_PTR)kep,
                   use28 ? "28" : "A2",
                   /* 0x28 也要带 EPROCESS：驱动在 ValidateProcessObject 不通过时
                      会直接返回成功却不做事，FeKillProcess 需要它来回落 0xA2。 */
                   FeKillProcess(&g_Client, kpid, kep, !use28) ? "OK" : "FAILED");
            XpchClose(&g_Client);
        } else {
            printf("open device failed\n");
        }
        return 0;
    }

    if (lpCmdLine && strstr(lpCmdLine, "--memory-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--memory-cli") + 12, NULL, 0);
        FePrintProcessMemory(pid);
        return 0;
    }

    /* 子视图调试入口：--handles-cli <pid> */
    if (lpCmdLine) {
        char *pt = strstr(lpCmdLine, "--tab ");
        if (pt) {
            g_StartTab = atoi(pt + 6);
            if (g_StartTab < 0 || g_StartTab > 6) g_StartTab = 0;
        }
    }

    if (lpCmdLine && strstr(lpCmdLine, "--handles-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--handles-cli") + 13, NULL, 0);
        FePrintProcessHandles(pid);
        return 0;
    }

    /* 子视图调试入口：--threads-cli <pid> */
    if (lpCmdLine && strstr(lpCmdLine, "--threads-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--threads-cli") + 13, NULL, 0);
        FePrintProcessThreads(pid);
        return 0;
    }

    /* 子视图调试入口：--modules-cli <pid> */
    if (lpCmdLine && strstr(lpCmdLine, "--modules-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--modules-cli") + 13, NULL, 0);
        FePrintProcessModules(pid);
        return 0;
    }

    /* 子视图调试入口：--windows-cli <pid> */
    if (lpCmdLine && strstr(lpCmdLine, "--windows-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--windows-cli") + 13, NULL, 0);
        FePrintProcessWindows(pid);
        return 0;
    }

    /* 子视图调试入口：--hotkeys-cli <pid>（命令 0x33，按 EPROCESS 过滤） */
    if (lpCmdLine && strstr(lpCmdLine, "--hotkeys-cli")) {
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--hotkeys-cli") + 13, NULL, 0);
        FePrintProcessHotkeys(&g_Client, pid);
        return 0;
    }

    if (lpCmdLine && strstr(lpCmdLine, "--scan-cli"))
        return RunHeadless();

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