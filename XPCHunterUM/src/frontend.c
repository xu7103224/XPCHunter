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

static XPCH_CLIENT g_Client;
static HWND g_hList, g_hStatus, g_hCmd, g_hSize;
static HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
static HWND g_hKmTabs, g_hKmList, g_hKmStatus;
static HWND g_hMainTabs, g_hPageHint;
static HWND g_hSuList, g_hSuStatus;
static HWND g_hSvList, g_hSvStatus;
static HWND g_hRgTabs, g_hRgList, g_hRgStatus;
static int  g_RgTab = 0;
static HWND g_hFlDir, g_hFlList, g_hFlStatus;
static HWND g_hOtList, g_hOtStatus, g_hOtPath;
static HWND g_hExList, g_hExStatus;
static FE_EXAM_RESULT g_ExamResult;
static int g_ExamLoaded = 0;
static HWND g_hFePath, g_hFeList, g_hFeStatus;
static FE_FIREEYE_JOB g_FeJob;
static int g_FeHasJob = 0;
static int  g_MainTab = 0;    /* 当前主 Tab（0 = Process） */
static int  g_KmTab = 0;
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
    static const char *titles[] = { "PID", "Name", "Path", "EPROCESS" };
    static const int widths[] = { 60, 150, 400, 160 };
    LVCOLUMNA col;
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

/* ---- 明细子视图（Modules / Threads / Windows）--------------------------- */

static const char *g_TabNames[5] = { "Modules", "Threads", "Windows", "Handles", "Memory" };

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
    static const char *cols[5][5] = {
        { "Base", "Size", "Name", "Path", "" },
        { "TID", "Prio", "Start", "", "" },
        { "HWND", "TID", "Class", "Title", "" },
        { "Handle", "Type", "Access", "Object", "" },
        { "Base", "Size", "Protect", "Type", "Name" },
    };
    static const int widths[5][5] = {
        { 130, 90, 160, 380, 0 },
        { 70, 60, 150, 0, 0 },
        { 110, 60, 170, 340, 0 },
        { 90, 180, 100, 260, 0 },
        { 130, 100, 80, 70, 360 },
    };
    LVCOLUMNA col;
    int i, n = (tab == 1) ? 3 : ((tab == 4) ? 5 : 4);

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

    if (tab < 0 || tab > 4)
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
    char buf[64];

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
 * 已实现的页：0 Process、1 Kernel。其余 12 页显示"未实现"提示，
 * 不伪造功能。
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
    hRef = GetDlgItem(hWnd, IDC_KM_REFRESH);
    if (hRef) ShowWindow(hRef, isKernel ? SW_SHOW : SW_HIDE);

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
        if (hRg) ShowWindow(hRg, isRegistry ? SW_SHOW : SW_HIDE);
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

    if (g_hPageHint) {
        if (isProc || isKernel || isStartup || isServices || isRegistry || isFile ||
            isOther || isExam || isFireeye) {
            ShowWindow(g_hPageHint, SW_HIDE);
        } else {
            sprintf_s(hint, sizeof(hint),
                      "%s  -  not implemented yet.\r\n\r\n"
                      "See docs/reversing for the planned data source.",
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
    } else {
        c.pszText = "Service";   c.cx = 180; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "State";     c.cx = 100; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Start";     c.cx = 80;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "ImagePath"; c.cx = 550; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
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
    char status[256];

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
    } else {
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
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = list.Items[i].Name;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            switch (list.Items[i].State) {
            case SERVICE_RUNNING:   st = "RUNNING";  break;
            case SERVICE_STOPPED:   st = "STOPPED";  break;
            case SERVICE_START_PENDING: st = "STARTING"; break;
            case SERVICE_STOP_PENDING:  st = "STOPPING"; break;
            default:                st = "?";        break;
            }
            KmSetText(g_hKmList, (int)i, 1, st);
            switch (list.Items[i].Start) {
            case SERVICE_BOOT_START:   st = "BOOT";   break;
            case SERVICE_SYSTEM_START: st = "SYSTEM"; break;
            case SERVICE_AUTO_START:   st = "AUTO";   break;
            case SERVICE_DEMAND_START: st = "DEMAND"; break;
            case SERVICE_DISABLED:     st = "DISABLED"; break;
            default:                   st = "?";      break;
            }
            KmSetText(g_hKmList, (int)i, 2, st);
            KmSetText(g_hKmList, (int)i, 3,
                      list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
        }
        sprintf_s(status, sizeof(status), "Driver: %lu kernel driver services", list.Count);
        FeFreeDrivers(&list);
    }
    SetWindowTextA(g_hKmStatus, status);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

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
            for (k = 0; k < 5; k++) {
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
        g_hKmStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | SS_LEFT,
                                    110, 82, 840, 20, hWnd, (HMENU)IDC_KM_STATUS, hInst, NULL);
        g_hKmTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | TCS_TABS,
                                  10, 110, 940, 24, hWnd, (HMENU)IDC_KM_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            static const char *kmNames[2] = { "Kernel Module", "Driver" };
            for (k = 0; k < 2; k++) {
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
        g_hRgTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | TCS_TABS,
                                  10, 110, 940, 24, hWnd, (HMENU)IDC_RG_TABS, hInst, NULL);
        {
            TCITEMA t;
            int k;
            static const char *rgNames[2] = { "Reg Handle", "Hidden Item" };
            for (k = 0; k < 2; k++) {
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
            if (p) page = atoi(p + 7);
            if (cl && strstr(cl, "--kernel-gui")) page = 1;
            if (page < 0 || page > 13) page = 0;
            SendMessageA(g_hMainTabs, TCM_SETCURSEL, (WPARAM)page, 0);
            ShowPage(hWnd, page);
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
                if (hRef) {
                    MoveWindow(hRef, 10, pageTop, 90, 28, TRUE);
                    ShowWindow(hRef, SW_SHOW);
                }
            }
            if (g_hKmStatus) MoveWindow(g_hKmStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            if (g_hKmTabs)   MoveWindow(g_hKmTabs, 10, pageTop + 34, w, 24, TRUE);
            if (g_hKmList)   MoveWindow(g_hKmList, 10, listY, w, listH, TRUE);
            if (g_hList)     ShowWindow(g_hList, SW_HIDE);
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
            int listY = pageTop + 64;
            int listH = pageBottom - listY;
            HWND hRg = GetDlgItem(hWnd, IDC_RG_REFRESH);
            if (listH < 100) listH = 100;
            if (hRg) MoveWindow(hRg, 10, pageTop, 90, 28, TRUE);
            if (g_hRgStatus) MoveWindow(g_hRgStatus, 110, pageTop + 6, w - 100, 20, TRUE);
            if (g_hRgTabs)   MoveWindow(g_hRgTabs, 10, pageTop + 34, w, 24, TRUE);
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
        case IDC_SU_REFRESH: DoRefreshStartup(); return 0;
        case IDC_SV_REFRESH: DoRefreshServices(); return 0;
        case IDC_RG_REFRESH: DoRefreshRegistry(); return 0;
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
        }
        return 0;

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
            return 0;
        }
        if (nm->idFrom == IDC_RG_TABS && nm->code == TCN_SELCHANGE) {
            g_RgTab = (int)SendMessageA(g_hRgTabs, TCM_GETCURSEL, 0, 0);
            DoRefreshRegistry();
            return 0;
        }
        if (nm->idFrom == IDC_KM_TABS && nm->code == TCN_SELCHANGE) {
            g_KmTab = (int)SendMessageA(g_hKmTabs, TCM_GETCURSEL, 0, 0);
            DoRefreshKernel();
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
                   FeKillProcess(&g_Client, kpid, use28 ? 0 : kep, !use28) ? "OK" : "FAILED");
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
            if (g_StartTab < 0 || g_StartTab > 4) g_StartTab = 0;
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