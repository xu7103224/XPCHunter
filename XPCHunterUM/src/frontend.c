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
/* Kernel 页（独立窗口） */
#define IDC_KERNEL      1014
#define IDC_KM_REFRESH  1020
#define IDC_KM_TABS     1021
#define IDC_KM_LIST     1022
#define IDC_KM_STATUS   1023

static XPCH_CLIENT g_Client;
static HWND g_hList, g_hStatus, g_hCmd, g_hSize;
static HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
static HWND g_hKernel, g_hKmTabs, g_hKmList, g_hKmStatus;
static int  g_KmTab = 0;
static int  g_DetailTab = -1;
static int  g_StartTab = 0;   /* --tab N：启动时预选子视图页 */

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
 * Kernel 页（对应原版 PCHunter 的第 2 个主 Tab，先落两个子页）
 *
 *   Kernel Module : EnumDeviceDrivers + GetDeviceDriverBaseNameW/FileNameW
 *   Driver        : SCM 的 SERVICE_DRIVER 枚举 + QueryServiceConfig
 *
 * 做成独立窗口而不是主窗口内的分页，是为了不改动已实机验证过的 Process 页
 * 布局（Process 页的坐标与 WM_SIZE 都是硬编码的）。等其余页面补齐后，
 * 这些页会统一收进一个主 Tab 栏里。
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

static LRESULT CALLBACK KernelWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        TCITEMA t;
        int k;

        CreateWindowA("BUTTON", "Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      10, 10, 90, 28, hWnd, (HMENU)IDC_KM_REFRESH, hInst, NULL);
        g_hKmStatus = CreateWindowA("STATIC", "Not loaded", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    110, 16, 860, 20, hWnd, (HMENU)IDC_KM_STATUS, hInst, NULL);

        g_hKmTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | TCS_TABS,
                                  10, 46, 960, 24, hWnd, (HMENU)IDC_KM_TABS, hInst, NULL);
        for (k = 0; k < 2; k++) {
            ZeroMemory(&t, sizeof(t));
            t.mask = TCIF_TEXT;
            t.pszText = (LPSTR)(k == 0 ? "Kernel Module" : "Driver");
            SendMessageA(g_hKmTabs, TCM_INSERTITEMA, k, (LPARAM)&t);
        }
        SendMessageA(g_hKmTabs, TCM_SETCURSEL, 0, 0);

        g_hKmList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
                                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                    10, 76, 960, 500, hWnd, (HMENU)IDC_KM_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hKmList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateKmColumns(g_hKmList, 0);
        DoRefreshKernel();
        SetWindowTextA(hWnd, "XPCHunter Frontend - Kernel");
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        int w;
        GetClientRect(hWnd, &rc);
        w = rc.right - 20;
        if (w < 300) w = 300;
        if (g_hKmTabs)   MoveWindow(g_hKmTabs, 10, 46, w, 24, TRUE);
        if (g_hKmList)   MoveWindow(g_hKmList, 10, 76, w, rc.bottom - 86, TRUE);
        if (g_hKmStatus) MoveWindow(g_hKmStatus, 110, 16, w - 100, 20, TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_KM_REFRESH) {
            DoRefreshKernel();
            return 0;
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)lParam;
        if (nm->idFrom == IDC_KM_TABS && nm->code == TCN_SELCHANGE) {
            g_KmTab = (int)SendMessageA(g_hKmTabs, TCM_GETCURSEL, 0, 0);
            DoRefreshKernel();
        }
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        g_hKernel = NULL;
        g_hKmTabs = g_hKmList = g_hKmStatus = NULL;
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

static void ShowKernelWindow(HINSTANCE hInst)
{
    static BOOL registered = FALSE;

    if (g_hKernel) {
        SetForegroundWindow(g_hKernel);
        return;
    }
    if (!registered) {
        WNDCLASSA wc;
        ZeroMemory(&wc, sizeof(wc));
        wc.lpfnWndProc = KernelWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "XPCHKernel";
        if (!RegisterClassA(&wc))
            return;
        registered = TRUE;
    }
    g_hKernel = CreateWindowExA(0, "XPCHKernel", "XPCHunter Frontend - Kernel",
                                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 1000, 640,
                                NULL, NULL, hInst, NULL);
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

        /* Process 页主视图 */
        g_hProc = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA,
                                  "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  10, 70, 940, 300, hWnd, (HMENU)IDC_PROCLIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hProc, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateProcColumns(g_hProc);

        g_hProcStatus = CreateWindowA("STATIC", "Not connected", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      10, 376, 940, 20, hWnd, (HMENU)IDC_PROCSTATUS, hInst, NULL);

        /* 明细子视图：tab + 一个 ListView（列随 tab 切换） */
        g_hTabs = CreateWindowA(WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | TCS_TABS,
                                10, 400, 940, 24, hWnd, (HMENU)IDC_TABS, hInst, NULL);
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
                                    10, 424, 940, 190, hWnd, (HMENU)IDC_DETAIL, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hDetail, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        /* 命令测试器（保留：逐条命令的结果与形状） */
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA,
                                  "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  10, 402, 940, 150, hWnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateListColumns(g_hList);

        SetWindowTextA(hWnd, "XPCHunter Frontend - Process");
        /* --kernel-gui：启动即打开 Kernel 页（截图/取证用；两个子页的数据源
           都是纯用户态 API，不依赖驱动，因此无驱动时也能正常显示） */
        if (strstr(GetCommandLineA(), "--kernel-gui"))
            ShowKernelWindow(hInst);
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        int w, h;
        GetClientRect(hWnd, &rc);
        w = rc.right - 20;
        h = rc.bottom;
        if (w < 200) w = 200;
        /* Process 列表占上方；底部固定给"命令测试器"留 170px */
        /* 上：进程列表（70 .. h-500）
           中：tab（h-496） + 明细列表（h-472 .. h-280）
           下：状态栏（h-275） + 命令测试器（h-250 .. h-10） */
        if (g_hProc)
            MoveWindow(g_hProc, 10, 70, w, (h - 500) - 70, TRUE);
        if (g_hTabs)
            MoveWindow(g_hTabs, 10, h - 496, w, 24, TRUE);
        if (g_hDetail)
            MoveWindow(g_hDetail, 10, h - 472, w, 192, TRUE);
        if (g_hProcStatus)
            MoveWindow(g_hProcStatus, 10, h - 275, w, 20, TRUE);
        if (g_hList)
            MoveWindow(g_hList, 10, h - 250, w, 240, TRUE);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_CONNECT: DoConnect(); return 0;
        case IDC_REFRESH: DoRefreshProcs(); return 0;
        case IDC_SCAN:    DoScan();    return 0;
        case IDC_SEND:    DoSend();    return 0;
        case IDC_KILL:    DoKillSelected(); return 0;
        case IDC_KERNEL:  ShowKernelWindow((HINSTANCE)GetWindowLongPtrA(hWnd, GWLP_HINSTANCE)); return 0;
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)lParam;
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