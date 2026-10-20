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

static XPCH_CLIENT g_Client;
static HWND g_hList, g_hStatus, g_hCmd, g_hSize;
static HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
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

    /* 子视图调试入口：--memory-cli <pid> */
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