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

static XPCH_CLIENT g_Client;
static HWND g_hList, g_hStatus, g_hCmd, g_hSize;
static HWND g_hProc, g_hProcStatus;

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
        /* 上：Process 列表（70 .. h-240）
           中：状态栏（h-235 .. h-215）
           下：命令测试器（h-210 .. h-10） */
        if (g_hProc)
            MoveWindow(g_hProc, 10, 70, w, (h - 240) - 70, TRUE);
        if (g_hProcStatus)
            MoveWindow(g_hProcStatus, 10, h - 235, w, 20, TRUE);
        if (g_hList)
            MoveWindow(g_hList, 10, h - 210, w, 200, TRUE);
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
                         1000, 760, NULL, NULL, hInst, NULL);
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