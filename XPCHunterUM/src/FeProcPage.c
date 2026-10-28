// ============================================================================
// FeProcPage.c — Proc 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
HWND g_hList;
HWND g_hCmd;
HWND g_hSize;

HWND g_hList, g_hStatus, g_hCmd, g_hSize;
HWND g_hProc, g_hProcStatus, g_hTabs, g_hDetail;
int  g_DetailTab = -1;

/* ---- 第二步增量：进程列表缓存 + 列头点击排序 + 定时自动刷新 ----
   缓存与 Items 平行保存 Ring3 可访问状态；排序在缓存索引上做，
   重绘不重查驱动。 */
FE_PROCESS_LIST g_ProcCache = { 0, 0, NULL };
unsigned char  *g_ProcAcc = NULL;
BOOL g_ProcCacheValid = FALSE;
int  g_ProcSortCol = -1;     /* -1 = 按驱动枚举序 */
int  g_ProcSortDesc = 0;
ULONG g_ProcShown = 0;       /* 过滤后实际渲染的行数 */
char g_ProcFilter[128] = ""; /* 列过滤串（空 = 不过滤） */
static BOOL g_ProcAutoOn = FALSE;

/* 大小写无关的子串查找（不用 StrStrIA，避免多引 shlwapi） */
static const char *ProcStrIStr(const char *Hay, const char *Needle)
{
    size_t nl;

    if (!Needle || !Needle[0])
        return Hay;
    nl = strlen(Needle);
    for (; *Hay; Hay++) {
        size_t k;
        for (k = 0; k < nl; k++) {
            unsigned char a = (unsigned char)Hay[k];
            unsigned char b = (unsigned char)Needle[k];
            if (!a)
                return NULL;
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b)
                break;
            if (k + 1 == nl)
                return Hay;
        }
    }
    return NULL;
}

/* 一行是否通过过滤：PID / Name / Path / EPROCESS / Ring3 状态 任一列命中即保留。
   空过滤串恒通过。 */
BOOL ProcFilterMatch(const FE_PROCESS *it, unsigned char acc, const char *filter)
{
    char pid[32], ep[32], path[FE_PROC_PATH_CHARS * 2];
    const char *state;

    if (!filter || !filter[0])
        return TRUE;

    sprintf_s(pid, sizeof(pid), "%lu", it->Pid);
    if (ProcStrIStr(pid, filter))
        return TRUE;
    if (ProcStrIStr(it->Name, filter))
        return TRUE;
    sprintf_s(ep, sizeof(ep), "%p", (void *)(ULONG_PTR)it->Eprocess);
    if (ProcStrIStr(ep, filter))
        return TRUE;
    state = acc ? "accessible" : "INACCESSIBLE";
    /* 状态列用精确匹配：'accessible' 是 'INACCESSIBLE' 的子串，
       子串匹配会让两个状态互相误命中。 */
    if (_stricmp(state, filter) == 0)
        return TRUE;
    FeWideToAnsi(it->Path, path, sizeof(path));
    if (ProcStrIStr(path, filter))
        return TRUE;
    return FALSE;
}

int ProcCmp(const void *pa, const void *pb)
{
    int a = *(const int *)pa, b = *(const int *)pb;
    const FE_PROCESS *A = &g_ProcCache.Items[a];
    const FE_PROCESS *B = &g_ProcCache.Items[b];
    int r = 0;

    switch (g_ProcSortCol) {
    case 0:   /* PID：数值序 */
        r = (A->Pid < B->Pid) ? -1 : ((A->Pid > B->Pid) ? 1 : 0);
        break;
    case 1:   /* Name：ImageFileName 可能占满 16 字节，按定长比较 */
        r = strncmp(A->Name, B->Name, sizeof(A->Name));
        break;
    case 2:   /* Path：宽字符字典序 */
        r = wcscmp(A->Path, B->Path);
        break;
    case 3:   /* EPROCESS：地址序 */
        r = (A->Eprocess < B->Eprocess) ? -1 : ((A->Eprocess > B->Eprocess) ? 1 : 0);
        break;
    case 4:   /* Ring3 Access State：accessible < INACCESSIBLE */
        r = (int)g_ProcAcc[a] - (int)g_ProcAcc[b];
        break;
    }
    if (r == 0)
        r = (a < b) ? -1 : ((a > b) ? 1 : 0);   /* 同键保持枚举序（稳定） */
    return g_ProcSortDesc ? -r : r;
}

/* 按当前过滤 + 排序生成行索引（渲染与导出共用，保证两者顺序严格一致）。
   调用方负责 free()。返回行数，失败返回 0 且 *OutOrder 置 NULL。 */
static ULONG ProcBuildOrder(int **OutOrder)
{
    int *order;
    ULONG i, n = 0, count = g_ProcCacheValid ? g_ProcCache.Count : 0;

    *OutOrder = NULL;
    if (!count)
        return 0;
    order = (int *)malloc(count * sizeof(int));
    if (!order)
        return 0;
    /* 过滤先于排序：只把命中行放进索引，qsort 的规模随之缩小 */
    for (i = 0; i < count; i++)
        if (ProcFilterMatch(&g_ProcCache.Items[i],
                            g_ProcAcc ? g_ProcAcc[i] : 0, g_ProcFilter))
            order[n++] = (int)i;
    if (g_ProcSortCol >= 0 && n > 1)
        qsort(order, n, sizeof(int), ProcCmp);
    *OutOrder = order;
    return n;
}

/* 按当前过滤 + 排序把缓存渲染进列表（列文本逻辑与原实现一致） */
static void ProcRenderRows(void)
{
    int *order;
    ULONG i, n;

    SendMessageA(g_hProc, LVM_DELETEALLITEMS, 0, 0);
    g_ProcShown = 0;
    n = ProcBuildOrder(&order);
    if (!n || !order)
        return;

    for (i = 0; i < n; i++) {
        FE_PROCESS *it = &g_ProcCache.Items[order[i]];
        LVITEMA item;
        char buf[256];
        char path[FE_PROC_PATH_CHARS * 2];

        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;
        sprintf_s(buf, sizeof(buf), "%lu", it->Pid);
        item.pszText = buf;
        SendMessageA(g_hProc, LVM_INSERTITEMA, 0, (LPARAM)&item);

        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 1;
        item.pszText = it->Name[0] ? it->Name : (LPSTR)"(?)";
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);

        FeWideToAnsi(it->Path, path, sizeof(path));
        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 2;
        item.pszText = path;
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);

        sprintf_s(buf, sizeof(buf), "%p", (void *)(ULONG_PTR)it->Eprocess);
        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 3;
        item.pszText = buf;
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);

        ZeroMemory(&item, sizeof(item));
        item.iSubItem = 4;
        item.pszText = g_ProcAcc && g_ProcAcc[order[i]] ? (LPSTR)"accessible" : (LPSTR)"INACCESSIBLE";
        SendMessageA(g_hProc, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&item);
    }
    g_ProcShown = n;
    free(order);
}

/* 过滤串变更（EN_CHANGE 或按钮触发）：重新渲染，状态行同步显示命中数 */
void FeProcPageSetFilter(const char *filter)
{
    ULONG total = g_ProcCacheValid ? g_ProcCache.Count : 0;
    char buf[256];

    if (!filter)
        filter = "";
    strncpy_s(g_ProcFilter, sizeof(g_ProcFilter), filter, _TRUNCATE);

    if (!g_ProcCacheValid)
        return;   /* 还没刷过，等 DoRefreshProcs 时生效 */
    ProcRenderRows();
    if (g_ProcShown == total)
        sprintf_s(buf, sizeof(buf), "Processes: %lu", total);
    else
        sprintf_s(buf, sizeof(buf), "Processes: %lu (filter \"%s\" matched %lu)",
                  total, g_ProcFilter, g_ProcShown);
    SetWindowTextA(g_hProcStatus, buf);
}

/* ---- 第二步增量4：双击下钻 ----
   双击进程行 = "我要看这个进程的细节"：按当前子 Tab（模块/线程/窗口/句柄/
   内存/定时器/热键）重查该 PID 的数据源并填进详情列表，然后把焦点移过去，
   让键盘导航可以接着在被下钻的列表里走。
   数据源就是 DoRefreshDetail 用的那套 FeLoadXxx，不新增查询路径。 */
BOOL FeProcPageDrillDown(void)
{
    static const char *kViewNames[7] = {
        "Modules", "Threads", "Windows", "Handles", "Memory", "Timer", "HotKey"
    };
    ULONG pid;
    int sel, tab;
    char msg[256];

    if (!g_hProc || !g_hDetail || !g_hTabs)
        return FALSE;
    sel = ListView_GetNextItem(g_hProc, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hProcStatus, "Double-click a process row to drill down");
        return FALSE;
    }
    pid = GetSelectedPid();
    if (!pid)
        return FALSE;

    /* 子 Tab 越界时归到 Modules，避免详情区空转 */
    tab = (int)SendMessageA(g_hTabs, TCM_GETCURSEL, 0, 0);
    if (tab < 0 || tab > 6) {
        SendMessageA(g_hTabs, TCM_SETCURSEL, 0, 0);
        tab = 0;
    }
    /* 强制重建列：下钻时子视图必须是"当前 Tab + 当前 PID"的确定状态，
       即使 g_DetailTab 没变也重设一次，避免残留上一个 PID 的列宽/列集 */
    g_DetailTab = -1;

    DoRefreshDetail();
    SetFocus(g_hDetail);

    {
        int rows = (int)SendMessageA(g_hDetail, LVM_GETITEMCOUNT, 0, 0);
        if (rows > 0)
            ListView_SetItemState(g_hDetail, 0, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
        sprintf_s(msg, sizeof(msg),
                  "Drill-down: PID %lu, %s view - %d row%s (focus in detail)",
                  pid, kViewNames[tab], rows, rows == 1 ? "" : "s");
        SetWindowTextA(g_hProcStatus, msg);
    }
    return TRUE;
}

/* 列头点击：同列再点反向，异列重新升序；缓存为空时忽略 */
void FeProcPageOnColumnClick(int col)
{
    if (col < 0 || col > 4)
        return;
    if (!g_ProcCacheValid || !g_ProcCache.Count)
        return;
    if (col == g_ProcSortCol)
        g_ProcSortDesc = !g_ProcSortDesc;
    else {
        g_ProcSortCol = col;
        g_ProcSortDesc = 0;
    }
    ProcRenderRows();
}

/* ---- 第二步增量3：导出当前可见行（过滤 + 排序后）为 CSV ----
   与 ProcRenderRows 共用 ProcBuildOrder，保证导出顺序与屏幕所见完全一致。
   CSV 转义按 RFC 4180：含逗号/引号/换行的字段用双引号包裹，内部引号翻倍。 */
static void CsvQuote(FILE *fp, const char *s)
{
    BOOL need = FALSE;
    const char *p;

    if (!s)
        s = "";
    for (p = s; *p; p++)
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            need = TRUE;
            break;
        }
    if (!need) {
        fputs(s, fp);
        return;
    }
    fputc('"', fp);
    for (p = s; *p; p++) {
        if (*p == '"')
            fputc('"', fp);   /* 引号翻倍 */
        fputc(*p, fp);
    }
    fputc('"', fp);
}

BOOL FeProcPageExportCsv(const char *Path, ULONG *OutRows)
{
    FILE *fp;
    int *order;
    ULONG i, n;

    if (OutRows)
        *OutRows = 0;
    if (!Path || !Path[0])
        return FALSE;
    if (!g_ProcCacheValid || !g_ProcCache.Count)
        return FALSE;

    n = ProcBuildOrder(&order);
    if (!order)
        return FALSE;

    /* 带 BOM 的 UTF-8：Excel 双击打开不会把中文路径变成乱码。
       ANSI 路径转换失败也照写（纯 ASCII 数据仍可读）。 */
    if (fopen_s(&fp, Path, "wb") != 0 || !fp) {
        free(order);
        return FALSE;
    }
    fputs("\xEF\xBB\xBF", fp);
    fputs("PID,Name,Path,EPROCESS,Ring3AccessState\r\n", fp);
    for (i = 0; i < n; i++) {
        const FE_PROCESS *it = &g_ProcCache.Items[order[i]];
        char num[32];
        char path[FE_PROC_PATH_CHARS * 2];

        fprintf(fp, "%lu,", it->Pid);
        CsvQuote(fp, it->Name[0] ? it->Name : "(?)");
        fputc(',', fp);
        FeWideToAnsi(it->Path, path, sizeof(path));
        CsvQuote(fp, path);
        fputc(',', fp);
        sprintf_s(num, sizeof(num), "%p", (void *)(ULONG_PTR)it->Eprocess);
        fputs(num, fp);
        fprintf(fp, ",%s\r\n",
                (g_ProcAcc && g_ProcAcc[order[i]]) ? "accessible" : "INACCESSIBLE");
    }
    fclose(fp);
    free(order);
    if (OutRows)
        *OutRows = n;
    return TRUE;
}

/* 导出按钮：写 %TEMP%\PCHunter_Processes.csv，状态行回报路径与行数 */
void FeProcPageExport(void)
{
    char path[MAX_PATH];
    ULONG rows = 0;
    char msg[600];

    if (!g_ProcCacheValid || !g_ProcCache.Count) {
        SetWindowTextA(g_hProcStatus, "Nothing to export - refresh the process list first");
        return;
    }
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, sizeof(path), "PCHunter_Processes.csv");
    if (FeProcPageExportCsv(path, &rows)) {
        sprintf_s(msg, sizeof(msg),
                  "Exported %lu row%s%s to %s",
                  rows, rows == 1 ? "" : "s",
                  g_ProcFilter[0] ? " (filtered)" : "", path);
        SetWindowTextA(g_hProcStatus, msg);
    } else {
        SetWindowTextA(g_hProcStatus, "Export failed");
    }
}

/* Auto Refresh 开关：共享 WM_TIMER（FE_AUTOREF_TIMER_ID），2s 周期 */
void FeProcPageToggleAuto(HWND hWnd)
{
    HWND hAuto = GetDlgItem(hWnd, IDC_PROC_AUTO);

    if (!g_ProcAutoOn) {
        g_AutoRefFn = DoRefreshProcs;
        SetTimer(hWnd, FE_AUTOREF_TIMER_ID, 2000, NULL);
        g_ProcAutoOn = TRUE;
        if (hAuto)
            SetWindowTextA(hAuto, "Auto Refresh: ON (2s)");
    } else {
        KillTimer(hWnd, FE_AUTOREF_TIMER_ID);
        g_AutoRefFn = NULL;
        g_ProcAutoOn = FALSE;
        if (hAuto)
            SetWindowTextA(hAuto, "Auto Refresh: OFF");
    }
}

void CreateProcColumns(HWND h)
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

void DetailSetText(int row, int sub, const char *text)
{
    LVITEMA item;
    ZeroMemory(&item, sizeof(item));
    item.iSubItem = sub;
    item.pszText = (LPSTR)text;
    SendMessageA(g_hDetail, LVM_SETITEMTEXTA, (WPARAM)row, (LPARAM)&item);
}

void DetailAddRow(const char *c0, const char *c1, const char *c2, const char *c3)
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

void SetupDetailColumns(int tab)
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

void DoRefreshDetail(void)
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

void DoKillSelected(void)
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

void DoRefreshProcs(void)
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

    /* 第二步增量：列表整体移入缓存（排序/自动刷新的重绘不再重查驱动），
       Ring3 可访问性按本次枚举缓存。 */
    if (g_ProcCacheValid)
        FeFreeProcessList(&g_ProcCache);
    if (g_ProcAcc) {
        free(g_ProcAcc);
        g_ProcAcc = NULL;
    }
    g_ProcCache = list;
    g_ProcCacheValid = TRUE;
    count = g_ProcCache.Count;
    g_ProcAcc = (unsigned char *)malloc(count ? count : 1);
    if (g_ProcAcc)
        for (i = 0; i < count; i++)
            g_ProcAcc[i] = FeIsProcessRing3Accessible(g_ProcCache.Items[i].Pid) ? 1 : 0;

    /* 完整映像路径：QueryFullProcessImageNameW（不走驱动 0x2A —— 它的
       KeStackAttachProcess 手工追链会让 guest 挂死，已记录待修）。
       路径在刷新时一次性解析进缓存，排序重绘不再重复查询。 */
    for (i = 0; i < count; i++)
        if (!FeLoadProcessPathWin32(g_ProcCache.Items[i].Pid, g_ProcCache.Items[i].Path, FE_PROC_PATH_CHARS))
            g_ProcCache.Items[i].Path[0] = 0;

    ProcRenderRows();

    {
        ULONG hidden = 0, inaccessible = 0;
        if (FeComputeProcessStatus(&g_ProcCache, &hidden, &inaccessible, NULL)) {
            sprintf_s(buf, sizeof(buf),
                      "Processes: %lu, Hidden Processes: %lu, "
                      "Ring3 Inaccessible Processes: %lu",
                      count, hidden, inaccessible);
            if (g_ProcFilter[0])
                sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf),
                          "  (filter \"%s\" matched %lu)", g_ProcFilter, g_ProcShown);
            SetWindowTextA(g_hProcStatus, buf);
            return;
        }
    }

    if (g_ProcFilter[0])
        sprintf_s(buf, sizeof(buf), "Processes: %lu (filter \"%s\" matched %lu)",
                  count, g_ProcFilter, g_ProcShown);
    else
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

/* 进程右键操作：Kill / Force Kill / Suspend / Resume / Kill By Process Tree /
 * Kill And Delete File / Copy Image Path。 */
void DoProcessOp(int Op)
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

void DoProcessContextMenu(HWND hWnd, int X, int Y)
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
ULONG64 DetailColumnQword(int Sel, int Sub)
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

BOOL DetailColumnText(int Sel, int Sub, char *Out, int OutChars)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Proc 页段，逐字保留） ---- */
void FeProcPagePageShow(HWND hWnd, int page)
{
    HWND hKill, hRef;

int isProc = (page == 0);
    if (g_hProc)       ShowWindow(g_hProc,       isProc ? SW_SHOW : SW_HIDE);
    if (g_hProcStatus) ShowWindow(g_hProcStatus, isProc ? SW_SHOW : SW_HIDE);
    if (g_hTabs)       ShowWindow(g_hTabs,       isProc ? SW_SHOW : SW_HIDE);
    if (g_hDetail)     ShowWindow(g_hDetail,     isProc ? SW_SHOW : SW_HIDE);
    if (g_hList)       ShowWindow(g_hList,       isProc ? SW_SHOW : SW_HIDE);
    hKill = GetDlgItem(hWnd, IDC_KILL);
    if (hKill) ShowWindow(hKill, isProc ? SW_SHOW : SW_HIDE);
    /* 第二步增量：Auto Refresh 开关只属于 Process 页 */
    {
        HWND hAuto = GetDlgItem(hWnd, IDC_PROC_AUTO);
        if (hAuto) ShowWindow(hAuto, isProc ? SW_SHOW : SW_HIDE);
    }
    /* 第二步增量2：列过滤框同理 */
    if (g_hProcFilter) ShowWindow(g_hProcFilter, isProc ? SW_SHOW : SW_HIDE);
    /* 第二步增量3：导出按钮只属于本页 */
    {
        HWND hExp = GetDlgItem(hWnd, IDC_PROC_EXPORT);
        if (hExp) ShowWindow(hExp, isProc ? SW_SHOW : SW_HIDE);
    }
    if (isProc) {
        RECT rc;
        GetClientRect(hWnd, &rc);
        SendMessageA(hWnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));
    }
}
