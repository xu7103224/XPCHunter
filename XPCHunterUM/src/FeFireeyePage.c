// ============================================================================
// FeFireeyePage.c — Fireeye 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
FE_FIREEYE_JOB g_FeJob;

HWND g_hFePath, g_hFeList, g_hFeStatus;
int g_FeHasJob = 0;

/* ---- Fireeye 页（主 Tab 11）---- */
void FeSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoFireeyeAnalyse(void)
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

void DoFireeyeRecords(void)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Fireeye 页段，逐字保留） ---- */
void FeFireeyePagePageShow(HWND hWnd, int page)
{
int isFireeye = (page == 11);    /* 第 12 个 Tab = Fireeye */
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
    }}
