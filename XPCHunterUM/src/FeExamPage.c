// ============================================================================
// FeExamPage.c — Exam 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
FE_EXAM_RESULT g_ExamResult;

HWND g_hExList, g_hExStatus;
int g_ExamLoaded = 0;

/* ---- Examination 页（主 Tab 9）---- */
void ExSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoRefreshExamination(void)
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

void DoExportExamination(void)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Exam 页段，逐字保留） ---- */
void FeExamPagePageShow(HWND hWnd, int page)
{
int isExam = (page == 9);        /* 第 10 个 Tab = Examination */
    if (g_hExList)   ShowWindow(g_hExList,   isExam ? SW_SHOW : SW_HIDE);
    if (g_hExStatus) ShowWindow(g_hExStatus, isExam ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_EX_RUN);
        HWND h2 = GetDlgItem(hWnd, IDC_EX_CANCEL);
        HWND h3 = GetDlgItem(hWnd, IDC_EX_EXPORT);
        if (h1) ShowWindow(h1, isExam ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isExam ? SW_SHOW : SW_HIDE);
        if (h3) ShowWindow(h3, isExam ? SW_SHOW : SW_HIDE);
    }}
