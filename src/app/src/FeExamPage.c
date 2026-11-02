// ============================================================================
// FeExamPage.c — Exam 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
FE_EXAM_RESULT g_ExamResult;

HWND g_hExList, g_hExStatus;
int g_ExamLoaded = 0;
/* 2026-10-29：Hide safe items 勾选（原版 "隐藏明显安全项"）。
   打开时只渲染 WARN/RISK，INFO 项隐藏。 */
BOOL g_ExamHideSafe = FALSE;

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

    {
        int row = 0;
        for (i = 0; i < g_ExamResult.Count; i++) {
            LVITEMA it;
            const char *sev = g_ExamResult.Items[i].Severity == 0 ? "INFO" :
                              g_ExamResult.Items[i].Severity == 1 ? "WARN" : "RISK";
            /* 2026-10-29 Hide safe items：隐藏 INFO 项 */
            if (g_ExamHideSafe && g_ExamResult.Items[i].Severity == 0)
                continue;
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = (LPSTR)sev;
            SendMessageA(g_hExList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            ExSetText(g_hExList, row, 1, g_ExamResult.Items[i].Title);
            ExSetText(g_hExList, row, 2, g_ExamResult.Items[i].Detail);
            row++;
        }
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
/* ============================================================================
 * 2026-10-29 新增：体检页右键菜单（原版 6 项，见 右键菜单差距分析）
 *
 *   Hide safe items                       隐藏明显安全项    [已补全]  ← 勾选过滤
 *   Generate examination report           生成检测报告      [已补全]
 *   Terminate generating examination report 终止生成检测报告 [已补全]
 *   Export examination report             导出检测报告      [已补全]
 *   Go to this item                       定位到该项目      [已补全]
 *   Go to the top                         定位到顶部        [已补全]
 * ==========================================================================*/

#define EX_MENU_BASE   10000
#define EX_ID_HIDE_SAFE   (EX_MENU_BASE + 1)
#define EX_ID_GENERATE    (EX_MENU_BASE + 2)
#define EX_ID_TERMINATE   (EX_MENU_BASE + 3)
#define EX_ID_EXPORT      (EX_MENU_BASE + 4)
#define EX_ID_GOTO_ITEM   (EX_MENU_BASE + 5)
#define EX_ID_GOTO_TOP    (EX_MENU_BASE + 6)
#define EX_ID_REFRESH     (EX_MENU_BASE + 7)

/* Generate：重跑一次体检（原版会显示进度并可终止） */
static void ExGenerate(void)
{
    FeExamResetCancel();
    DoRefreshExamination();
    if (g_hExStatus) {
        char msg[400];
        sprintf_s(msg, sizeof(msg),
                  "Generate examination report: %lu items (risk %lu, warn %lu, info %lu)",
                  g_ExamResult.Count, g_ExamResult.RiskCount,
                  g_ExamResult.WarnCount, g_ExamResult.InfoCount);
        SetWindowTextA(g_hExStatus, msg);
    }
}

/* Terminate：置取消标志（FeRunExamination 内部逐项检查 FeExamIsCancelled） */
static void ExTerminate(void)
{
    FeExamCancel();
    if (g_hExStatus)
        SetWindowTextA(g_hExStatus,
                       "Terminate examination: cancel flag set; running scan will stop "
                       "at the next check point");
}

void DoExaminationContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    UINT cmd;
    int sel;

    FeListSelectUnderCursor(g_hExList, X, Y);
    sel = FeListGetSel(g_hExList);

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAddCheck(hMenu, EX_ID_HIDE_SAFE, "Hide safe items", g_ExamHideSafe);  /* 隐藏明显安全项 */
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, EX_ID_GENERATE, "Generate examination report");            /* 生成检测报告 */
    FeMenuAddEx(hMenu, EX_ID_TERMINATE, "Terminate generating examination report", g_ExamLoaded);
    FeMenuAddEx(hMenu, EX_ID_EXPORT, "Export examination report", g_ExamLoaded); /* 导出检测报告 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, EX_ID_GOTO_ITEM, "Go to this item", sel >= 0);            /* 定位到该项目 */
    FeMenuAdd(hMenu, EX_ID_GOTO_TOP, "Go to the top");                          /* 定位到顶部 */
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, EX_ID_REFRESH, "Refresh");                                 /* 我方补充：刷新 */

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case EX_ID_HIDE_SAFE:
        g_ExamHideSafe = !g_ExamHideSafe;
        if (g_ExamLoaded)
            DoRefreshExamination();
        break;
    case EX_ID_GENERATE:
        ExGenerate();
        break;
    case EX_ID_TERMINATE:
        ExTerminate();
        break;
    case EX_ID_EXPORT:
        DoExportExamination();
        break;
    case EX_ID_GOTO_ITEM:
        if (sel >= 0) {
            ListView_EnsureVisible(g_hExList, sel, FALSE);
            {
                char title[128], msg[300];
                FeListGetCellText(g_hExList, sel, 1, title, sizeof(title));
                sprintf_s(msg, sizeof(msg), "Go to this item: row %d - %s", sel, title);
                SetWindowTextA(g_hExStatus, msg);
            }
        }
        break;
    case EX_ID_GOTO_TOP:
        if (FeListGetCount(g_hExList) > 0) {
            ListView_EnsureVisible(g_hExList, 0, FALSE);
            ListView_SetItemState(g_hExList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(g_hExList, 0, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            SetWindowTextA(g_hExStatus, "Go to the top: moved to first row");
        }
        break;
    case EX_ID_REFRESH:
        DoRefreshExamination();
        break;
    default:
        break;
    }
}