// ============================================================================
// FeTrojanPage.c — Trojan 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
FE_TROJAN_REPORT g_TrReport;

HWND g_hTrList, g_hTrStatus;
int g_TrLoaded = 0;

/* ---- Trojan Detection 页（主 Tab 12）---- */
void TrSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoTrojanScan(void)
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

void DoTrojanBackup(void)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Trojan 页段，逐字保留） ---- */
void FeTrojanPagePageShow(HWND hWnd, int page)
{
int isTrojan = (page == 12);     /* 第 13 个 Tab = Trojan Detection */
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
    }}
