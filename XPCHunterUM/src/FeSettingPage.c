// ============================================================================
// FeSettingPage.c — Setting 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
FE_OBJ_TYPES g_StObjTypes;

HWND g_hStList, g_hStStatus;
int g_StObjReady = 0;

/* ---- Setting 页（主 Tab 10）----
 * 三项可用 Forbid（对应已确认的 IoFile/Driver/DeviceObjectType）
 * + 四项标注"未定位对象类型"
 * + 两项自保护（占位，需 0xD2/0xD3 的 21712 字节输出）
 * + 托盘最小化开关 */
void StSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoRefreshSetting(void)
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

void DoApplyForbid(int Which)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Setting 页段，逐字保留） ---- */
void FeSettingPagePageShow(HWND hWnd, int page)
{
int isSetting = (page == 10);    /* 第 11 个 Tab = Setting */
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
    }}
