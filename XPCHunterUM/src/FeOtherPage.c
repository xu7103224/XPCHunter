// ============================================================================
// FeOtherPage.c — Other 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hOtList, g_hOtStatus, g_hOtPath;

/* ---- Other 页（主 Tab 13）---- */
void OtAddRow(const char *k, const char *v)
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

void DoRefreshOther(void)
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

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Other 页段，逐字保留） ---- */
void FeOtherPagePageShow(HWND hWnd, int page)
{
int isOther = (page == 13);      /* 第 14 个 Tab = Other */
    if (g_hOtList)   ShowWindow(g_hOtList,   isOther ? SW_SHOW : SW_HIDE);
    if (g_hOtStatus) ShowWindow(g_hOtStatus, isOther ? SW_SHOW : SW_HIDE);
    if (g_hOtPath)   ShowWindow(g_hOtPath,   isOther ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_OT_VERIFY);
        HWND h2 = GetDlgItem(hWnd, IDC_OT_QUERY);
        if (h1) ShowWindow(h1, isOther ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isOther ? SW_SHOW : SW_HIDE);
    }}
