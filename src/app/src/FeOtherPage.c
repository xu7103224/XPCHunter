// ============================================================================
// FeOtherPage.c — Other 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
extern int g_FeSysViewSilent;

HWND g_hOtList, g_hOtStatus, g_hOtPath;

/* ---- Other 页（主 Tab 13）---- */
void OtAddRow(const char *k, const char *v)
{
    LVITEMA it;
    int i;

    /* 自检（--selftest-sysviews-cli）时列表尚未创建，直接忽略即可；
       数据源的正确性由各自的返回值体现。 */
    if (!g_hOtList)
        return;
    if (g_FeSysViewSilent)
        return;
    i = ListView_GetItemCount(g_hOtList);
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

    /* 2026-10-29：追加系统类视图（用户账户 / 输入法 / 系统解锁 / WDF 驱动）
       —— 对应 功能差距分析 §2.8 的 CUserNameDialog / CImeDialog /
       CSystemUnlockDialog / CWdfDialog 四项。 */
    OtAddRow("", "");
    {
        ULONG users = FeLoadUserAccounts();
        char line[128];
        sprintf_s(line, sizeof(line), "--- User Accounts (%lu) ---", users);
        OtAddRow(line, "");
    }
    {
        ULONG imes = FeLoadInputMethods();
        char line[128];
        sprintf_s(line, sizeof(line), "--- Input Methods (%lu) ---", imes);
        OtAddRow(line, "");
    }
    {
        ULONG locked = FeLoadLockedSystemPaths();
        char line[128];
        sprintf_s(line, sizeof(line), "--- Locked System Paths (%lu) ---", locked);
        OtAddRow(line, "");
    }
    {
        ULONG wdf = FeLoadWdfDrivers();
        char line[128];
        sprintf_s(line, sizeof(line), "--- WDF Drivers (%lu) ---", wdf);
        OtAddRow(line, "");
    }
}


/* Query Online — 用路径框里输入的文件的 SHA-256 打开 VirusTotal 查询页。
 *
 * 【2026-10-30 补】"Query Online" 按钮此前只有控件、没有 WM_COMMAND 处理
 * （frontend.c 里只有 IDC_OT_VERIFY），点击无反应。原版 Other 页有
 * 「在线查询（百度、virscan）」这一组。
 *
 * 实现取舍：按**文件哈希**查比按文件名查准得多（同名文件遍地都是），
 * 所以先对路径框里的文件算 SHA-256，再拼 VirusTotal 的 file/<hash> URL。
 * 文件不存在或算不出哈希时，退化为按文件名做 Bing 搜索。 */
void DoOtherQueryOnline(void)
{
    char path[MAX_PATH * 2];
    char hash[80] = { 0 };
    char url[1024];
    char msg[MAX_PATH * 2 + 200];

    if (!g_hOtPath) {
        return;
    }
    GetWindowTextA(g_hOtPath, path, sizeof(path));
    if (!path[0]) {
        SetWindowTextA(g_hOtStatus, "Query Online: enter a file path first");
        return;
    }

    if (FeHashFile(path, CALG_SHA_256, hash, sizeof(hash)) && hash[0]) {
        sprintf_s(url, sizeof(url),
                  "https://www.virustotal.com/gui/file/%s", hash);
        ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
        sprintf_s(msg, sizeof(msg), "Query Online: opened VirusTotal for SHA256=%s", hash);
    } else {
        /* 文件不可读时按文件名搜；取最后一段路径作为关键词 */
        const char *base = path;
        const char *p = path;
        while (*p) { if (*p == '\\' || *p == '/') base = p + 1; p++; }
        sprintf_s(url, sizeof(url), "https://www.bing.com/search?q=%s", base);
        ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
        sprintf_s(msg, sizeof(msg),
                  "Query Online: cannot hash \"%s\" (missing or no access), searched by name instead",
                  path);
    }
    SetWindowTextA(g_hOtStatus, msg);
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
