// ============================================================================
// FeFilePage.c — File 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hFlDir, g_hFlList, g_hFlStatus;

/* ---- File 页（主 Tab 8）---- */
void FlSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateFlColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Name";       c.cx = 300; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "Size";       c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "Attr";       c.cx = 80;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "Flags";      c.cx = 150; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    c.pszText = "Path";       c.cx = 500; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
}

void DoRefreshFiles(void)
{
    FE_FILE_LIST list;
    char dir[MAX_PATH];
    char status[256];
    ULONG i;

    if (!g_hFlList || !g_hFlStatus || !g_hFlDir)
        return;
    GetWindowTextA(g_hFlDir, dir, sizeof(dir));
    if (!dir[0])
        strcpy_s(dir, sizeof(dir), "C:\Windows\System32");

    ListView_DeleteAllItems(g_hFlList);
    CreateFlColumns(g_hFlList);

    if (!FeLoadDirectory(dir, &list)) {
        sprintf_s(status, sizeof(status), "Files: cannot open \"%s\", GetLastError=%lu",
                  dir, GetLastError());
        SetWindowTextA(g_hFlStatus, status);
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        char sz[32], attr[32], flags[128], name[FE_FILE_NAME_CHARS + 4];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        /* Rootkit 可疑项按原版样式加括号 */
        if (list.Items[i].Suspect)
            sprintf_s(name, sizeof(name), "(%s)", list.Items[i].Name);
        else
            strcpy_s(name, sizeof(name), list.Items[i].Name);
        it.pszText = name;
        SendMessageA(g_hFlList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(sz, sizeof(sz), "%I64u", list.Items[i].Size);
        sprintf_s(attr, sizeof(attr), "0x%lX", list.Items[i].Attributes);
        flags[0] = 0;
        if (list.Items[i].DeletePending)
            strcat_s(flags, sizeof(flags), "DELETE-PENDING ");
        if (list.Items[i].LockedCount) {
            char lk[64];
            sprintf_s(lk, sizeof(lk), "LOCKED(pid=%lu) ", list.Items[i].LockOwners[0]);
            strcat_s(flags, sizeof(flags), lk);
        }
        FlSetText(g_hFlList, (int)i, 1, sz);
        FlSetText(g_hFlList, (int)i, 2, attr);
        FlSetText(g_hFlList, (int)i, 3, flags);
        FlSetText(g_hFlList, (int)i, 4, list.Items[i].Path);
    }
    sprintf_s(status, sizeof(status),
              "%s: %lu files  (suspect: %lu, delete-pending: %lu, locked: %lu)",
              dir, list.Count, list.HiddenCount, list.PendingCount, list.LockedCount);
    SetWindowTextA(g_hFlStatus, status);
    FeFreeDirectory(&list);
}

/* ============================================================================
 * 2026-10-29 新增：File 页右键菜单（对齐原版，§2.7 补全）
 *
 *   Refresh                  刷新                [已补全]
 *   Search File              搜索文件             [已补全]
 *   File MD5                 文件哈希             [已补全]
 *   File Association         文件关联             [已补全]
 *   Rename File              重命名文件           [已补全]
 *   Move Pending (view)      查看挂起操作          [已补全]
 *   Pending Delete On Reboot 重启时删除           [已补全]
 *   Pending Rename On Reboot 重启时改名           [已补全]
 *   Copy Name / Copy Path / Locate / Export       [已补全]
 *   File Locker              文件解锁             [未补全-需驱动]
 * ==========================================================================*/

#define FL_MENU_BASE       10800
#define FL_ID_REFRESH       (FL_MENU_BASE + 1)
#define FL_ID_SEARCH        (FL_MENU_BASE + 2)
#define FL_ID_MD5           (FL_MENU_BASE + 3)
#define FL_ID_ASSOC         (FL_MENU_BASE + 4)
#define FL_ID_PENDING       (FL_MENU_BASE + 5)
#define FL_ID_RENAME        (FL_MENU_BASE + 6)
#define FL_ID_PEND_DELETE   (FL_MENU_BASE + 7)
#define FL_ID_PEND_RENAME   (FL_MENU_BASE + 8)
#define FL_ID_COPY_PATH     (FL_MENU_BASE + 9)
#define FL_ID_COPY_NAME     (FL_MENU_BASE + 10)
#define FL_ID_LOCATE        (FL_MENU_BASE + 11)
#define FL_ID_EXPORT        (FL_MENU_BASE + 12)
#define FL_ID_LOCKER        (FL_MENU_BASE + 13)

/* 取选中行的 Path 列（第 4 列） */
static BOOL FlSelectedPath(char *Out, int OutChars)
{
    int sel = FeListGetSel(g_hFlList);
    if (sel < 0) {
        if (Out && OutChars > 0) Out[0] = 0;
        return FALSE;
    }
    return FeListGetCellText(g_hFlList, sel, 4, Out, OutChars);
}

/* 搜索：用搜索结果替换当前列表内容 */
static void DoFileSearch(void)
{
    char dir[MAX_PATH * 2], pattern[128];
    int depth = 6;
    ULONG64 minSize = 0;
    ULONG hits, i;
    char status[700];

    dir[0] = 0;
    if (g_hFlDir)
        GetWindowTextA(g_hFlDir, dir, sizeof(dir));
    if (!FeFileSearchDialog(g_hMainWnd, dir, sizeof(dir), pattern, sizeof(pattern),
                            &depth, &minSize))
        return;

    if (g_hFlStatus) SetWindowTextA(g_hFlStatus, "Search File: scanning...");
    UpdateWindow(g_hFlStatus);
    hits = FeSearchFiles(dir, pattern, depth, minSize, NULL);

    ListView_DeleteAllItems(g_hFlList);
    CreateFlColumns(g_hFlList);
    for (i = 0; i < hits; i++) {
        ULONG64 sz = 0;
        DWORD attr = 0;
        const char *path = FeSearchFileAt(i, &sz, &attr);
        LVITEMA it;
        char szText[32], attrText[32], name[600];
        const char *leaf;

        if (!path)
            break;
        leaf = strrchr(path, '\\');
        strncpy_s(name, sizeof(name), leaf ? leaf + 1 : path, _TRUNCATE);
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = name;
        SendMessageA(g_hFlList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(szText, sizeof(szText), "%I64u", sz);
        sprintf_s(attrText, sizeof(attrText), "0x%lX", (unsigned long)attr);
        FlSetText(g_hFlList, (int)i, 1, szText);
        FlSetText(g_hFlList, (int)i, 2, attrText);
        FlSetText(g_hFlList, (int)i, 3, "");
        FlSetText(g_hFlList, (int)i, 4, path);
    }
    sprintf_s(status, sizeof(status),
              "Search File: %lu hit(s) in \"%s\" (%s, depth %d)", hits, dir, pattern, depth);
    SetWindowTextA(g_hFlStatus, status);
}

void DoFileContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    UINT cmd;
    int sel;
    char path[MAX_PATH * 2];

    FeListSelectUnderCursor(g_hFlList, X, Y);
    sel = FeListGetSel(g_hFlList);
    FlSelectedPath(path, sizeof(path));

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, FL_ID_REFRESH, "Refresh");
    FeMenuAdd(hMenu, FL_ID_SEARCH, "Search File");
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, FL_ID_MD5, "File MD5", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_ASSOC, "File Association", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_RENAME, "Rename File", sel >= 0);
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, FL_ID_PENDING, "Move Pending (view)");
    FeMenuAddEx(hMenu, FL_ID_PEND_DELETE, "Pending Delete On Reboot", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_PEND_RENAME, "Pending Rename On Reboot", sel >= 0);
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, FL_ID_COPY_NAME, "Copy Name", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_COPY_PATH, "Copy Path", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_LOCATE, "Locate in Explorer", sel >= 0);
    FeMenuAdd(hMenu, FL_ID_EXPORT, "Export Display");
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, FL_ID_LOCKER, "File Locker (needs driver)", FALSE);

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case FL_ID_REFRESH:
        DoRefreshFiles();
        break;
    case FL_ID_SEARCH:
        DoFileSearch();
        break;
    case FL_ID_MD5:
        FeFileHashView(hWnd, path);
        break;
    case FL_ID_ASSOC:
        FeFileAssociationView(hWnd, path);
        break;
    case FL_ID_PENDING:
        FeFilePendingView(hWnd);
        break;
    case FL_ID_RENAME: {
        char newPath[MAX_PATH * 2];
        if (!path[0])
            break;
        strcpy_s(newPath, sizeof(newPath), path);
        if (DoPromptText(hWnd, "Rename File", "New full path:", newPath, sizeof(newPath))) {
            char msg[1400];
            if (FeRenameFileNow(path, newPath)) {
                sprintf_s(msg, sizeof(msg), "Rename File: OK  %s -> %s", path, newPath);
                DoRefreshFiles();
            } else {
                sprintf_s(msg, sizeof(msg), "Rename File: failed (err=%lu)", GetLastError());
            }
            SetWindowTextA(g_hFlStatus, msg);
        }
        break;
    }
    case FL_ID_PEND_DELETE: {
        char msg[1400];
        if (!path[0])
            break;
        if (!FeConfirmDanger(hWnd, "Pending Delete On Reboot", path))
            break;
        if (FeScheduleDeleteOnReboot(path))
            sprintf_s(msg, sizeof(msg), "Pending Delete: scheduled for next reboot: %s", path);
        else
            sprintf_s(msg, sizeof(msg), "Pending Delete: failed (err=%lu, need admin)",
                      GetLastError());
        SetWindowTextA(g_hFlStatus, msg);
        break;
    }
    case FL_ID_PEND_RENAME: {
        char newPath[MAX_PATH * 2];
        char msg[1400];
        if (!path[0])
            break;
        strcpy_s(newPath, sizeof(newPath), path);
        if (!DoPromptText(hWnd, "Pending Rename On Reboot", "New full path:", newPath,
                          sizeof(newPath)))
            break;
        if (!FeConfirmDanger(hWnd, "Pending Rename On Reboot", newPath))
            break;
        if (FeScheduleRenameOnReboot(path, newPath))
            sprintf_s(msg, sizeof(msg), "Pending Rename: scheduled for next reboot");
        else
            sprintf_s(msg, sizeof(msg), "Pending Rename: failed (err=%lu, need admin)",
                      GetLastError());
        SetWindowTextA(g_hFlStatus, msg);
        break;
    }
    case FL_ID_COPY_NAME: {
        char name[512];
        if (sel >= 0 && FeListGetCellText(g_hFlList, sel, 0, name, sizeof(name))) {
            FeClipCopyText(g_hFlList, name);
            SetWindowTextA(g_hFlStatus, "Copy Name: copied to clipboard");
        }
        break;
    }
    case FL_ID_COPY_PATH:
        if (path[0]) {
            FeClipCopyText(g_hFlList, path);
            SetWindowTextA(g_hFlStatus, "Copy Path: copied to clipboard");
        }
        break;
    case FL_ID_LOCATE:
        if (path[0]) {
            char arg[MAX_PATH * 2 + 32];
            sprintf_s(arg, sizeof(arg), "/select,\"%s\"", path);
            ShellExecuteA(NULL, "open", "explorer.exe", arg, NULL, SW_SHOWNORMAL);
            SetWindowTextA(g_hFlStatus, "Locate: opened Explorer");
        }
        break;
    case FL_ID_EXPORT:
        FeListExportDefault(g_hFlList, g_hFlStatus, "PCHunter_Files");
        break;
    case FL_ID_LOCKER:
        SetWindowTextA(g_hFlStatus,
                       "File Locker: closing the owning handles needs a kernel channel "
                       "(enumerate holders via 0x26, then close) - not implemented yet");
        break;
    default:
        break;
    }
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 File 页段，逐字保留） ---- */
void FeFilePagePageShow(HWND hWnd, int page)
{
int isFile = (page == 8);        /* 第 9 个 Tab = File */
    if (g_hFlDir)    ShowWindow(g_hFlDir,    isFile ? SW_SHOW : SW_HIDE);
    if (g_hFlList)   ShowWindow(g_hFlList,   isFile ? SW_SHOW : SW_HIDE);
    if (g_hFlStatus) ShowWindow(g_hFlStatus, isFile ? SW_SHOW : SW_HIDE);
    {
        HWND h1 = GetDlgItem(hWnd, IDC_FL_GO);
        HWND h2 = GetDlgItem(hWnd, IDC_FL_DEL);
        HWND h3 = GetDlgItem(hWnd, IDC_FL_VERIFY);
        if (h1) ShowWindow(h1, isFile ? SW_SHOW : SW_HIDE);
        if (h2) ShowWindow(h2, isFile ? SW_SHOW : SW_HIDE);
        if (h3) ShowWindow(h3, isFile ? SW_SHOW : SW_HIDE);
    }}
