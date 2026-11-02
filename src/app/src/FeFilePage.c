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
/* 【2026-10-30 补】原版 File 页有 Delete File / Verify File Signature /
   Verify All Files Signatrue，我方菜单缺这三项；同时 File 页的
   "Delete" 与 "Verify" 两个按钮只有控件、没有 WM_COMMAND 处理（点击
   无反应）。一并补上。 */
#define FL_ID_VERIFY        (FL_MENU_BASE + 14)
#define FL_ID_VERIFY_ALL    (FL_MENU_BASE + 15)
#define FL_ID_DELETE        (FL_MENU_BASE + 16)
#define FL_ID_FIND_HIDDEN   (FL_MENU_BASE + 17)   /* 原版 File 页 Find Hidden Item */

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
    FeMenuAdd(hMenu, FL_ID_FIND_HIDDEN, "Find Hidden Item");
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, FL_ID_MD5, "File MD5", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_ASSOC, "File Association", sel >= 0);
    FeMenuAddEx(hMenu, FL_ID_VERIFY, "Verify File Signature", sel >= 0);
    FeMenuAdd(hMenu, FL_ID_VERIFY_ALL, "Verify All Files Signatrue");
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
    FeMenuAddEx(hMenu, FL_ID_LOCKER, "File Locker (find holders)", sel >= 0);
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, FL_ID_DELETE, "Delete File", sel >= 0);

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
        if (path[0]) {
            ULONG n = 0, i;
            char msg[1400];
            msg[0] = 0;

            SetWindowTextA(g_hFlStatus, "File Locker: enumerating system handles...");
            UpdateWindow(g_hFlStatus);
            n = FeFileLockerFindHolders(path, NULL, NULL);
            if (n == 0) {
                sprintf_s(msg, sizeof(msg),
                          "File Locker: no handle holder found for \"%s\"", path);
                SetWindowTextA(g_hFlStatus, msg);
                FeFileLockerFree();
                break;
            }
            {
                char line[600];
                sprintf_s(msg, sizeof(msg),
                          "File Locker: %lu holder(s) for \"%s\"", n, path);
                for (i = 0; i < n && i < 20; i++) {
                    ULONG pid = 0;
                    ULONG64 h = 0;
                    const char *pname = NULL;
                    if (!FeFileLockerGet(i, &pid, &h, &pname, NULL))
                        continue;
                    sprintf_s(line, sizeof(line), "\r\n  [%lu] %s (pid %lu) handle=0x%I64X",
                              i + 1, pname ? pname : "?", (unsigned long)pid,
                              (unsigned long long)h);
                    if (strlen(msg) + strlen(line) + 1 < sizeof(msg))
                        strcat_s(msg, sizeof(msg), line);
                }
                if (n > 20)
                    strcat_s(msg, sizeof(msg), "\r\n  ... (more)");
                strcat_s(msg, sizeof(msg),
                         "\r\n\r\nClose all these handles to unlock the file?");
            }
            if (MessageBoxA(hWnd, msg, "File Locker",
                            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES) {
                ULONG closed = 0, failed = 0;
                for (i = 0; i < n; i++) {
                    ULONG pid = 0, rr = 0;
                    ULONG64 h = 0;
                    if (!FeFileLockerGet(i, &pid, &h, NULL, NULL))
                        continue;
                    if (FeFileLockerCloseHandle(&g_Client, pid, h, (UCHAR *)&rr))
                        closed++;
                    else
                        failed++;
                }
                sprintf_s(msg, sizeof(msg),
                          "File Locker: closed %lu handle(s), %lu failed "
                          "(driver 0xA0; needs driver loaded and admin)", closed, failed);
                SetWindowTextA(g_hFlStatus, msg);
            } else {
                SetWindowTextA(g_hFlStatus, "File Locker: cancelled (no handle closed)");
            }
            FeFileLockerFree();
        }
        break;
    case FL_ID_VERIFY:
        DoFileVerifySelected();
        break;
    case FL_ID_VERIFY_ALL:
        DoFileVerifyAll();
        break;
    case FL_ID_DELETE:
        DoFileDeleteSelected();
        break;
    case FL_ID_FIND_HIDDEN:
        DoFileFindHidden();
        break;
    default:
        break;
    }
}

/* 【2026-10-30 新增】File 页的三个动作，同时供右键菜单与顶部按钮使用。
   此前 "Verify"/"Delete" 两个按钮只有控件、没有 WM_COMMAND 处理，
   点击无反应；原版的 Delete File / Verify File Signature /
   Verify All Files Signatrue 三项在菜单里也不存在。 */

/* 校验选中文件的 Authenticode 签名。FeVerifyFileSignature 返回：
   1=受信任、0=无签名或不受信任、-1=无法判定。 */
void DoFileVerifySelected(void)
{
    char path[MAX_PATH * 2];
    char msg[MAX_PATH * 2 + 200];
    int r;

    FlSelectedPath(path, sizeof(path));
    if (!path[0]) {
        SetWindowTextA(g_hFlStatus, "Verify: select a file first");
        return;
    }
    r = FeVerifyFileSignature(path);
    sprintf_s(msg, sizeof(msg), "Verify File Signature: %s -> %s",
              path,
              r == 1 ? "trusted" : (r == 0 ? "no signature or not trusted" : "cannot verify"));
    SetWindowTextA(g_hFlStatus, msg);
}

/* 校验当前列表里所有文件。逐条调用，最后汇总；
   为避免阻塞界面，最多处理 500 条。 */
void DoFileVerifyAll(void)
{
    int count, i, trusted = 0, unsig = 0, unknown = 0;
    char msg[300];

    if (!g_hFlList) {
        return;
    }
    count = ListView_GetItemCount(g_hFlList);
    if (count <= 0) {
        SetWindowTextA(g_hFlStatus, "Verify All: file list is empty");
        return;
    }
    if (count > 500)
        count = 500;

    SetWindowTextA(g_hFlStatus, "Verify All: checking signatures...");
    UpdateWindow(g_hFlStatus);

    for (i = 0; i < count; i++) {
        char path[MAX_PATH * 2];
        int r;

        ListView_SetItemState(g_hFlList, i, LVIS_SELECTED, LVIS_SELECTED);
        FlSelectedPath(path, sizeof(path));
        ListView_SetItemState(g_hFlList, i, 0, LVIS_SELECTED);
        if (!path[0])
            continue;

        r = FeVerifyFileSignature(path);
        if (r == 1)      trusted++;
        else if (r == 0) unsig++;
        else             unknown++;
    }

    sprintf_s(msg, sizeof(msg),
              "Verify All Files: %d checked, %d trusted, %d unsigned/untrusted, %d unknown",
              count, trusted, unsig, unknown);
    SetWindowTextA(g_hFlStatus, msg);
}

/* 删除选中文件。破坏性操作，必须二次确认。 */
/* Find Hidden Item — 只显示当前目录里名字可疑（Rootkit 特征）的项。
 *
 * 【2026-10-30 补】原版 File 页有此菜单项。判据用 FE_FILE_ENTRY.Suspect，
 * 与 DoRefreshFiles 里"可疑项加括号标红"同源，保证两处一致。
 * 重新枚举一遍当前目录（而不是从 listview 过滤）：因为 listview 里的名字
 * 已经被加了括号，用文本反查不可靠。 */
void DoFileFindHidden(void)
{
    FE_FILE_LIST list;
    char dir[MAX_PATH];
    char status[400];
    ULONG i, shown = 0;

    if (!g_hFlList || !g_hFlStatus || !g_hFlDir)
        return;
    GetWindowTextA(g_hFlDir, dir, sizeof(dir));
    if (!dir[0])
        strcpy_s(dir, sizeof(dir), "C:\Windows\System32");

    if (!FeLoadDirectory(dir, &list)) {
        sprintf_s(status, sizeof(status),
                  "Find Hidden Item: cannot open \"%s\", GetLastError=%lu",
                  dir, GetLastError());
        SetWindowTextA(g_hFlStatus, status);
        return;
    }

    ListView_DeleteAllItems(g_hFlList);
    CreateFlColumns(g_hFlList);
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        char sz[32], attr[32], flags[128], name[FE_FILE_NAME_CHARS + 4];

        if (!list.Items[i].Suspect)
            continue;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)shown;
        sprintf_s(name, sizeof(name), "(%s)", list.Items[i].Name);
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
        FlSetText(g_hFlList, (int)shown, 1, sz);
        FlSetText(g_hFlList, (int)shown, 2, attr);
        FlSetText(g_hFlList, (int)shown, 3, flags);
        FlSetText(g_hFlList, (int)shown, 4, list.Items[i].Path);
        shown++;
    }
    sprintf_s(status, sizeof(status),
              "Find Hidden Item: %lu suspicious name(s) in \"%s\" (of %lu entries)",
              shown, dir, list.Count);
    SetWindowTextA(g_hFlStatus, status);
    FeFreeDirectory(&list);
}

void DoFileDeleteSelected(void)
{
    char path[MAX_PATH * 2];
    char msg[MAX_PATH * 2 + 400];
    DWORD err = 0;

    FlSelectedPath(path, sizeof(path));
    if (!path[0]) {
        SetWindowTextA(g_hFlStatus, "Delete: select a file first");
        return;
    }
    sprintf_s(msg, sizeof(msg),
              "Delete this file permanently?\r\n\r\n%s\r\n\r\nThis cannot be undone.",
              path);
    if (MessageBoxA(g_hFlList, msg, "Delete File",
                    MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
        SetWindowTextA(g_hFlStatus, "Delete: cancelled");
        return;
    }
    if (FeDeleteFileEx(path, &err)) {
        sprintf_s(msg, sizeof(msg), "Delete File: OK  %s", path);
        SetWindowTextA(g_hFlStatus, msg);
        DoRefreshFiles();
    } else {
        sprintf_s(msg, sizeof(msg),
                  "Delete File: failed, GetLastError=%lu (may need admin or be in use)", err);
        SetWindowTextA(g_hFlStatus, msg);
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
