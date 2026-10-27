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
