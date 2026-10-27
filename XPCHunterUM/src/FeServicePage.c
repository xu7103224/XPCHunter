// ============================================================================
// FeServicePage.c — Service 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hSvList, g_hSvStatus;

/* ---- Services 页（主 Tab 7）---- */
void SvSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateSvColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Service";     c.cx = 200; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "State";       c.cx = 80;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "ServiceDll";  c.cx = 70;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "ImagePath / Resolved"; c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
}

void DoRefreshServices(void)
{
    FE_SERVICE_LIST list;
    char status[256];
    ULONG i;

    if (!g_hSvList || !g_hSvStatus)
        return;
    ListView_DeleteAllItems(g_hSvList);
    CreateSvColumns(g_hSvList);

    if (!FeLoadServices(&list)) {
        SetWindowTextA(g_hSvStatus, "Services: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        const char *st;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = list.Items[i].Name;
        SendMessageA(g_hSvList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        switch (list.Items[i].State) {
        case SERVICE_RUNNING: st = "RUNNING"; break;
        case SERVICE_STOPPED: st = "STOPPED"; break;
        case SERVICE_START_PENDING: st = "STARTING"; break;
        case SERVICE_STOP_PENDING: st = "STOPPING"; break;
        default: st = "?"; break;
        }
        SvSetText(g_hSvList, (int)i, 1, st);
        SvSetText(g_hSvList, (int)i, 2, list.Items[i].ServiceDll[0] ? "yes" : "-");
        SvSetText(g_hSvList, (int)i, 3,
                  list.Items[i].ResolvedPath[0] ? list.Items[i].ResolvedPath :
                  (list.Items[i].ImagePath[0] ? list.Items[i].ImagePath : "(?)"));
    }
    sprintf_s(status, sizeof(status),
              "Services: %lu / Hidden Services: %lu  (registry keys: %lu)",
              list.Count, list.HiddenCount, list.RegServiceCount);
    SetWindowTextA(g_hSvStatus, status);
    FeFreeServices(&list);
}

void DoServiceFireeye(int UseServiceDll)
{
    int sel;
    char name[FE_SVC_NAME_CHARS];
    LVITEMA it;
    FE_SERVICE_LIST list;
    ULONG i;
    const char *target = NULL;

    if (!g_hSvList || !g_hSvStatus)
        return;
    sel = ListView_GetNextItem(g_hSvList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hSvStatus, "Select a service first");
        return;
    }
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.pszText = name;
    it.cchTextMax = (int)sizeof(name);
    if (!SendMessageA(g_hSvList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it)) {
        SetWindowTextA(g_hSvStatus, "Selected service has no name");
        return;
    }
    if (!FeLoadServices(&list)) {
        SetWindowTextA(g_hSvStatus, "Services: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) == 0) {
            target = UseServiceDll
                     ? (list.Items[i].ServiceDll[0] ? list.Items[i].ServiceDll
                                                    : list.Items[i].ResolvedPath)
                     : (list.Items[i].ResolvedPath[0] ? list.Items[i].ResolvedPath
                                                      : list.Items[i].ImagePath);
            break;
        }
    }
    if (target && target[0] && g_hFePath) {
        char pathCopy[FE_SVC_PATH_CHARS];
        strcpy_s(pathCopy, sizeof(pathCopy), target);
        FeFreeServices(&list);
        SetWindowTextA(g_hFePath, pathCopy);
        g_MainTab = 11;
        if (g_hMainTabs)
            SendMessageA(g_hMainTabs, TCM_SETCURSEL, 11, 0);
        if (g_hMainWnd)
            ShowPage(g_hMainWnd, 11);
        DoFireeyeAnalyse();
        sprintf_s(pathCopy, sizeof(pathCopy), "%s", target);
        {
            char msg[512];
            sprintf_s(msg, sizeof(msg), "FireEye: %s -> %s",
                      UseServiceDll ? "ServiceDll" : "ImagePath", pathCopy);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    }
    FeFreeServices(&list);
    SetWindowTextA(g_hSvStatus,
                   UseServiceDll ? "Selected service has no ServiceDll"
                                 : "Selected service has no ImagePath");
}

/* 取 Services 列表选中行的服务条目（重新查表以拿到完整字段）。 */
BOOL SvGetSelectedEntry(FE_SERVICE_ENTRY *Out)
{
    int sel;
    char name[FE_SVC_NAME_CHARS];
    LVITEMA it;
    FE_SERVICE_LIST list;
    ULONG i;
    BOOL found = FALSE;

    if (!Out || !g_hSvList)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    sel = ListView_GetNextItem(g_hSvList, -1, LVNI_SELECTED);
    if (sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.pszText = name;
    it.cchTextMax = (int)sizeof(name);
    if (!SendMessageA(g_hSvList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it))
        return FALSE;
    if (!FeLoadServices(&list))
        return FALSE;
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) == 0) {
            *Out = list.Items[i];
            found = TRUE;
            break;
        }
    }
    FeFreeServices(&list);
    return found;
}

void DoServiceOp(int Op)
{
    FE_SERVICE_ENTRY e;
    char msg[768];
    const char *path;

    if (!g_hSvStatus)
        return;
    if (!SvGetSelectedEntry(&e)) {
        SetWindowTextA(g_hSvStatus, "Select a service first");
        return;
    }
    path = e.ResolvedPath[0] ? e.ResolvedPath : e.ImagePath;

    switch (Op) {
    case 0:   /* Delete Service (Not Delete File) */
        {
            int r;
            sprintf_s(msg, sizeof(msg),
                      "Delete service \"%s\"?\n\nThe service registration is removed "
                      "but the file on disk is NOT deleted.", e.Name);
            r = MessageBoxA(g_hMainWnd, msg, "Delete Service",
                            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
            if (r != IDYES) {
                SetWindowTextA(g_hSvStatus, "Delete service cancelled");
                return;
            }
            if (FeDeleteService(e.Name))
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s removed (file kept: %s)",
                          e.Name, path[0] ? path : "(none)");
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Service(Not Delete File): %s failed", e.Name);
            SetWindowTextA(g_hSvStatus, msg);
            DoRefreshServices();
        }
        return;
    case 1:   /* Verify ImagePath Signature */
        sprintf_s(msg, sizeof(msg), "Verify ImagePath Signature: %s -> %s (%s)",
                  e.Name,
                  FeVerifyFileSignature(path) ? "valid and trusted"
                                              : "no signature or not trusted",
                  path[0] ? path : "(no ImagePath)");
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 2:   /* Verify ServiceDll Signature */
        if (!e.ServiceDll[0]) {
            sprintf_s(msg, sizeof(msg),
                      "Verify ServiceDll Signature: %s has no ServiceDll", e.Name);
        } else {
            sprintf_s(msg, sizeof(msg), "Verify ServiceDll Signature: %s -> %s (%s)",
                      e.Name,
                      FeVerifyFileSignature(e.ServiceDll) ? "valid and trusted"
                                                          : "no signature or not trusted",
                      e.ServiceDll);
        }
        SetWindowTextA(g_hSvStatus, msg);
        return;
    case 3:   /* Find ImagePath Target */
    case 4:   /* Find ServiceDll Target */
        {
            const char *t = (Op == 3) ? path : e.ServiceDll;
            const char *what = (Op == 3) ? "Find ImagePath Target" : "Find ServiceDll Target";
            if (!t || !t[0]) {
                sprintf_s(msg, sizeof(msg), "%s: %s has no %s", what, e.Name,
                          Op == 3 ? "ImagePath" : "ServiceDll");
            } else {
                WCHAR wt[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, t, -1, wt, MAX_PATH);
                sprintf_s(msg, sizeof(msg), "%s: %s -> %s (%s)", what, e.Name, t,
                          GetFileAttributesW(wt) == INVALID_FILE_ATTRIBUTES
                          ? "FILE NOT FOUND" : "file exists");
            }
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 5:   /* Copy ImagePath */
    case 6:   /* Copy ServiceDll Path */
        {
            const char *t = (Op == 5) ? path : e.ServiceDll;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path to copy");
                return;
            }
            if (!OpenClipboard(g_hSvList))
                return;
            EmptyClipboard();
            {
                HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(t) + 1);
                if (h) {
                    void *q = GlobalLock(h);
                    if (q) {
                        memcpy(q, t, strlen(t) + 1);
                        GlobalUnlock(h);
                        SetClipboardData(CF_TEXT, h);
                    }
                }
            }
            CloseClipboard();
            sprintf_s(msg, sizeof(msg), "%s copied: %s",
                      Op == 5 ? "ImagePath" : "ServiceDll path", t);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    case 7:   /* Locate in File Tab (ImagePath) */
    case 8:   /* Locate in File Tab (ServiceDll) */
        {
            const char *t = (Op == 7) ? path : e.ServiceDll;
            char dir[FE_SVC_PATH_CHARS];
            char *slash;
            if (!t || !t[0]) {
                SetWindowTextA(g_hSvStatus, "Selected service has no path");
                return;
            }
            strcpy_s(dir, sizeof(dir), t);
            slash = strrchr(dir, '\\');
            if (slash)
                *slash = 0;
            if (g_hFlDir) {
                SetWindowTextA(g_hFlDir, dir);
                g_MainTab = 8;
                if (g_hMainTabs)
                    SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
                if (g_hMainWnd)
                    ShowPage(g_hMainWnd, 8);
                DoRefreshFiles();
            }
            sprintf_s(msg, sizeof(msg), "%s: located in File tab -> %s",
                      Op == 7 ? "Locate ImagePath" : "Locate ServiceDll", dir);
            SetWindowTextA(g_hSvStatus, msg);
        }
        return;
    default:
        return;
    }
}

void DoServiceContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    AppendMenuA(hMenu, MF_STRING, 7003, "Delete Service (Not Delete File)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7004, "Verify ImagePath Signature");
    AppendMenuA(hMenu, MF_STRING, 7005, "Verify ServiceDll Signature");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7006, "Find ImagePath Target");
    AppendMenuA(hMenu, MF_STRING, 7007, "Find ServiceDll Target");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7008, "Copy ImagePath");
    AppendMenuA(hMenu, MF_STRING, 7009, "Copy ServiceDll Path");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7010, "Locate in File Tab (ImagePath)");
    AppendMenuA(hMenu, MF_STRING, 7011, "Locate in File Tab (ServiceDll)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, 7001, "Analyse ImagePath by FireEye");
    AppendMenuA(hMenu, MF_STRING, 7002, "Analyse ServiceDll by FireEye");
    if (X == -1 && Y == -1) {
        RECT rc;
        GetWindowRect(g_hSvList, &rc);
        X = rc.left + 40;
        Y = rc.top + 40;
    }
    cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                         X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    if (cmd == 7001)
        DoServiceFireeye(0);
    else if (cmd == 7002)
        DoServiceFireeye(1);
    else if (cmd >= 7003 && cmd <= 7011)
        DoServiceOp(cmd - 7003);
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Service 页段，逐字保留） ---- */
void FeServicePagePageShow(HWND hWnd, int page)
{
int isServices = (page == 7);    /* 第 8 个 Tab = Services */
    if (g_hSvList)   ShowWindow(g_hSvList,   isServices ? SW_SHOW : SW_HIDE);
    if (g_hSvStatus) ShowWindow(g_hSvStatus, isServices ? SW_SHOW : SW_HIDE);
    {
        HWND hSv = GetDlgItem(hWnd, IDC_SV_REFRESH);
        if (hSv) ShowWindow(hSv, isServices ? SW_SHOW : SW_HIDE);
    }}
