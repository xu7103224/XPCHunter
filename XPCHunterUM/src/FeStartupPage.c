// ============================================================================
// FeStartupPage.c — Startup 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hSuList, g_hSuStatus, g_hSuTabs;
int  g_SuTab = 0;   /* 0 = Startup Item（注册表启动项） 1 = Schedule Task（计划任务） */

/* ==========================================================================
 * 主 Tab 容器（M1）
 *
 * 原版是单窗口 + 14 个主 Tab。这里：
 *   顶部工具条（连接/刷新/命令测试器）   10..38
 *   主 Tab 栏                            44..68
 *   页面区（各页控件都建在主窗口里，按选中页显示/隐藏）
 *
 * 14 页全部有实现：0 Process / 1 Kernel / 2-3 Ring0+Ring3 Hooks /
 * 4 Network / 5 Registry / 6 Startup Info / 7 Services / 8 File /
 * 9 Examination / 10 Setting / 11 Fireeye / 12 Trojan Detection / 13 Other。
 * Network 页的 30 个字段无数据源（命令表审计确认原驱动无对应命令），
 * 页内如实标注，不伪造数据。
 * ========================================================================== */

/* ---- Startup Info 页（主 Tab 6）---- */
void SuSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateSuColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Location"; c.cx = 210; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "View";     c.cx = 45;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "Name";     c.cx = 240; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "Data";     c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
}

void DoRefreshStartup(void)
{
    FE_STARTUP_LIST list;
    char status[256];
    ULONG i;

    if (!g_hSuList || !g_hSuStatus)
        return;
    ListView_DeleteAllItems(g_hSuList);

    /* 2026-10-29：按子 Tab 分发。Schedule Task 子页的数据源独立。 */
    if (g_SuTab == 1) {
        DoRefreshSchedule();
        return;
    }
    CreateSuColumns(g_hSuList);

    if (!FeLoadStartupItems(&list)) {
        sprintf_s(status, sizeof(status), "Startup Info: 0 items");
        SetWindowTextA(g_hSuStatus, status);
        return;
    }
    for (i = 0; i < list.Count; i++) {
        LVITEMA it;
        char view[16];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        it.pszText = list.Items[i].Location;
        SendMessageA(g_hSuList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(view, sizeof(view), "%lu", list.Items[i].View);
        SuSetText(g_hSuList, (int)i, 1, view);
        SuSetText(g_hSuList, (int)i, 2, list.Items[i].Name);
        SuSetText(g_hSuList, (int)i, 3, list.Items[i].Data);
    }
    sprintf_s(status, sizeof(status), "Startup Info: %lu items (16 locations, Wow64 split)", list.Count);
    SetWindowTextA(g_hSuStatus, status);
    FeFreeStartupItems(&list);
}

/* Startup Info 页右键：Delete Startup / Delete(Startup And File) / Repair Startup。
 * 原版的这三项都在自启动项列表的右键菜单里。 */
void DoStartupOp(int Op)
{
    int sel;
    FE_STARTUP_LIST list;
    ULONG i;
    char msg[768];
    char name[FE_STARTUP_NAME_CHARS];

    if (!g_hSuList || !g_hSuStatus)
        return;

    if (Op == 2) {   /* Repair Startup：整表检查，不需要选中行 */
        ULONG checked = 0, fixed;
        FE_STARTUP_LIST rep;
        fixed = FeRepairStartupItems(&checked, &rep);
        if (fixed) {
            sprintf_s(msg, sizeof(msg),
                      "Repair Startup: %lu of %lu entries pointed at missing files "
                      "and were removed", fixed, checked);
        } else {
            sprintf_s(msg, sizeof(msg),
                      "Repair Startup: checked %lu entries, none needed repair "
                      "(all targets exist)", checked);
        }
        SetWindowTextA(g_hSuStatus, msg);
        FeFreeStartupItems(&rep);
        DoRefreshStartup();
        return;
    }

    sel = ListView_GetNextItem(g_hSuList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hSuStatus, "Select a startup item first");
        return;
    }
    name[0] = 0;
    {
        LVITEMA it;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = sel;
        it.iSubItem = 1;        /* Name 列 */
        it.pszText = name;
        it.cchTextMax = (int)sizeof(name);
        SendMessageA(g_hSuList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it);
    }

    if (!FeLoadStartupItems(&list)) {
        SetWindowTextA(g_hSuStatus, "Startup: load failed");
        return;
    }
    for (i = 0; i < list.Count; i++) {
        if (strcmp(list.Items[i].Name, name) != 0)
            continue;
        if (Op == 0) {          /* Delete Startup */
            if (FeDeleteStartupItem(&list.Items[i]))
                sprintf_s(msg, sizeof(msg), "Delete Startup: %s removed", name);
            else
                sprintf_s(msg, sizeof(msg), "Delete Startup: %s failed", name);
        } else {                /* Delete(Startup And File) */
            char path[FE_STARTUP_DATA_CHARS];
            BOOL regOk = FALSE;
            DWORD fileErr = 0;
            BOOL ok = FeDeleteStartupItemAndFile(&list.Items[i], path, sizeof(path),
                                                 &regOk, &fileErr);
            if (ok) {
                sprintf_s(msg, sizeof(msg),
                          "Delete(Startup And File): %s removed, file deleted: %s",
                          name, path[0] ? path : "(none)");
            } else {
                sprintf_s(msg, sizeof(msg),
                          "Delete(Startup And File): %s -> registry %s, "
                          "file delete failed (GetLastError=%lu)%s",
                          name, regOk ? "removed" : "failed",
                          (unsigned long)fileErr,
                          fileErr == ERROR_ACCESS_DENIED ? " [in use]" : "");
            }
        }
        SetWindowTextA(g_hSuStatus, msg);
        FeFreeStartupItems(&list);
        DoRefreshStartup();
        return;
    }
    FeFreeStartupItems(&list);
    SetWindowTextA(g_hSuStatus, "Startup item disappeared after refresh");
}

void DoStartupContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    UINT cmd;
    int sel;

    /* 2026-10-29：Schedule Task 子页转给计划任务菜单（14 项） */
    if (g_SuTab == 1) {
        DoScheduleContextMenu(hWnd, X, Y);
        return;
    }

    FeListSelectUnderCursor(g_hSuList, X, Y);
    sel = FeListGetSel(g_hSuList);

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;
    /* 原版 Startup 页菜单四项，官方译名见 pch_menu_strings.json */
    FeMenuAdd(hMenu, 8100, "Refresh");                                  /* 刷新 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, 8001, "Delete Startup", sel >= 0);                /* 删除 */
    FeMenuAddEx(hMenu, 8002, "Delete(Startup And File)", sel >= 0);      /* 连文件一起删除 */
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, 8003, "Repair Startup");                            /* 修复启动项 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, 8101, "Copy Name", sel >= 0);                     /* 复制名称 */
    FeMenuAddEx(hMenu, 8102, "Copy Data", sel >= 0);                     /* 复制数据 */
    FeMenuAddEx(hMenu, 8103, "Locate in File Tab", sel >= 0);            /* 定位到文件管理器 */
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, 8104, "Export Display");                            /* 导出 */

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);
    switch (cmd) {
    case 8100: DoRefreshStartup(); break;
    case 8001: DoStartupOp(0); break;
    case 8002: DoStartupOp(1); break;
    case 8003: DoStartupOp(2); break;
    case 8101: {
        char name[FE_STARTUP_NAME_CHARS];
        if (sel >= 0 && FeListGetCellText(g_hSuList, sel, 2, name, sizeof(name))) {
            FeClipCopyText(g_hSuList, name);
            SetWindowTextA(g_hSuStatus, "Copy Name: copied to clipboard");
        }
        break;
    }
    case 8102: {
        char data[FE_STARTUP_DATA_CHARS];
        if (sel >= 0 && FeListGetCellText(g_hSuList, sel, 3, data, sizeof(data))) {
            FeClipCopyText(g_hSuList, data);
            SetWindowTextA(g_hSuStatus, "Copy Data: copied to clipboard");
        }
        break;
    }
    case 8103: {
        char data[FE_STARTUP_DATA_CHARS];
        char *p;
        if (sel >= 0 && FeListGetCellText(g_hSuList, sel, 3, data, sizeof(data))) {
            p = strchr(data, '"');
            if (p) { char *q = strchr(p + 1, '"'); if (q) *q = 0; memmove(data, p + 1, strlen(p)); }
            p = strrchr(data, '\\');
            if (p) {
                *p = 0;
                if (g_hFlDir) SetWindowTextA(g_hFlDir, data);
            }
            if (g_hMainTabs) SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
            if (g_hMainWnd) ShowPage(g_hMainWnd, 8);
            DoRefreshFiles();
            SetWindowTextA(g_hSuStatus, "Locate in File Tab: opened File page");
        }
        break;
    }
    case 8104: FeListExportDefault(g_hSuList, g_hSuStatus, "PCHunter_Startup"); break;
    default: break;
    }
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Startup 页段，逐字保留） ---- */
void FeStartupPagePageShow(HWND hWnd, int page)
{
int isStartup = (page == 6);     /* 0-based：第 7 个 Tab = Startup Info */
    if (g_hSuTabs)   ShowWindow(g_hSuTabs,   isStartup ? SW_SHOW : SW_HIDE);
    if (g_hSuList)   ShowWindow(g_hSuList,   isStartup ? SW_SHOW : SW_HIDE);
    if (g_hSuStatus) ShowWindow(g_hSuStatus, isStartup ? SW_SHOW : SW_HIDE);
    {
        HWND hSu = GetDlgItem(hWnd, IDC_SU_REFRESH);
        if (hSu) ShowWindow(hSu, isStartup ? SW_SHOW : SW_HIDE);
    }}
