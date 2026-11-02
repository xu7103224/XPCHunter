// ============================================================================
// FeCommonMenu.c — 剩余页面的通用右键菜单（Refresh / Export / Copy）
//
// 【2026-10-29 新增】对应差距文档第 2.1 节"通用动作（跨页复用）"：
//   Refresh        刷新            [已补全]
//   Export Display 导出            [已补全]
//   Copy          复制单元格        [已补全]
//
// 原版每个列表都有这三项（见 pch_menu_strings.json 0x14069F3A0/0x1406A1A70/
// 0x1406A1B60），我方此前只有进程页有导出、其余页连刷新菜单项都没有。
// 本文件为 Network / File / Service / Other / Setting / Fireeye / Trojan 提供统一入口。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMON_ID_REFRESH   (10600 + 1)
#define COMMON_ID_EXPORT    (10600 + 2)
#define COMMON_ID_COPY1     (10600 + 3)
#define COMMON_ID_COPY2     (10600 + 4)
#define COMMON_ID_COPY3     (10600 + 5)
#define COMMON_ID_COPYALL   (10600 + 6)

/* 页面标识 */
typedef enum {
    FE_PG_UNKNOWN = 0,
    FE_PG_NETWORK,
    FE_PG_FILE,
    FE_PG_SERVICE,
    FE_PG_OTHER,
    FE_PG_SETTING,
    FE_PG_FIREYE,
    FE_PG_TROJAN
} FE_COMMON_PAGE;

/* 刷新回调：按页面分发到现有的 DoRefreshXxx */
static void FeCommonRefresh(FE_COMMON_PAGE Page)
{
    switch (Page) {
    case FE_PG_NETWORK: DoRefreshNetwork(); break;
    case FE_PG_FILE:    DoRefreshFiles(); break;
    case FE_PG_SERVICE: DoRefreshServices(); break;
    case FE_PG_OTHER:   DoRefreshOther(); break;
    case FE_PG_SETTING: DoRefreshSetting(); break;
    case FE_PG_FIREYE:  DoFireeyeAnalyse(); break;
    case FE_PG_TROJAN:  DoTrojanScan(); break;
    default: break;
    }
}

/* 目标列表 + 状态栏 */
static BOOL FeCommonTargets(FE_COMMON_PAGE Page, HWND *OutList, HWND *OutStatus)
{
    HWND lst = NULL, st = NULL;

    switch (Page) {
    case FE_PG_NETWORK: lst = g_hNwList;   st = g_hNwStatus;  break;
    case FE_PG_FILE:    lst = g_hFlList;   st = g_hFlStatus;  break;
    case FE_PG_SERVICE: lst = g_hSvList;   st = g_hSvStatus;  break;
    case FE_PG_OTHER:   lst = g_hOtList;   st = g_hOtStatus;  break;
    case FE_PG_SETTING: lst = g_hStList;   st = g_hStStatus;  break;
    case FE_PG_FIREYE:  lst = g_hFeList;   st = g_hFeStatus;  break;
    case FE_PG_TROJAN:  lst = g_hTrList;   st = g_hTrStatus;  break;
    default: break;
    }
    if (OutList)   *OutList = lst;
    if (OutStatus) *OutStatus = st;
    return lst != NULL;
}

/* 复制整行（所有列用 tab 连接） */
static void FeCommonCopyRow(HWND hList, HWND Status, int Sel)
{
    char line[2048];
    char cell[512];
    int c, nCol;
    HWND hdr;

    if (!hList || Sel < 0) {
        if (Status) SetWindowTextA(Status, "Copy: no row selected");
        return;
    }
    hdr = (HWND)(INT_PTR)SendMessageA(hList, LVM_GETHEADER, 0, 0);
    nCol = hdr ? (int)SendMessageA(hdr, HDM_GETITEMCOUNT, 0, 0) : 0;
    line[0] = 0;
    for (c = 0; c < nCol; c++) {
        if (!FeListGetCellText(hList, Sel, c, cell, sizeof(cell)))
            cell[0] = 0;
        if (c) strncat_s(line, sizeof(line), "\t", _TRUNCATE);
        strncat_s(line, sizeof(line), cell, _TRUNCATE);
    }
    FeClipCopyText(hList, line);
    if (Status) {
        char msg[300];
        sprintf_s(msg, sizeof(msg), "Copy: row %d copied (%d columns)", Sel, nCol);
        SetWindowTextA(Status, msg);
    }
}

/* 通用菜单：Page 指定归属页；CopyColumns 可选（单列复制项，最多 3 个） */
void FeCommonContextMenu(HWND hWnd, FE_COMMON_PAGE Page, int X, int Y,
                         const char *ExportName,
                         const char *Col1, const char *Col2, const char *Col3,
                         int Sub1, int Sub2, int Sub3)
{
    HMENU hMenu;
    UINT cmd;
    HWND lst = NULL, st = NULL;
    int sel = -1;

    if (!FeCommonTargets(Page, &lst, &st))
        return;
    FeListSelectUnderCursor(lst, X, Y);
    sel = FeListGetSel(lst);

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, COMMON_ID_REFRESH, "Refresh");                     /* 刷新 */
    FeMenuAdd(hMenu, COMMON_ID_EXPORT, "Export Display");               /* 导出 */
    FeMenuSep(hMenu);
    if (Col1) FeMenuAddEx(hMenu, COMMON_ID_COPY1, Col1, sel >= 0);
    if (Col2) FeMenuAddEx(hMenu, COMMON_ID_COPY2, Col2, sel >= 0);
    if (Col3) FeMenuAddEx(hMenu, COMMON_ID_COPY3, Col3, sel >= 0);
    FeMenuAddEx(hMenu, COMMON_ID_COPYALL, "Copy Row", sel >= 0);

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case COMMON_ID_REFRESH: FeCommonRefresh(Page); break;
    case COMMON_ID_EXPORT:
        FeListExportDefault(lst, st, ExportName ? ExportName : "PCHunter_Export");
        break;
    case COMMON_ID_COPY1: FeListCopyCell(lst, sel, Sub1, st, Col1); break;
    case COMMON_ID_COPY2: FeListCopyCell(lst, sel, Sub2, st, Col2); break;
    case COMMON_ID_COPY3: FeListCopyCell(lst, sel, Sub3, st, Col3); break;
    case COMMON_ID_COPYALL: FeCommonCopyRow(lst, st, sel); break;
    default: break;
    }
}

/* ---- 各页的便捷入口（frontend.c 的 WM_CONTEXTMENU 分发调用） ---- */

void DoNetworkContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_NETWORK, X, Y, "PCHunter_Network",
                        "Copy Fun Name", "Copy Current Entry", "Copy Module",
                        0, 1, 4);
}

void DoServiceCommonContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_SERVICE, X, Y, "PCHunter_Services",
                        "Copy Service", "Copy ImagePath", "Copy ServiceDll",
                        0, 2, 3);
}

void DoOtherContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_OTHER, X, Y, "PCHunter_Other",
                        "Copy Item", "Copy Value", NULL,
                        0, 1, 0);
}

void DoSettingContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_SETTING, X, Y, "PCHunter_Setting",
                        "Copy Setting", "Copy State", NULL,
                        0, 1, 0);
}

void DoFireeyeContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_FIREYE, X, Y, "PCHunter_Fireeye",
                        "Copy Field", "Copy Value", NULL,
                        0, 1, 0);
}

void DoTrojanContextMenu(HWND hWnd, int X, int Y)
{
    FeCommonContextMenu(hWnd, FE_PG_TROJAN, X, Y, "PCHunter_Trojan",
                        "Copy Item", "Copy Result", "Copy Detail",
                        0, 1, 2);
}