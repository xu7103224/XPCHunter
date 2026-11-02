// ============================================================================
// FeMenu.c — 跨页共享的右键菜单与剪贴板/文件助手
//
// 背景：原版 PCHunter 的每个列表都挂了右键菜单（662 条多语言文案，见
// doc/reversing/pch_menu_strings.json）。我方此前只有 5 个页面各自手写
// AppendMenuA，重复且不一致。本文件提供一套统一构件：
//
//   FeMenuBegin/FeMenuAdd/FeMenuSep/FeMenuItem/FeMenuEnd  菜单构造与弹出
//   FeClipCopyText    复制文本到剪贴板
//   FeListCopyCell    复制列表某个单元格
//   FeListExportToFile 把整个列表导出为 TSV
//   FeConfirmDanger   破坏性操作二次确认
//   FeAskText         单行文本输入（复用 Kernel 页的 Prompt 窗口）
//
// 所有文案与原版官方中文对齐（见 pch_menu_strings.json 的 zh_cn 字段），
// 但由于本客户端界面为英文，这里用英文原文，并在注释里标注原版中文。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 菜单构造 ---- */

HMENU FeMenuBegin(void)
{
    return CreatePopupMenu();
}

/* 添加普通菜单项。id 为 0 时只做标题（不响应）。 */
void FeMenuAdd(HMENU hMenu, UINT id, const char *Text)
{
    if (hMenu && Text)
        AppendMenuA(hMenu, MF_STRING, (UINT_PTR)id, Text);
}

/* 添加带启用状态的菜单项（原版大量使用 EnableMenuItem 做依赖选中行的灰化）。 */
void FeMenuAddEx(HMENU hMenu, UINT id, const char *Text, BOOL Enabled)
{
    if (!hMenu || !Text)
        return;
    AppendMenuA(hMenu, MF_STRING | (Enabled ? 0 : MF_GRAYED), (UINT_PTR)id, Text);
}

/* 添加勾选项（原版 Only Show Loaded Driver / Only show hooks 都是勾选项）。 */
void FeMenuAddCheck(HMENU hMenu, UINT id, const char *Text, BOOL Checked)
{
    if (hMenu && Text)
        AppendMenuA(hMenu, MF_STRING | (Checked ? MF_CHECKED : MF_UNCHECKED),
                    (UINT_PTR)id, Text);
}

void FeMenuSep(HMENU hMenu)
{
    if (hMenu)
        AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
}

/* 二级子菜单：hSub 由 FeMenuBegin 创建，用完后随父菜单一起 DestroyMenu。 */
void FeMenuAddPopup(HMENU hMenu, HMENU hSub, const char *Text)
{
    if (hMenu && hSub && Text)
        AppendMenuA(hMenu, MF_POPUP | MF_STRING, (UINT_PTR)hSub, Text);
}

/* 弹出并返回选中的命令 ID（未选返回 0）。 */
UINT FeMenuEnd(HMENU hMenu, HWND hWnd, int X, int Y, int FallbackDx, int FallbackDy)
{
    UINT cmd;

    if (!hMenu)
        return 0;
    if (X == -1 && Y == -1) {
        RECT rc;
        if (GetWindowRect(hWnd, &rc)) {
            X = rc.left + FallbackDx;
            Y = rc.top + FallbackDy;
        } else {
            POINT pt;
            GetCursorPos(&pt);
            X = pt.x;
            Y = pt.y;
        }
    }
    cmd = (UINT)TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                               X, Y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
    return cmd;
}

/* ---- 剪贴板 ---- */

BOOL FeClipCopyText(HWND Owner, const char *Text)
{
    HGLOBAL h;
    void *p;
    size_t n;

    if (!Text)
        return FALSE;
    if (!OpenClipboard(Owner))
        return FALSE;
    EmptyClipboard();
    n = strlen(Text) + 1;
    h = GlobalAlloc(GMEM_MOVEABLE, n);
    if (!h) {
        CloseClipboard();
        return FALSE;
    }
    p = GlobalLock(h);
    if (!p) {
        GlobalFree(h);
        CloseClipboard();
        return FALSE;
    }
    memcpy(p, Text, n);
    GlobalUnlock(h);
    SetClipboardData(CF_TEXT, h);
    CloseClipboard();
    return TRUE;
}

/* 复制列表某个单元格（Sel 行 Sub 列）。返回 FALSE 表示该单元格为空。 */
BOOL FeListCopyCell(HWND hList, int Sel, int Sub, HWND StatusWnd, const char *What)
{
    LVITEMA it;
    char text[1024];
    char msg[1200];

    if (!hList || Sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = Sel;
    it.iSubItem = Sub;
    it.pszText = text;
    it.cchTextMax = sizeof(text);
    text[0] = 0;
    if (!SendMessageA(hList, LVM_GETITEMTEXTA, (WPARAM)Sel, (LPARAM)&it) || !text[0])
        return FALSE;
    FeClipCopyText(hList, text);
    if (StatusWnd && What) {
        sprintf_s(msg, sizeof(msg), "%s copied: %s", What, text);
        SetWindowTextA(StatusWnd, msg);
    }
    return TRUE;
}

/* ---- 列表导出（原版每页都有 Export Display / 导出） ---- */

BOOL FeListExportToFile(HWND hList, const char *Path, ULONG *OutRows)
{
    FILE *f = NULL;
    int nCol, nRow, r, c;
    char cell[2048];
    ULONG written = 0;

    if (!hList || !Path)
        return FALSE;
    if (fopen_s(&f, Path, "wb") != 0 || !f)
        return FALSE;

    /* UTF-8 BOM，与进程页 CSV 导出一致 */
    fwrite("\xEF\xBB\xBF", 1, 3, f);

    nCol = (int)(INT_PTR)SendMessageA(hList, LVM_GETHEADER, 0, 0);
    nCol = nCol ? (int)SendMessageA((HWND)(INT_PTR)nCol, HDM_GETITEMCOUNT, 0, 0) : 0;
    nRow = (int)SendMessageA(hList, LVM_GETITEMCOUNT, 0, 0);

    /* 表头 */
    for (c = 0; c < nCol; c++) {
        LVCOLUMNA col;
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT;
        col.pszText = cell;
        col.cchTextMax = sizeof(cell);
        cell[0] = 0;
        SendMessageA(hList, LVM_GETCOLUMNA, (WPARAM)c, (LPARAM)&col);
        /* TSV：把内嵌 tab/换行替换成空格 */
        for (char *p = cell; *p; p++)
            if (*p == '\t' || *p == '\r' || *p == '\n') *p = ' ';
        if (c) fputc('\t', f);
        fputs(cell, f);
    }
    fputs("\r\n", f);

    /* 行 */
    for (r = 0; r < nRow; r++) {
        for (c = 0; c < nCol; c++) {
            LVITEMA it;
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = r;
            it.iSubItem = c;
            it.pszText = cell;
            it.cchTextMax = sizeof(cell);
            cell[0] = 0;
            SendMessageA(hList, LVM_GETITEMTEXTA, (WPARAM)r, (LPARAM)&it);
            for (char *p = cell; *p; p++)
                if (*p == '\t' || *p == '\r' || *p == '\n') *p = ' ';
            if (c) fputc('\t', f);
            fputs(cell, f);
        }
        fputs("\r\n", f);
        written++;
    }
    fclose(f);
    if (OutRows)
        *OutRows = written;
    return TRUE;
}

/* 导出到 %TEMP%\<Name>.tsv 并在状态栏回报路径。 */
BOOL FeListExportDefault(HWND hList, HWND StatusWnd, const char *Name)
{
    char path[MAX_PATH];
    char msg[MAX_PATH + 128];
    ULONG rows = 0;

    GetTempPathA(MAX_PATH, path);
    strcat_s(path, sizeof(path), Name);
    strcat_s(path, sizeof(path), ".tsv");
    if (!FeListExportToFile(hList, path, &rows)) {
        if (StatusWnd) {
            sprintf_s(msg, sizeof(msg), "%s: export failed", Name);
            SetWindowTextA(StatusWnd, msg);
        }
        return FALSE;
    }
    if (StatusWnd) {
        sprintf_s(msg, sizeof(msg), "%s exported (%lu rows): %s", Name, rows, path);
        SetWindowTextA(StatusWnd, msg);
    }
    return TRUE;
}

/* ---- 破坏性操作确认（原版所有删除/卸载/终止都要二次确认） ---- */

BOOL FeConfirmDanger(HWND Owner, const char *Title, const char *Detail)
{
    char msg[1024];

    sprintf_s(msg, sizeof(msg),
              "%s\n\n%s\n\nThis action may be irreversible. Continue?",
              Title, Detail ? Detail : "");
    return MessageBoxA(Owner, msg, "Confirm", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

/* ---- 列表选中项取某一列的文本（跨页复用，替代各页自己的 XXXColumnText） ---- */

BOOL FeListGetCellText(HWND hList, int Sel, int Sub, char *Out, int OutChars)
{
    LVITEMA it;

    if (!hList || !Out || OutChars <= 0)
        return FALSE;
    Out[0] = 0;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = Sel;
    it.iSubItem = Sub;
    it.pszText = Out;
    it.cchTextMax = OutChars;
    return SendMessageA(hList, LVM_GETITEMTEXTA, (WPARAM)Sel, (LPARAM)&it) != 0;
}

int FeListGetSel(HWND hList)
{
    if (!hList)
        return -1;
    return (int)SendMessageA(hList, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
}

int FeListGetCount(HWND hList)
{
    if (!hList)
        return 0;
    return (int)SendMessageA(hList, LVM_GETITEMCOUNT, 0, 0);
}

/* ---- 右键命中行：如果右键点在某行上则选中它（Windows 列表的常规行为） ---- */

void FeListSelectUnderCursor(HWND hList, int X, int Y)
{
    POINT pt;
    LVHITTESTINFO ht;

    if (!hList)
        return;
    pt.x = X;
    pt.y = Y;
    ScreenToClient(hList, &pt);
    ht.pt = pt;
    if (ListView_HitTest(hList, &ht) >= 0) {
        ListView_SetItemState(hList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(hList, ht.iItem, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    }
}