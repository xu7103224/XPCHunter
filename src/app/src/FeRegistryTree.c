// ============================================================================
// FeRegistryTree.c — Registry 页 Key 子页的树形导航（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.5 的最后一项目标：原版 CRegEditDialog
// 是 Tree+List 的完整编辑器，我方此前只有 List。本文件补上 Tree。
//
// 设计：
//   - 根节点 = 5 个预定义 HKEY（HKLM/HKCU/HKCR/HKU/HKCC）
//   - 懒加载：只展开用户点开的节点（避免一次枚举整个注册表）
//   - TVN_ITEMEXPANDING 时填充子键
//   - 选中节点 → 更新 g_RgCurKey → 刷新右侧列表
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RG_TREE_MAX_DEPTH 24

/* 节点数据：用 malloc 的字符串保存完整路径 */
static void RgTreeFreeItemData(HTREEITEM hItem);

/* 取节点保存的路径字符串（TVM_GETITEMDATA 不存在，要用 TVM_GETITEMA + TVIF_PARAM） */
static char *RgTreeGetPath(HWND hTree, HTREEITEM hItem)
{
    TVITEMA it;

    if (!hTree || !hItem)
        return NULL;
    ZeroMemory(&it, sizeof(it));
    it.mask = TVIF_PARAM;
    it.hItem = hItem;
    if (!SendMessageA(hTree, TVM_GETITEMA, 0, (LPARAM)&it))
        return NULL;
    return (char *)it.lParam;
}

static void RgW2A(const WCHAR *In, char *Out, int OutChars)
{
    if (!Out || OutChars <= 0)
        return;
    Out[0] = 0;
    if (!In)
        return;
    WideCharToMultiByte(CP_UTF8, 0, In, -1, Out, OutChars, NULL, NULL);
}

/* 往树里插入一个子节点，Data 为完整路径（堆分配，由 RgTreeFreeItemData 释放） */
static HTREEITEM RgTreeInsert(HWND hTree, HTREEITEM hParent, const char *Name,
                              const char *FullPath)
{
    TVINSERTSTRUCTA tv;
    char *dup;

    if (!hTree || !Name)
        return NULL;
    dup = (char *)malloc(strlen(FullPath ? FullPath : Name) + 1);
    if (!dup)
        return NULL;
    strcpy(dup, FullPath ? FullPath : Name);

    ZeroMemory(&tv, sizeof(tv));
    tv.hParent = hParent ? hParent : TVI_ROOT;
    tv.hInsertAfter = TVI_LAST;
    tv.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_CHILDREN;
    tv.item.pszText = (LPSTR)Name;
    tv.item.lParam = (LPARAM)dup;
    /* 先假定有子键（显示 + 号），展开时才知道真实情况 */
    tv.item.cChildren = 1;
    return (HTREEITEM)SendMessageA(hTree, TVM_INSERTITEMA, 0, (LPARAM)&tv);
}

void RgBuildRoots(void)
{
    HWND hTree = g_hRgTree;
    HTREEITEM hItem;

    if (!hTree)
        return;
    TreeView_DeleteAllItems(hTree);
    hItem = RgTreeInsert(hTree, TVI_ROOT, "HKEY_LOCAL_MACHINE", "HKLM");
    if (hItem) SendMessageA(hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hItem);
    RgTreeInsert(hTree, TVI_ROOT, "HKEY_CURRENT_USER", "HKCU");
    RgTreeInsert(hTree, TVI_ROOT, "HKEY_CLASSES_ROOT", "HKCR");
    RgTreeInsert(hTree, TVI_ROOT, "HKEY_USERS", "HKU");
    RgTreeInsert(hTree, TVI_ROOT, "HKEY_CURRENT_CONFIG", "HKCC");
}

/* 把 "HKLM\SOFTWARE\..." 拆成 root + 子路径 */
static HKEY RgTreeRootOf(const char *Path, const char **Sub)
{
    if (!Path || !Path[0]) { *Sub = ""; return NULL; }
    if (_strnicmp(Path, "HKLM", 4) == 0) { *Sub = Path + 4; return HKEY_LOCAL_MACHINE; }
    if (_strnicmp(Path, "HKCU", 4) == 0) { *Sub = Path + 4; return HKEY_CURRENT_USER; }
    if (_strnicmp(Path, "HKCR", 4) == 0) { *Sub = Path + 4; return HKEY_CLASSES_ROOT; }
    if (_strnicmp(Path, "HKU",  3) == 0) { *Sub = Path + 3; return HKEY_USERS; }
    if (_strnicmp(Path, "HKCC", 4) == 0) { *Sub = Path + 4; return HKEY_CURRENT_CONFIG; }
    *Sub = Path;
    return NULL;
}

/* 填充某个节点的直接子键（懒加载） */
static void RgTreePopulate(HWND hTree, HTREEITEM hItem)
{
    char *Path;
    const char *sub;
    HKEY root, hk;
    WCHAR wsub[512];
    DWORD idx = 0;

    if (!hTree || !hItem)
        return;
    Path = RgTreeGetPath(hTree, hItem);
    if (!Path || !Path[0])
        return;
    /* 已填充过则不重复 */
    if (SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)hItem) != 0)
        return;

    root = RgTreeRootOf(Path, &sub);
    if (!root)
        return;
    while (*sub == '\\')
        sub++;
    if (sub[0]) {
        MultiByteToWideChar(CP_UTF8, 0, sub, -1, wsub, 512);
        if (RegOpenKeyExW(root, wsub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
            SendMessageA(hTree, TVM_SETITEMHEIGHT, 0, 0);
            return;
        }
    } else {
        hk = root;
    }

    for (;;) {
        WCHAR wname[256];
        DWORD cch = 256;
        char nameA[256], full[1024];
        HTREEITEM hChild;

        if (RegEnumKeyExW(hk, idx++, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        RgW2A(wname, nameA, sizeof(nameA));
        if (!nameA[0])
            continue;
        sprintf_s(full, sizeof(full), "%s\\%s", Path, nameA);
        hChild = RgTreeInsert(hTree, hItem, nameA, full);
        (void)hChild;
    }
    if (hk != root)
        RegCloseKey(hk);
}

/* 清空整棵树的 item data（销毁前调用） */
void RgTreeFreeAll(void)
{
    HWND hTree = g_hRgTree;
    HTREEITEM hItem;

    if (!hTree)
        return;
    hItem = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_ROOT, 0);
    while (hItem) {
        RgTreeFreeItemData(hItem);
        hItem = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_NEXT, (LPARAM)hItem);
    }
}

static void RgTreeFreeItemData(HTREEITEM hItem)
{
    HWND hTree = g_hRgTree;
    HTREEITEM hChild;

    if (!hTree || !hItem)
        return;
    hChild = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)hItem);
    while (hChild) {
        RgTreeFreeItemData(hChild);
        hChild = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_NEXT, (LPARAM)hChild);
    }
    {
        char *p = RgTreeGetPath(hTree, hItem);
        if (p) {
            free(p);
            TVITEMA it;
            ZeroMemory(&it, sizeof(it));
            it.mask = TVIF_PARAM;
            it.hItem = hItem;
            it.lParam = 0;
            SendMessageA(hTree, TVM_SETITEMA, 0, (LPARAM)&it);
        }
    }
}

/* 处理 TVN_ITEMEXPANDING：展开时懒加载子键 */
void RgOnTreeExpanding(NMTREEVIEWA *nm)
{
    if (!nm || !g_hRgTree)
        return;
    if (nm->action == TVE_EXPAND)
        RgTreePopulate(g_hRgTree, nm->itemNew.hItem);
}

/* 处理 TVN_SELCHANGED：选中节点 → 更新路径 → 刷新列表 */
void RgOnTreeSelChanged(void)
{
    HTREEITEM hSel;
    char *Path;
    char status[700];

    if (!g_hRgTree)
        return;
    hSel = (HTREEITEM)SendMessageA(g_hRgTree, TVM_GETNEXTITEM, TVGN_CARET, 0);
    if (!hSel)
        return;
    Path = RgTreeGetPath(g_hRgTree, hSel);
    if (!Path || !Path[0])
        return;

    strcpy_s(g_RgCurKey, sizeof(g_RgCurKey), Path);
    strcpy_s(g_RgPath, sizeof(g_RgPath), Path);
    /* 深度 = 反斜杠数 */
    {
        int d = 0;
        const char *p = Path;
        while (*p) {
            if (*p == '\\')
                d++;
            p++;
        }
        g_RgKeyDepth = d;
    }
    /* 路径框同步 */
    {
        HWND hPath = GetDlgItem(g_hMainWnd, IDC_RG_PATH);
        if (hPath)
            SetWindowTextA(hPath, Path);
    }
    sprintf_s(status, sizeof(status), "Key: %s", Path);
    if (g_hRgStatus)
        SetWindowTextA(g_hRgStatus, status);
    RgFillKeyViewPublic(Path);
}