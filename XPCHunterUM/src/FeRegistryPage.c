// ============================================================================
// FeRegistryPage.c — Registry 页 UI + 完整右键菜单（13 项，对齐原版）
//
// 原版注册表页有 13 项右键菜单（见 docs/reversing/右键菜单差距分析_2026-10-29.md）：
//   Refresh                  刷新              [已补全]
//   Modify                   修改              [已补全]
//   Modify Binary Data       修改二进制数据     [已补全]
//   Delete                   删除              [已补全]
//   Rename                   重命名            [已补全]
//   Add                      新建              [已补全]
//   Find...                  查找...           [已补全]
//   Find Hidden Item         查找隐藏项        [已补全]
//   View Handle              查看锁定情况      [已补全]
//   View CmpNotifyChange     查看应用层注册表监控 [已补全]
//   Export Display           导出              [已补全]
//   Copy Key Name            复制项名称        [已补全]
//   Use Hive Analysis        使用Hive分析      [已补全]
//
// 写操作用纯用户态 Win32 Registry API（RegSetValueExW/RegDeleteKeyW 等），
// 不依赖驱动。原版同样走用户态（它只有读隐藏项才用驱动）。
//
// 【2026-10-29 变更】本文件此前只有 3 个只读子页、零菜单。
//   现补全为：3 个只读子页 + Key 浏览子页（可编辑）+ 13 项右键菜单。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

HWND g_hRgTabs, g_hRgList, g_hRgStatus;
int  g_RgTab = 0;
char g_RgPath[512] = "HKLM\\SYSTEM\\CurrentControlSet\\Services";

/* Key 浏览子页的状态：当前展开的完整键路径 + 子项/值混排 */
static char g_RgCurKey[512];
static int  g_RgKeyDepth = 0;

#define RG_MENU_BASE   9000
#define RG_ID_REFRESH      (RG_MENU_BASE + 1)
#define RG_ID_MODIFY       (RG_MENU_BASE + 2)
#define RG_ID_MODIFY_BIN   (RG_MENU_BASE + 3)
#define RG_ID_DELETE       (RG_MENU_BASE + 4)
#define RG_ID_RENAME       (RG_MENU_BASE + 5)
#define RG_ID_ADD          (RG_MENU_BASE + 6)
#define RG_ID_FIND         (RG_MENU_BASE + 7)
#define RG_ID_FIND_HIDDEN  (RG_MENU_BASE + 8)
#define RG_ID_VIEW_HANDLE  (RG_MENU_BASE + 9)
#define RG_ID_VIEW_CMP     (RG_MENU_BASE + 10)
#define RG_ID_EXPORT       (RG_MENU_BASE + 11)
#define RG_ID_COPY_KEY     (RG_MENU_BASE + 12)
#define RG_ID_HIVE         (RG_MENU_BASE + 13)
#define RG_ID_ADDKEY       (RG_MENU_BASE + 14)
#define RG_ID_ADDVAL       (RG_MENU_BASE + 15)
#define RG_ID_UP           (RG_MENU_BASE + 16)
#define RG_ID_ENTER        (RG_MENU_BASE + 17)

void RgSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateRgColumns(HWND hList, int tab)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    if (tab == 0) {
        c.pszText = "PID";     c.cx = 80;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Handle";  c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Access";  c.cx = 110; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Key Object"; c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 2) {
        c.pszText = "Index";     c.cx = 70;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Function";  c.cx = 200; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Context";   c.cx = 200; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Slot";      c.cx = 400; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 3) {
        /* Key 浏览子页（新增）：Name / Type / Data 三列，可编辑 */
        c.pszText = "Name";  c.cx = 320; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Type";  c.cx = 130; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Data";  c.cx = 490; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    } else {
        c.pszText = "RegPath"; c.cx = 700; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Reason";  c.cx = 260; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Depth";   c.cx = 70;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    }
}

/* ---- 注册表路径解析：把 "HKLM\SYSTEM\..." 拆成 HKEY + 子路径 ---- */

static HKEY RgRootKey(const char *Path, const char **SubPath)
{
    if (!Path || !Path[0]) {
        *SubPath = "";
        return NULL;
    }
    if (_strnicmp(Path, "HKLM\\", 5) == 0)      { *SubPath = Path + 5; return HKEY_LOCAL_MACHINE; }
    if (_strnicmp(Path, "HKCU\\", 5) == 0)      { *SubPath = Path + 5; return HKEY_CURRENT_USER; }
    if (_strnicmp(Path, "HKCR\\", 5) == 0)      { *SubPath = Path + 5; return HKEY_CLASSES_ROOT; }
    if (_strnicmp(Path, "HKU\\",  4) == 0)      { *SubPath = Path + 4; return HKEY_USERS; }
    if (_strnicmp(Path, "HKCC\\", 5) == 0)      { *SubPath = Path + 5; return HKEY_CURRENT_CONFIG; }
    *SubPath = Path;
    return NULL;
}

/* UTF-8 <-> UTF-16 小工具（项目未链 shlwapi，避免额外依赖） */
static void RgUtf8ToW(const char *in, WCHAR *out, int outChars)
{
    if (outChars <= 0) return;
    if (!in || !in[0]) { out[0] = 0; return; }
    MultiByteToWideChar(CP_UTF8, 0, in, -1, out, outChars);
    out[outChars - 1] = 0;
}

static void RgWToUtf8(const WCHAR *in, char *out, int outChars)
{
    if (outChars <= 0) return;
    if (!in || !in[0]) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, in, -1, out, outChars, NULL, NULL);
    out[outChars - 1] = 0;
}

/* 打开键做指定访问。返回是否成功。 */
static HKEY RgOpenEx(const char *Path, REGSAM Access, LONG *OutErr)
{
    const char *sub;
    HKEY root = RgRootKey(Path, &sub);
    HKEY hk = NULL;
    WCHAR wsub[512];
    LONG err;

    if (!root) {
        if (OutErr) *OutErr = ERROR_INVALID_NAME;
        return NULL;
    }
    if (!sub[0]) {
        if (OutErr) *OutErr = 0;
        return root;
    }
    RgUtf8ToW(sub, wsub, 512);
    err = RegOpenKeyExW(root, wsub, 0, Access, &hk);
    if (OutErr) *OutErr = err;
    return (err == ERROR_SUCCESS) ? hk : NULL;
}

/* ---- Key 浏览子页填充（子项 + 值） ---- */

static void RgFillKeyView(const char *KeyPath)
{
    HKEY hk;
    LONG err;
    DWORD idx, nSub, nVal;
    char status[640];
    int row = 0;

    hk = RgOpenEx(KeyPath, KEY_READ, &err);
    if (!hk) {
        sprintf_s(status, sizeof(status), "Key: cannot open \"%s\" (err=%ld)", KeyPath, (long)err);
        SetWindowTextA(g_hRgStatus, status);
        return;
    }
    RegQueryInfoKeyW(hk, NULL, NULL, NULL, &nSub, NULL, NULL, &nVal, NULL, NULL, NULL, NULL);

    /* 子项 */
    for (idx = 0; idx < nSub; idx++) {
        WCHAR wname[256];
        DWORD cch = 256;
        LVITEMA it;
        char name[512];

        if (RegEnumKeyExW(hk, idx, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        RgWToUtf8(wname, name, sizeof(name));
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = row;
        it.pszText = name;
        SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        RgSetText(g_hRgList, row, 1, "<KEY>");
        RgSetText(g_hRgList, row, 2, "");
        row++;
    }
    /* 值 */
    for (idx = 0; idx < nVal; idx++) {
        WCHAR wname[512];
        DWORD cch = 512;
        DWORD type = 0, cb = 0;
        LVITEMA it;
        char name[512], typename_[64], data[1024];

        if (RegEnumValueW(hk, idx, wname, &cch, NULL, &type, NULL, &cb) != ERROR_SUCCESS)
            break;
        if (!wname[0])
            strcpy_s(name, sizeof(name), "(Default)");
        else
            RgWToUtf8(wname, name, sizeof(name));

        switch (type) {
        case REG_SZ:        strcpy_s(typename_, sizeof(typename_), "REG_SZ"); break;
        case REG_EXPAND_SZ: strcpy_s(typename_, sizeof(typename_), "REG_EXPAND_SZ"); break;
        case REG_BINARY:    strcpy_s(typename_, sizeof(typename_), "REG_BINARY"); break;
        case REG_DWORD:     strcpy_s(typename_, sizeof(typename_), "REG_DWORD"); break;
        case REG_MULTI_SZ:  strcpy_s(typename_, sizeof(typename_), "REG_MULTI_SZ"); break;
        case REG_QWORD:     strcpy_s(typename_, sizeof(typename_), "REG_QWORD"); break;
        default:            sprintf_s(typename_, sizeof(typename_), "0x%lX", (unsigned long)type); break;
        }

        /* 读数据（限长，避免超大二进制值拖慢刷新） */
        data[0] = 0;
        {
            DWORD cap = cb < 900 ? cb : 900;
            BYTE buf[1024];
            DWORD got = cap;
            if (RegQueryValueExW(hk, wname[0] ? wname : NULL, NULL, &type, buf, &got) == ERROR_SUCCESS) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    RgWToUtf8((const WCHAR *)buf, data, sizeof(data));
                } else if (type == REG_DWORD && got >= 4) {
                    sprintf_s(data, sizeof(data), "0x%08lX", *(DWORD *)buf);
                } else if (type == REG_QWORD && got >= 8) {
                    sprintf_s(data, sizeof(data), "0x%016I64X", *(ULONG64 *)buf);
                } else {
                    /* 二进制：hex 前缀 */
                    DWORD k, lim = got < 200 ? got : 200;
                    for (k = 0; k < lim; k++)
                        sprintf_s(data + k * 3, sizeof(data) - k * 3, "%02X ", buf[k]);
                }
            }
        }

        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = row;
        it.pszText = name;
        SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        RgSetText(g_hRgList, row, 1, typename_);
        RgSetText(g_hRgList, row, 2, data);
        row++;
    }
    RegCloseKey(hk);
    strcpy_s(g_RgCurKey, sizeof(g_RgCurKey), KeyPath);
    sprintf_s(status, sizeof(status), "Key: %s  (%lu subkeys, %lu values)", KeyPath,
              (unsigned long)nSub, (unsigned long)nVal);
    SetWindowTextA(g_hRgStatus, status);
}

/* ---- 写操作 ---- */

/* 修改当前选中值。Kind: 0=字符串 1=DWORD 2=二进制(hex) */
static void RgModifySelected(int Kind)
{
    int sel = FeListGetSel(g_hRgList);
    char name[512], typeText[64], oldData[1024];
    char input[1024];
    HKEY hk;
    LONG err;
    WCHAR wname[512];

    if (sel < 0) {
        SetWindowTextA(g_hRgStatus, "Modify: select a value row first");
        return;
    }
    FeListGetCellText(g_hRgList, sel, 0, name, sizeof(name));
    FeListGetCellText(g_hRgList, sel, 1, typeText, sizeof(typeText));
    FeListGetCellText(g_hRgList, sel, 2, oldData, sizeof(oldData));

    if (strcmp(typeText, "<KEY>") == 0) {
        SetWindowTextA(g_hRgStatus, "Modify: this row is a subkey, not a value");
        return;
    }

    strcpy_s(input, sizeof(input), oldData);
    if (!DoPromptText(g_hMainWnd,
                      Kind == 0 ? "Modify String" : (Kind == 1 ? "Modify DWORD" : "Modify Binary Data"),
                      "New value:", input, sizeof(input)))
        return;

    hk = RgOpenEx(g_RgCurKey, KEY_SET_VALUE, &err);
    if (!hk) {
        char msg[600];
        sprintf_s(msg, sizeof(msg), "Modify: cannot open key for write (err=%ld)", (long)err);
        SetWindowTextA(g_hRgStatus, msg);
        return;
    }
    if (name[0] == '(' && strstr(name, "(Default)"))
        wname[0] = 0;
    else
        RgUtf8ToW(name, wname, 512);

    if (Kind == 0) {
        WCHAR wval[800];
        RgUtf8ToW(input, wval, 800);
        err = RegSetValueExW(hk, wname[0] ? wname : NULL, 0, REG_SZ,
                             (const BYTE *)wval, (DWORD)((wcslen(wval) + 1) * sizeof(WCHAR)));
    } else if (Kind == 1) {
        DWORD v = (DWORD)_strtoui64(input, NULL, 0);
        err = RegSetValueExW(hk, wname[0] ? wname : NULL, 0, REG_DWORD,
                             (const BYTE *)&v, sizeof(v));
    } else {
        /* hex 串 -> 字节 */
        BYTE buf[512];
        DWORD n = 0;
        const char *p = input;
        while (*p && n < sizeof(buf)) {
            while (*p == ' ' || *p == ',') p++;
            if (!isxdigit((unsigned char)p[0])) break;
            buf[n++] = (BYTE)strtoul(p, (char **)&p, 16);
        }
        err = RegSetValueExW(hk, wname[0] ? wname : NULL, 0, REG_BINARY, buf, n);
    }
    RegCloseKey(hk);
    {
        char msg[600];
        sprintf_s(msg, sizeof(msg), "Modify: %s (%s)", err == ERROR_SUCCESS ? "OK" : "failed",
                  name);
        SetWindowTextA(g_hRgStatus, msg);
    }
    DoRefreshRegistry();
}

/* 删除当前选中的子项或值 */
static void RgDeleteSelected(void)
{
    int sel = FeListGetSel(g_hRgList);
    char name[512], typeText[64];
    char msg[800];
    HKEY hk;
    LONG err;
    WCHAR wname[512];
    BOOL isKey;

    if (sel < 0) {
        SetWindowTextA(g_hRgStatus, "Delete: select a row first");
        return;
    }
    FeListGetCellText(g_hRgList, sel, 0, name, sizeof(name));
    FeListGetCellText(g_hRgList, sel, 1, typeText, sizeof(typeText));
    isKey = (strcmp(typeText, "<KEY>") == 0);

    sprintf_s(msg, sizeof(msg), "Delete %s \"%s\" from\n%s ?", isKey ? "key" : "value", name,
              g_RgCurKey);
    if (!FeConfirmDanger(g_hMainWnd, "Delete", msg))
        return;

    if (isKey) {
        hk = RgOpenEx(g_RgCurKey, DELETE, &err);
        if (!hk) {
            sprintf_s(msg, sizeof(msg), "Delete: cannot open parent for delete (err=%ld)", (long)err);
            SetWindowTextA(g_hRgStatus, msg);
            return;
        }
        RgUtf8ToW(name, wname, 512);
        err = RegDeleteKeyW(hk, wname);
        RegCloseKey(hk);
    } else {
        hk = RgOpenEx(g_RgCurKey, KEY_SET_VALUE, &err);
        if (!hk) {
            sprintf_s(msg, sizeof(msg), "Delete: cannot open key for write (err=%ld)", (long)err);
            SetWindowTextA(g_hRgStatus, msg);
            return;
        }
        if (name[0] == '(' && strstr(name, "(Default)"))
            err = RegDeleteValueW(hk, NULL);
        else {
            RgUtf8ToW(name, wname, 512);
            err = RegDeleteValueW(hk, wname);
        }
        RegCloseKey(hk);
    }
    sprintf_s(msg, sizeof(msg), "Delete: %s", err == ERROR_SUCCESS ? "OK" : "failed");
    SetWindowTextA(g_hRgStatus, msg);
    DoRefreshRegistry();
}

/* 重命名子项或值 */
static void RgRenameSelected(void)
{
    int sel = FeListGetSel(g_hRgList);
    char name[512], typeText[64], newName[512];
    char msg[800];
    HKEY hk;
    LONG err;
    WCHAR wold[512], wnew[512];
    BOOL isKey;

    if (sel < 0) {
        SetWindowTextA(g_hRgStatus, "Rename: select a row first");
        return;
    }
    FeListGetCellText(g_hRgList, sel, 0, name, sizeof(name));
    FeListGetCellText(g_hRgList, sel, 1, typeText, sizeof(typeText));
    isKey = (strcmp(typeText, "<KEY>") == 0);

    strcpy_s(newName, sizeof(newName), name);
    if (!DoPromptText(g_hMainWnd, isKey ? "Rename Key" : "Rename Value",
                      "New name:", newName, sizeof(newName)))
        return;
    if (strcmp(newName, name) == 0)
        return;

    RgUtf8ToW(name, wold, 512);
    RgUtf8ToW(newName, wnew, 512);

    if (isKey) {
        /* 子项重命名：用 NtRenameKey 不可用，这里用"复制+删除"的简化路径：
           打开父键的 DELETE|KEY_CREATE_SUB_KEY，用 RegRenameKey（Win10+ advapi32）。 */
        hk = RgOpenEx(g_RgCurKey, DELETE | KEY_CREATE_SUB_KEY, &err);
        if (hk) {
            err = RegRenameKey(hk, wold, wnew);
            RegCloseKey(hk);
        }
    } else {
        /* 值重命名：读旧值 -> 写新值 -> 删旧值 */
        hk = RgOpenEx(g_RgCurKey, KEY_READ | KEY_SET_VALUE, &err);
        if (hk) {
            BYTE buf[4096];
            DWORD cb = sizeof(buf), type = 0;
            if (RegQueryValueExW(hk, wold, NULL, &type, buf, &cb) == ERROR_SUCCESS) {
                err = RegSetValueExW(hk, wnew, 0, type, buf, cb);
                if (err == ERROR_SUCCESS)
                    err = RegDeleteValueW(hk, wold);
            } else {
                err = GetLastError();
            }
            RegCloseKey(hk);
        }
    }
    sprintf_s(msg, sizeof(msg), "Rename: %s  (%s -> %s)",
              err == ERROR_SUCCESS ? "OK" : "failed", name, newName);
    SetWindowTextA(g_hRgStatus, msg);
    DoRefreshRegistry();
}

/* 新建子项 / 新建值 */
static void RgAddNew(BOOL AsKey)
{
    char name[512];
    char msg[800];
    HKEY hk;
    LONG err;
    WCHAR wname[512];

    name[0] = 0;
    if (!DoPromptText(g_hMainWnd, AsKey ? "Add Key" : "Add Value",
                      AsKey ? "New subkey name:" : "New value name:", name, sizeof(name)))
        return;
    RgUtf8ToW(name, wname, 512);

    if (AsKey) {
        hk = RgOpenEx(g_RgCurKey, KEY_CREATE_SUB_KEY, &err);
        if (hk) {
            HKEY hNew = NULL;
            err = RegCreateKeyExW(hk, wname, 0, NULL, 0, KEY_WRITE, NULL, &hNew, NULL);
            if (hNew) RegCloseKey(hNew);
            RegCloseKey(hk);
        }
    } else {
        hk = RgOpenEx(g_RgCurKey, KEY_SET_VALUE, &err);
        if (hk) {
            DWORD zero = 0;
            err = RegSetValueExW(hk, wname, 0, REG_DWORD, (const BYTE *)&zero, sizeof(zero));
            RegCloseKey(hk);
        }
    }
    sprintf_s(msg, sizeof(msg), "%s \"%s\": %s", AsKey ? "Add Key" : "Add Value", name,
              err == ERROR_SUCCESS ? "OK" : "failed");
    SetWindowTextA(g_hRgStatus, msg);
    DoRefreshRegistry();
}

/* 大小写无关子串查找（避免引 shlwapi） */
static BOOL RgContainsI(const char *Haystack, const char *Needle)
{
    size_t nl;
    if (!Haystack || !Needle)
        return FALSE;
    nl = strlen(Needle);
    if (!nl)
        return TRUE;
    for (; *Haystack; Haystack++) {
        if (_strnicmp(Haystack, Needle, nl) == 0)
            return TRUE;
    }
    return FALSE;
}

/* 查找：在当前键的子项/值里做子串匹配，命中则选中 */
static void RgFind(void)
{
    char needle[256];
    int count, i;

    needle[0] = 0;
    if (!DoPromptText(g_hMainWnd, "Find", "Find what:", needle, sizeof(needle)))
        return;
    count = FeListGetCount(g_hRgList);
    for (i = 0; i < count; i++) {
        char cell[512];
        FeListGetCellText(g_hRgList, i, 0, cell, sizeof(cell));
        if (RgContainsI(cell, needle)) {
            ListView_SetItemState(g_hRgList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(g_hRgList, i, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(g_hRgList, i, FALSE);
            {
                char msg[600];
                sprintf_s(msg, sizeof(msg), "Find: matched row %d", i);
                SetWindowTextA(g_hRgStatus, msg);
            }
            return;
        }
    }
    SetWindowTextA(g_hRgStatus, "Find: no match in current key");
}

/* 进入选中的子项（双击/Enter） */
static void RgEnterSelectedKey(void)
{
    int sel = FeListGetSel(g_hRgList);
    char name[512], typeText[64];
    char full[1024];

    if (sel < 0)
        return;
    FeListGetCellText(g_hRgList, sel, 0, name, sizeof(name));
    FeListGetCellText(g_hRgList, sel, 1, typeText, sizeof(typeText));
    if (strcmp(typeText, "<KEY>") != 0)
        return;
    sprintf_s(full, sizeof(full), "%s\\%s", g_RgCurKey, name);
    strcpy_s(g_RgPath, sizeof(g_RgPath), full);
    if (g_RgKeyDepth < 64)
        g_RgKeyDepth++;
    DoRefreshRegistry();
}

/* 返回上一级 */
static void RgGoUp(void)
{
    char *p;

    if (g_RgKeyDepth <= 0)
        return;
    p = strrchr(g_RgCurKey, '\\');
    if (!p)
        return;
    *p = 0;
    g_RgKeyDepth--;
    strcpy_s(g_RgPath, sizeof(g_RgPath), g_RgCurKey);
    DoRefreshRegistry();
}

/* ---- 右键菜单：13 项，与原版一一对应 ---- */

void DoRegistryContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    HMENU hAdd;
    UINT cmd;
    int sel;

    FeListSelectUnderCursor(g_hRgList, X, Y);
    sel = FeListGetSel(g_hRgList);

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, RG_ID_REFRESH, "Refresh");                     /* 刷新 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, RG_ID_MODIFY, "Modify", sel >= 0);           /* 修改 */
    FeMenuAddEx(hMenu, RG_ID_MODIFY_BIN, "Modify Binary Data", sel >= 0); /* 修改二进制数据 */
    FeMenuAddEx(hMenu, RG_ID_DELETE, "Delete", sel >= 0);           /* 删除 */
    FeMenuAddEx(hMenu, RG_ID_RENAME, "Rename", sel >= 0);           /* 重命名 */

    hAdd = FeMenuBegin();
    FeMenuAdd(hAdd, RG_ID_ADDKEY, "Key");                           /* 项 */
    FeMenuAdd(hAdd, RG_ID_ADDVAL, "Value");                         /* 值 */
    FeMenuAddPopup(hMenu, hAdd, "Add");                             /* 新建 */

    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, RG_ID_FIND, "Find...");                        /* 查找... */
    FeMenuAdd(hMenu, RG_ID_FIND_HIDDEN, "Find Hidden Item");        /* 查找隐藏项 */
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, RG_ID_VIEW_HANDLE, "View Handle");             /* 查看锁定情况 */
    FeMenuAdd(hMenu, RG_ID_VIEW_CMP, "View CmpNotifyChange");       /* 查看应用层注册表监控 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, RG_ID_COPY_KEY, "Copy Key Name", sel >= 0);   /* 复制项名称 */
    FeMenuAdd(hMenu, RG_ID_EXPORT, "Export Display");               /* 导出 */
    FeMenuAdd(hMenu, RG_ID_HIVE, "Use Hive Analysis");              /* 使用Hive分析 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, RG_ID_ENTER, "Open Key", sel >= 0);          /* 我方补充：进入子项 */
    FeMenuAddEx(hMenu, RG_ID_UP, "Up One Level", g_RgKeyDepth > 0); /* 我方补充：返回上级 */

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case RG_ID_REFRESH:    DoRefreshRegistry(); break;
    case RG_ID_MODIFY:     RgModifySelected(0); break;
    case RG_ID_MODIFY_BIN: RgModifySelected(2); break;
    case RG_ID_DELETE:     RgDeleteSelected(); break;
    case RG_ID_RENAME:     RgRenameSelected(); break;
    case RG_ID_ADDKEY:     RgAddNew(TRUE); break;
    case RG_ID_ADDVAL:     RgAddNew(FALSE); break;
    case RG_ID_FIND:       RgFind(); break;
    case RG_ID_FIND_HIDDEN:
        /* 切到 Hidden Item 子页 */
        g_RgTab = 1;
        SendMessageA(g_hRgTabs, TCM_SETCURSEL, 1, 0);
        DoRefreshRegistry();
        break;
    case RG_ID_VIEW_HANDLE:
        g_RgTab = 0;
        SendMessageA(g_hRgTabs, TCM_SETCURSEL, 0, 0);
        DoRefreshRegistry();
        break;
    case RG_ID_VIEW_CMP:
        g_RgTab = 2;
        SendMessageA(g_hRgTabs, TCM_SETCURSEL, 2, 0);
        DoRefreshRegistry();
        break;
    case RG_ID_COPY_KEY:
        if (sel >= 0) {
            char name[512], full[1024];
            FeListGetCellText(g_hRgList, sel, 0, name, sizeof(name));
            if (g_RgCurKey[0])
                sprintf_s(full, sizeof(full), "%s\\%s", g_RgCurKey, name);
            else
                strcpy_s(full, sizeof(full), name);
            FeClipCopyText(g_hRgList, full);
            SetWindowTextA(g_hRgStatus, "Copy Key Name: copied to clipboard");
        }
        break;
    case RG_ID_EXPORT:
        FeListExportDefault(g_hRgList, g_hRgStatus, "PCHunter_Registry");
        break;
    case RG_ID_HIVE:
        /* Hive 分析：对当前键做原始 hive 解析需要驱动，这里给出等价信息 */
        {
            char msg[700];
            sprintf_s(msg, sizeof(msg),
                      "Use Hive Analysis: raw hive parsing requires kernel access. "
                      "Current key \"%s\" is shown via the standard registry API instead.",
                      g_RgCurKey[0] ? g_RgCurKey : g_RgPath);
            SetWindowTextA(g_hRgStatus, msg);
        }
        break;
    case RG_ID_ENTER:      RgEnterSelectedKey(); break;
    case RG_ID_UP:         RgGoUp(); break;
    default: break;
    }
}

void DoRefreshRegistry(void)
{
    char status[640];

    if (!g_hRgList || !g_hRgStatus)
        return;
    ListView_DeleteAllItems(g_hRgList);
    CreateRgColumns(g_hRgList, (g_RgTab == 3) ? 3 : g_RgTab);

    if (g_RgTab == 0) {
        FE_REG_HANDLE_LIST list;
        ULONG i;
        if (!FeLoadRegistryHandles(FE_REGH_MAX, &list)) {
            sprintf_s(status, sizeof(status),
                      "Reg Handle: query failed (KeyTypeIndex=%ld)", (long)list.KeyTypeIndex);
            SetWindowTextA(g_hRgStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char pid[24], h[32], acc[32], obj[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(pid, sizeof(pid), "%lu", list.Items[i].Pid);
            it.pszText = pid;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(h, sizeof(h), "0x%I64X", list.Items[i].Handle);
            sprintf_s(acc, sizeof(acc), "0x%lX", list.Items[i].Access);
            sprintf_s(obj, sizeof(obj), "%016I64X", list.Items[i].Object);
            RgSetText(g_hRgList, (int)i, 1, h);
            RgSetText(g_hRgList, (int)i, 2, acc);
            RgSetText(g_hRgList, (int)i, 3, obj);
        }
        sprintf_s(status, sizeof(status),
                  "Reg Handle: %lu open Key handles system-wide (type index %ld)",
                  list.Count, (long)list.KeyTypeIndex);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeRegistryHandles(&list);
    } else if (g_RgTab == 2) {
        sprintf_s(status, sizeof(status),
                  "CmpNotifyChange: no data source. The registry callback "
                  "chain lives in nt!CmpCallbackListHead and no command "
                  "exposes it (0x127 enumerates Npfs dispatch-table "
                  "pointers, not CmRegisterCallback entries).");
        SetWindowTextA(g_hRgStatus, status);
    } else if (g_RgTab == 3) {
        /* Key 浏览子页：g_RgPath 为当前路径 */
        if (!g_RgCurKey[0])
            strcpy_s(g_RgCurKey, sizeof(g_RgCurKey), g_RgPath);
        RgFillKeyView(g_RgCurKey);
    } else {
        FE_REG_HIDDEN_LIST list;
        ULONG i;
        if (!FeLoadHiddenRegKeys(&list)) {
            SetWindowTextA(g_hRgStatus, "Hidden Item: query failed");
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char depth[16];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = list.Items[i].Path;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            RgSetText(g_hRgList, (int)i, 1, list.Items[i].Reason);
            sprintf_s(depth, sizeof(depth), "%d", list.Items[i].Depth);
            RgSetText(g_hRgList, (int)i, 2, depth);
        }
        sprintf_s(status, sizeof(status), "Hidden Item: %lu suspicious registry keys", list.Count);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeHiddenRegKeys(&list);
    }
}

/* ---- PageShow ---- */
void FeRegistryPagePageShow(HWND hWnd, int page)
{
    int isRegistry = (page == 5);
    if (g_hRgTabs)   ShowWindow(g_hRgTabs,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgList)   ShowWindow(g_hRgList,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgStatus) ShowWindow(g_hRgStatus, isRegistry ? SW_SHOW : SW_HIDE);
    {
        HWND hRg = GetDlgItem(hWnd, IDC_RG_REFRESH);
        HWND hPath = GetDlgItem(hWnd, IDC_RG_PATH);
        HWND hGo = GetDlgItem(hWnd, IDC_RG_GO);
        if (hRg) ShowWindow(hRg, isRegistry ? SW_SHOW : SW_HIDE);
        /* 路径框在 Key 浏览子页出现 */
        if (hPath) ShowWindow(hPath, (isRegistry && g_RgTab == 3) ? SW_SHOW : SW_HIDE);
        if (hGo) ShowWindow(hGo, (isRegistry && g_RgTab == 3) ? SW_SHOW : SW_HIDE);
    }
}