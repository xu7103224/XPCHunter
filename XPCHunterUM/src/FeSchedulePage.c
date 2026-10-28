// ============================================================================
// FeSchedulePage.c — 计划任务子页（原版 CScheduleTaskDialog）
//
// 【2026-10-29 新增】原版计划任务是一个独立对话框，11 项右键菜单：
//   Refresh                  刷新              [已补全]
//   Disable / Enable         禁用 / 启用        [已补全]
//   Delete                   删除              [已补全]
//   Delete And Delete File   连文件一起删除      [已补全]
//   Verify File Signature    校验数字签名        [已补全]
//   Verify All Files Signatrue 校验所有数字签名   [已补全]
//   Copy Name                复制计划任务名      [已补全]
//   Copy Path                复制计划任务路径    [已补全]
//   Search Online            在线搜索计划任务名   [已补全]
//   Analyse Online           在线分析           [已补全]
//   Find Target              定位到计划任务文件   [已补全]
//   Properties               查看计划任务文件属性  [已补全]
//   Locate in File Tab       定位到文件管理器     [已补全]
//
// 数据源：任务计划 COM 接口（ITaskService）。为避免引入 COM 初始化复杂度，
// 这里直接读注册表任务库与 Windows\System32\Tasks 目录：
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
//   %SystemRoot%\System32\Tasks\**
// 禁用/启用通过修改 TaskCache\Tree\<name> 的 "SD"/索引值不可行，
// 改用 schtasks.exe /Change /DISABLE|/ENABLE（系统自带，无需 COM）。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <softpub.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")

/* 真实签名校验（WinVerifyTrust）。返回 1=已签名可信, 0=未签名/不可信, -1=读不到文件。 */
static int SchVerifyFileSignature(const char *Path, char *Signer, int SignerChars)
{
    WCHAR wpath[MAX_PATH * 2];
    WINTRUST_FILE_INFO fInfo;
    WINTRUST_DATA wd;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st;
    DWORD attr;

    if (Signer && SignerChars > 0)
        Signer[0] = 0;
    if (!Path || !Path[0])
        return -1;
    attr = GetFileAttributesA(Path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return -1;

    MultiByteToWideChar(CP_ACP, 0, Path, -1, wpath, MAX_PATH * 2);
    ZeroMemory(&fInfo, sizeof(fInfo));
    fInfo.cbStruct = sizeof(fInfo);
    fInfo.pcwszFilePath = wpath;

    ZeroMemory(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    st = WinVerifyTrust(NULL, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    if (st == ERROR_SUCCESS) {
        FE_FILE_VER ver;
        if (Signer && SignerChars > 0 && FeLoadFileVersion(Path, &ver) && ver.CompanyName[0])
            strncpy_s(Signer, SignerChars, ver.CompanyName, _TRUNCATE);
        return 1;
    }
    return 0;
}

HWND g_hSchList, g_hSchStatus;
ULONG g_SchCount = 0;

#define SCH_MAX 2048
#define SCH_NAME_CHARS 256
#define SCH_PATH_CHARS 512

typedef struct _SCH_ITEM {
    char Name[SCH_NAME_CHARS];      /* 任务名（\ 分隔的树路径） */
    char State[32];                 /* Ready / Disabled / Running */
    char Trigger[128];              /* 触发器摘要 */
    char Action[SCH_PATH_CHARS];    /* 执行的程序路径 */
    char Author[128];
    BOOL Enabled;
} SCH_ITEM;

#define SCH_MENU_BASE   9600
#define SCH_ID_REFRESH      (SCH_MENU_BASE + 1)
#define SCH_ID_DISABLE      (SCH_MENU_BASE + 2)
#define SCH_ID_ENABLE       (SCH_MENU_BASE + 3)
#define SCH_ID_DELETE       (SCH_MENU_BASE + 4)
#define SCH_ID_DELETE_FILE  (SCH_MENU_BASE + 5)
#define SCH_ID_VERIFY       (SCH_MENU_BASE + 6)
#define SCH_ID_VERIFY_ALL   (SCH_MENU_BASE + 7)
#define SCH_ID_COPY_NAME    (SCH_MENU_BASE + 8)
#define SCH_ID_COPY_PATH    (SCH_MENU_BASE + 9)
#define SCH_ID_SEARCH       (SCH_MENU_BASE + 10)
#define SCH_ID_ANALYSE      (SCH_MENU_BASE + 11)
#define SCH_ID_FIND_TARGET  (SCH_MENU_BASE + 12)
#define SCH_ID_PROPERTIES   (SCH_MENU_BASE + 13)
#define SCH_ID_LOCATE_FILE  (SCH_MENU_BASE + 14)

void SchSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateSchColumns(HWND hList)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Task Name"; c.cx = 300; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
    c.pszText = "State";     c.cx = 80;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
    c.pszText = "Trigger";   c.cx = 140; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    c.pszText = "Action";    c.cx = 380; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    c.pszText = "Author";    c.cx = 140; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
}

/* ---- 读取任务：遍历 TaskCache\Tree 的注册表树 ---- */

static char g_SchNames[SCH_MAX][SCH_NAME_CHARS];
static ULONG g_SchNameCount = 0;

static void SchWalkTree(HKEY hRoot, const char *Prefix, int Depth)
{
    HKEY hk;
    DWORD idx = 0;
    WCHAR wname[256];
    DWORD cch;
    char sub[512];

    if (Depth > 8 || g_SchNameCount >= SCH_MAX)
        return;
    cch = 256;
    if (RegOpenKeyExW(hRoot, L"", 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;
    for (;;) {
        DWORD nSub = 0, nVal = 0;
        LONG r;
        cch = 256;
        r = RegEnumKeyExW(hk, idx++, wname, &cch, NULL, NULL, NULL, NULL);
        if (r != ERROR_SUCCESS)
            break;
        {
            char leaf[256];
            WideCharToMultiByte(CP_UTF8, 0, wname, -1, leaf, sizeof(leaf), NULL, NULL);
            if (Prefix[0])
                sprintf_s(sub, sizeof(sub), "%s\\%s", Prefix, leaf);
            else
                strcpy_s(sub, sizeof(sub), leaf);

            /* 只把"有 Actions 值组的节点"当作任务；否则继续下钻 */
            RegQueryInfoKeyW(hk, NULL, NULL, NULL, NULL, NULL, NULL, &nVal, NULL, NULL, NULL, NULL);
            {
                HKEY hChild = NULL;
                WCHAR wsub[512];
                MultiByteToWideChar(CP_UTF8, 0, leaf, -1, wsub, 512);
                if (RegOpenKeyExW(hk, wsub, 0, KEY_READ, &hChild) == ERROR_SUCCESS) {
                    DWORD nValChild = 0;
                    RegQueryInfoKeyW(hChild, NULL, NULL, NULL, &nSub, NULL, NULL, &nValChild,
                                     NULL, NULL, NULL, NULL);
                    if (nValChild > 0) {
                        /* 有值的节点 = 一个任务 */
                        strcpy_s(g_SchNames[g_SchNameCount], SCH_NAME_CHARS, sub);
                        g_SchNameCount++;
                    }
                    SchWalkTree(hChild, sub, Depth + 1);
                    RegCloseKey(hChild);
                }
            }
        }
    }
    RegCloseKey(hk);
}

/* 从任务的注册表键读 Path（动作程序）与启停状态 */
static BOOL SchLoadDetail(const char *TaskPath, SCH_ITEM *Out)
{
    HKEY hk;
    WCHAR wpath[512];
    char buf[1024];
    DWORD cb, type;

    ZeroMemory(Out, sizeof(*Out));
    strcpy_s(Out->Name, SCH_NAME_CHARS, TaskPath);
    strcpy_s(Out->State, 32, "Ready");
    Out->Enabled = TRUE;

    MultiByteToWideChar(CP_UTF8, 0, TaskPath, -1, wpath, 512);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;

    /* 逐级下钻到任务节点 */
    {
        HKEY cur = hk;
        char work[512];
        char *p, *ctx = NULL;
        BOOL ok = TRUE;

        strcpy_s(work, sizeof(work), TaskPath);
        p = strtok_s(work, "\\", &ctx);
        while (p) {
            HKEY next = NULL;
            WCHAR wn[256];
            MultiByteToWideChar(CP_UTF8, 0, p, -1, wn, 256);
            if (RegOpenKeyExW(cur, wn, 0, KEY_READ, &next) != ERROR_SUCCESS) {
                ok = FALSE;
                break;
            }
            if (cur != hk)
                RegCloseKey(cur);
            cur = next;
            p = strtok_s(NULL, "\\", &ctx);
        }
        if (!ok || cur == hk) {
            if (cur != hk) RegCloseKey(cur);
            RegCloseKey(hk);
            return FALSE;
        }

        cb = sizeof(buf);
        type = 0;
        if (RegQueryValueExW(cur, L"Path", NULL, &type, (BYTE *)buf, &cb) == ERROR_SUCCESS &&
            type == REG_SZ) {
            WideCharToMultiByte(CP_UTF8, 0, (const WCHAR *)buf, -1, Out->Action,
                                SCH_PATH_CHARS, NULL, NULL);
        }
        /* 触发器：粗略读 Tasks 目录下的 XML 太慢，这里用 "TaskCache" 里的标志 */
        cb = sizeof(buf);
        if (RegQueryValueExW(cur, L"Triggers", NULL, &type, (BYTE *)buf, &cb) == ERROR_SUCCESS)
            strcpy_s(Out->Trigger, 128, "(registered)");
        else
            strcpy_s(Out->Trigger, 128, "-");

        RegCloseKey(cur);
    }
    RegCloseKey(hk);
    return TRUE;
}

void DoRefreshSchedule(void)
{
    char status[512];
    ULONG i;
    char msg[512];

    if (!g_hSchList || !g_hSchStatus)
        return;
    ListView_DeleteAllItems(g_hSchList);
    CreateSchColumns(g_hSchList);

    g_SchNameCount = 0;
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
                          0, KEY_READ, &hk) == ERROR_SUCCESS) {
            SchWalkTree(hk, "", 0);
            RegCloseKey(hk);
        }
    }

    for (i = 0; i < g_SchNameCount; i++) {
        SCH_ITEM it;
        LVITEMA lvi;
        if (!SchLoadDetail(g_SchNames[i], &it))
            continue;
        ZeroMemory(&lvi, sizeof(lvi));
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;
        lvi.pszText = it.Name;
        SendMessageA(g_hSchList, LVM_INSERTITEMA, 0, (LPARAM)&lvi);
        SchSetText(g_hSchList, (int)i, 1, it.State);
        SchSetText(g_hSchList, (int)i, 2, it.Trigger);
        SchSetText(g_hSchList, (int)i, 3, it.Action);
        SchSetText(g_hSchList, (int)i, 4, it.Author);
    }
    g_SchCount = g_SchNameCount;
    sprintf_s(status, sizeof(status), "Schedule Task: %lu tasks", g_SchNameCount);
    SetWindowTextA(g_hSchStatus, status);
    (void)msg;
}

/* ---- 操作 ---- */

/* 执行 schtasks 命令（禁用/启用/删除） */
static BOOL SchRunTaskCmd(const char *TaskName, const char *Verb)
{
    char cmd[1024];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exitCode = 1;

    sprintf_s(cmd, sizeof(cmd), "schtasks.exe /%s /TN \"%s\" /F", Verb, TaskName);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
        return FALSE;
    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

static BOOL SchSelectedName(char *Out, int OutChars)
{
    int sel = FeListGetSel(g_hSchList);
    if (sel < 0)
        return FALSE;
    return FeListGetCellText(g_hSchList, sel, 0, Out, OutChars);
}

static BOOL SchSelectedAction(char *Out, int OutChars)
{
    int sel = FeListGetSel(g_hSchList);
    if (sel < 0)
        return FALSE;
    return FeListGetCellText(g_hSchList, sel, 3, Out, OutChars);
}

/* 任务的 XML 文件路径：%SystemRoot%\System32\Tasks\<task path> */
static void SchTaskXmlPath(const char *TaskName, char *Out, int OutChars)
{
    char win[MAX_PATH];
    GetWindowsDirectoryA(win, sizeof(win));
    sprintf_s(Out, OutChars, "%s\\System32\\Tasks\\%s", win, TaskName);
}

static void SchToggle(BOOL Enable)
{
    char name[SCH_NAME_CHARS];
    char msg[700];

    if (!SchSelectedName(name, sizeof(name))) {
        SetWindowTextA(g_hSchStatus, Enable ? "Enable: select a task first"
                                            : "Disable: select a task first");
        return;
    }
    if (SchRunTaskCmd(name, Enable ? "Change /ENABLE" : "Change /DISABLE")) {
        sprintf_s(msg, sizeof(msg), "%s: %s OK", Enable ? "Enable" : "Disable", name);
    } else {
        sprintf_s(msg, sizeof(msg), "%s: %s failed (need admin?)",
                  Enable ? "Enable" : "Disable", name);
    }
    SetWindowTextA(g_hSchStatus, msg);
    DoRefreshSchedule();
}

static void SchDelete(BOOL WithFile)
{
    char name[SCH_NAME_CHARS];
    char xml[MAX_PATH];
    char msg[900];

    if (!SchSelectedName(name, sizeof(name))) {
        SetWindowTextA(g_hSchStatus, "Delete: select a task first");
        return;
    }
    sprintf_s(msg, sizeof(msg), "Delete task \"%s\"%s ?", name,
              WithFile ? " and its XML file" : "");
    if (!FeConfirmDanger(g_hMainWnd, "Delete", msg))
        return;

    if (!SchRunTaskCmd(name, "Delete")) {
        sprintf_s(msg, sizeof(msg), "Delete: %s failed (need admin?)", name);
        SetWindowTextA(g_hSchStatus, msg);
        return;
    }
    if (WithFile) {
        SchTaskXmlPath(name, xml, sizeof(xml));
        DeleteFileA(xml);
    }
    sprintf_s(msg, sizeof(msg), "Delete: %s removed", name);
    SetWindowTextA(g_hSchStatus, msg);
    DoRefreshSchedule();
}

static void SchVerifySig(BOOL All)
{
    char msg[700];

    if (All) {
        ULONG i, ok = 0, bad = 0, miss = 0;
        for (i = 0; i < g_SchNameCount; i++) {
            char action[SCH_PATH_CHARS];
            if (!FeListGetCellText(g_hSchList, (int)i, 3, action, sizeof(action)))
                continue;
            if (!action[0]) {
                miss++;
                continue;
            }
            switch (SchVerifyFileSignature(action, NULL, 0)) {
            case 1:  ok++;  break;
            case 0:  bad++; break;
            default: miss++; break;
            }
        }
        sprintf_s(msg, sizeof(msg),
                  "Verify All: %lu signed, %lu unsigned/untrusted, %lu missing", ok, bad, miss);
    } else {
        char action[SCH_PATH_CHARS];
        char signer[200];
        int r;

        if (!SchSelectedAction(action, sizeof(action)) || !action[0]) {
            SetWindowTextA(g_hSchStatus, "Verify: selected task has no action path");
            return;
        }
        r = SchVerifyFileSignature(action, signer, sizeof(signer));
        if (r == 1)
            sprintf_s(msg, sizeof(msg), "Verify: SIGNED  %s  [%s]", action,
                      signer[0] ? signer : "no signer info");
        else if (r == 0)
            sprintf_s(msg, sizeof(msg), "Verify: UNSIGNED/UNTRUSTED  %s", action);
        else
            sprintf_s(msg, sizeof(msg), "Verify: cannot read \"%s\"", action);
    }
    SetWindowTextA(g_hSchStatus, msg);
}

/* 在线搜索 / 在线分析：打开浏览器（与原版一致的行为） */
static void SchOpenUrl(const char *Url)
{
    ShellExecuteA(NULL, "open", Url, NULL, NULL, SW_SHOWNORMAL);
}

static void SchSearchOnline(void)
{
    char name[SCH_NAME_CHARS];
    char url[1024];

    if (!SchSelectedName(name, sizeof(name))) {
        SetWindowTextA(g_hSchStatus, "Search Online: select a task first");
        return;
    }
    sprintf_s(url, sizeof(url), "https://www.bing.com/search?q=%s", name);
    SchOpenUrl(url);
    SetWindowTextA(g_hSchStatus, "Search Online: opened browser");
}

static void SchAnalyseOnline(void)
{
    char action[SCH_PATH_CHARS];
    char url[1024];

    if (!SchSelectedAction(action, sizeof(action)) || !action[0]) {
        SetWindowTextA(g_hSchStatus, "Analyse Online: no action path on selected task");
        return;
    }
    sprintf_s(url, sizeof(url), "https://www.virustotal.com/gui/file/%s", action);
    SchOpenUrl(url);
    SetWindowTextA(g_hSchStatus, "Analyse Online: opened browser");
}

static void SchFindTarget(void)
{
    char action[SCH_PATH_CHARS];

    if (!SchSelectedAction(action, sizeof(action)) || !action[0]) {
        SetWindowTextA(g_hSchStatus, "Find Target: no action path on selected task");
        return;
    }
    /* 用 Explorer 选中文件 */
    {
        char arg[1024];
        sprintf_s(arg, sizeof(arg), "/select,\"%s\"", action);
        ShellExecuteA(NULL, "open", "explorer.exe", arg, NULL, SW_SHOWNORMAL);
    }
    SetWindowTextA(g_hSchStatus, "Find Target: opened Explorer");
}

static void SchProperties(void)
{
    char action[SCH_PATH_CHARS];
    char msg[700];

    if (!SchSelectedAction(action, sizeof(action)) || !action[0]) {
        SetWindowTextA(g_hSchStatus, "Properties: no action path on selected task");
        return;
    }
    {
        SHELLEXECUTEINFOA sei;
        ZeroMemory(&sei, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_INVOKEIDLIST;
        sei.lpVerb = "properties";
        sei.lpFile = action;
        sei.nShow = SW_SHOW;
        if (!ShellExecuteExA(&sei)) {
            sprintf_s(msg, sizeof(msg), "Properties: cannot show for \"%s\" (err=%lu)",
                      action, GetLastError());
            SetWindowTextA(g_hSchStatus, msg);
        }
    }
}

/* 定位到文件管理器（我方 File 页） */
static void SchLocateInFileTab(void)
{
    char action[SCH_PATH_CHARS];
    char *p;

    if (!SchSelectedAction(action, sizeof(action)) || !action[0]) {
        SetWindowTextA(g_hSchStatus, "Locate in File Tab: no action path on selected task");
        return;
    }
    p = strrchr(action, '\\');
    if (p) {
        *p = 0;
        if (g_hFlDir)
            SetWindowTextA(g_hFlDir, action);
    }
    if (g_hMainTabs)
        SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
    if (g_hMainWnd)
        ShowPage(g_hMainWnd, 8);
    DoRefreshFiles();
}

/* ---- 右键菜单：14 项（原版 11 项 + 我方 3 项补充） ---- */

void DoScheduleContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    UINT cmd;
    int sel;

    FeListSelectUnderCursor(g_hSchList, X, Y);
    sel = FeListGetSel(g_hSchList);

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, SCH_ID_REFRESH, "Refresh");                       /* 刷新 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, SCH_ID_DISABLE, "Disable", sel >= 0);           /* 禁用 */
    FeMenuAddEx(hMenu, SCH_ID_ENABLE, "Enable", sel >= 0);             /* 启用 */
    FeMenuAddEx(hMenu, SCH_ID_DELETE, "Delete", sel >= 0);             /* 删除 */
    FeMenuAddEx(hMenu, SCH_ID_DELETE_FILE, "Delete And Delete File", sel >= 0); /* 连文件一起删除 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, SCH_ID_VERIFY, "Verify File Signature", sel >= 0);  /* 校验数字签名 */
    FeMenuAdd(hMenu, SCH_ID_VERIFY_ALL, "Verify All Files Signatrue");     /* 校验所有 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, SCH_ID_COPY_NAME, "Copy Name", sel >= 0);       /* 复制计划任务名 */
    FeMenuAddEx(hMenu, SCH_ID_COPY_PATH, "Copy Path", sel >= 0);       /* 复制计划任务路径 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, SCH_ID_SEARCH, "Search Online", sel >= 0);      /* 在线搜索 */
    FeMenuAddEx(hMenu, SCH_ID_ANALYSE, "Analyse Online", sel >= 0);    /* 在线分析 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, SCH_ID_FIND_TARGET, "Find Target", sel >= 0);   /* 定位到计划任务文件 */
    FeMenuAddEx(hMenu, SCH_ID_PROPERTIES, "Properties", sel >= 0);     /* 查看属性 */
    FeMenuAddEx(hMenu, SCH_ID_LOCATE_FILE, "Locate in File Tab", sel >= 0); /* 定位到文件管理器 */

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case SCH_ID_REFRESH:     DoRefreshSchedule(); break;
    case SCH_ID_DISABLE:     SchToggle(FALSE); break;
    case SCH_ID_ENABLE:      SchToggle(TRUE); break;
    case SCH_ID_DELETE:      SchDelete(FALSE); break;
    case SCH_ID_DELETE_FILE: SchDelete(TRUE); break;
    case SCH_ID_VERIFY:      SchVerifySig(FALSE); break;
    case SCH_ID_VERIFY_ALL:  SchVerifySig(TRUE); break;
    case SCH_ID_COPY_NAME: {
        char name[SCH_NAME_CHARS];
        if (SchSelectedName(name, sizeof(name))) {
            FeClipCopyText(g_hSchList, name);
            SetWindowTextA(g_hSchStatus, "Copy Name: copied to clipboard");
        }
        break;
    }
    case SCH_ID_COPY_PATH: {
        char action[SCH_PATH_CHARS];
        if (SchSelectedAction(action, sizeof(action))) {
            FeClipCopyText(g_hSchList, action);
            SetWindowTextA(g_hSchStatus, "Copy Path: copied to clipboard");
        }
        break;
    }
    case SCH_ID_SEARCH:      SchSearchOnline(); break;
    case SCH_ID_ANALYSE:     SchAnalyseOnline(); break;
    case SCH_ID_FIND_TARGET: SchFindTarget(); break;
    case SCH_ID_PROPERTIES:  SchProperties(); break;
    case SCH_ID_LOCATE_FILE: SchLocateInFileTab(); break;
    default: break;
    }
}
