// ============================================================================
// FeNetRegistryViews.c — Network 页的两个纯注册表视图（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.4 的未完成清单：
//   CIePluginDialog   IE 插件        [已补全]
//   CIfeoDialog       IFEO 映像劫持   [已补全]
//
// 两者都是纯注册表枚举，不需要驱动：
//   IE 插件：HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
//            HKCU 同名键（每用户 BHO）
//            HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions
//            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Extensions
//   IFEO  ：HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
//            每个子键（可执行文件名）下的 Debugger 值 = 劫持者
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 把 UTF-16 转窄字符 */
static void NrvW2A(const WCHAR *In, char *Out, int OutChars)
{
    if (!Out || OutChars <= 0)
        return;
    Out[0] = 0;
    if (!In)
        return;
    WideCharToMultiByte(CP_ACP, 0, In, -1, Out, OutChars, NULL, NULL);
}

/* 读子键的默认值（ProgID / CLSID）或指定值 */
static void NrvReadValue(HKEY hk, const WCHAR *Name, char *Out, int OutChars)
{
    WCHAR buf[1024];
    DWORD cb = sizeof(buf) - 2, type = 0;

    if (Out && OutChars > 0)
        Out[0] = 0;
    if (!hk || !Out)
        return;
    ZeroMemory(buf, sizeof(buf));
    if (RegQueryValueExW(hk, Name, NULL, &type, (BYTE *)buf, &cb) == ERROR_SUCCESS)
        NrvW2A(buf, Out, OutChars);
}

/* 从 CLSID 反查 InprocServer32 路径 */
static void NrvClsidToDll(const char *Clsid, char *Out, int OutChars)
{
    char key[512];
    WCHAR wkey[512];
    HKEY hk;

    if (Out && OutChars > 0)
        Out[0] = 0;
    if (!Clsid || !Clsid[0])
        return;
    sprintf_s(key, sizeof(key), "CLSID\\%s\\InprocServer32", Clsid);
    MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        NrvReadValue(hk, NULL, Out, OutChars);
        RegCloseKey(hk);
    }
}

/* 统一的追加回调（由调用方提供，避免依赖 Other 页） */
typedef void (*NRV_ADD_FN)(const char *Item, const char *Detail);

/* ---- IE 插件（BHO + 浏览器扩展） ---- */

ULONG FeLoadIePlugins(NRV_ADD_FN Add)
{
    static const struct {
        HKEY Root;
        const WCHAR *Key;
        const char *Label;
    } sources[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "BHO (HKLM)" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "BHO (HKCU)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer\\Extensions", "IE Extension (HKLM)" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Internet Explorer\\Extensions", "IE Extension (HKCU)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Extensions", "Browser Ext (HKLM)" },
    };
    ULONG count = 0;
    size_t si;
    char itemBuf[400];

    for (si = 0; si < sizeof(sources) / sizeof(sources[0]); si++) {
        HKEY hk;
        DWORD idx = 0;

        if (RegOpenKeyExW(sources[si].Root, sources[si].Key, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            continue;
        for (;;) {
            WCHAR wname[256];
            DWORD cch = 256;
            char nameA[256];
            if (RegEnumKeyExW(hk, idx++, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            NrvW2A(wname, nameA, sizeof(nameA));
            if (!nameA[0])
                continue;
            {
                char dll[700] = { 0 };
                char detail[1200];
                HKEY hSub;
                /* BHO 的子键名是 CLSID */
                if (strstr(sources[si].Label, "BHO") && nameA[0] == '{')
                    NrvClsidToDll(nameA, dll, sizeof(dll));
                /* IE Extension 子键里有 CLSID 值 */
                if (RegOpenKeyExW(hk, wname, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    if (!dll[0]) {
                        char clsid[256] = { 0 };
                        NrvReadValue(hSub, L"CLSID", clsid, sizeof(clsid));
                        if (clsid[0] && clsid[0] == '{')
                            NrvClsidToDll(clsid, dll, sizeof(dll));
                    }
                    RegCloseKey(hSub);
                }
                sprintf_s(itemBuf, sizeof(itemBuf), "%s: %s", sources[si].Label, nameA);
                sprintf_s(detail, sizeof(detail), "dll=%s", dll[0] ? dll : "(unresolved)");
                if (Add)
                    Add(itemBuf, detail);
                count++;
            }
        }
        RegCloseKey(hk);
    }
    return count;
}

/* ---- IFEO（映像文件执行选项 / 映像劫持） ---- */

ULONG FeLoadIfeoEntries(NRV_ADD_FN Add)
{
    HKEY hk;
    DWORD idx = 0;
    ULONG count = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;

    for (;;) {
        WCHAR wname[256];
        DWORD cch = 256;
        char exeA[256];

        if (RegEnumKeyExW(hk, idx++, wname, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        NrvW2A(wname, exeA, sizeof(exeA));
        if (!exeA[0])
            continue;
        {
            HKEY hSub;
            if (RegOpenKeyExW(hk, wname, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                char dbg[700] = { 0 };
                char other[700] = { 0 };
                char item[400], detail[1500];

                NrvReadValue(hSub, L"Debugger", dbg, sizeof(dbg));
                NrvReadValue(hSub, L"GlobalFlag", other, sizeof(other));
                RegCloseKey(hSub);

                /* 只报有异常的项：有 Debugger（劫持）或 GlobalFlag 非 0（可疑） */
                if (!dbg[0] && (!other[0] || strcmp(other, "0") == 0))
                    continue;
                sprintf_s(item, sizeof(item), "IFEO: %s", exeA);
                sprintf_s(detail, sizeof(detail), "%s%s%s",
                          dbg[0] ? "Debugger=" : "",
                          dbg[0] ? dbg : "",
                          other[0] ? "  (GlobalFlag set)" : "");
                if (Add)
                    Add(item, detail);
                count++;
            }
        }
    }
    RegCloseKey(hk);
    return count;
}