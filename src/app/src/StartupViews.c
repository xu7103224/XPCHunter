// ============================================================================
// StartupViews.c — Startup Info 页（原版第 7 个主 Tab）
//
// 原版覆盖 16 类自启动位置。全部是注册表读取，不依赖驱动。
//
// 360/32 位重定向：在 64 位进程里访问 HKLM\SOFTWARE 时，若键不存在会自动
// 重定向到 Wow6432Node。原版把两者**分别列出**（"含 Wow64 版本"），所以这里
// 对每个 32/64 位敏感的位置显式枚举 REGSAM（KEY_WOW64_64KEY / KEY_WOW64_32KEY），
// 不做隐式回退。
//
// 每个条目记录：
//   Location  位置标识（如 "HKLM\\...\\Run"）
//   Name      值名
//   Data      值数据（命令行 / DLL 路径）
//   View      64 / 32（Wow64）
//   Hive/Path 便于"复制路径"和"删除"
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winreg.h>
#include <ctype.h>

typedef struct _FE_STARTUP_LOC {
    const char *Label;      /* 展示用的位置名 */
    HKEY        Root;       /* HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER */
    const char *SubKey;     /* 子键路径 */
    REGSAM      Wow64;      /* KEY_WOW64_64KEY 或 KEY_WOW64_32KEY */
    int         IsValueList;/* 1 = 枚举值（Run 类）；0 = 枚举子键（CLSID 类） */
} FE_STARTUP_LOC;

#define W64 KEY_WOW64_64KEY
#define W32 KEY_WOW64_32KEY

static const FE_STARTUP_LOC g_StartupLocs[] = {
    /* --- HKLM Run 系列（原版：Run / RunOnce / RunOnce\\Setup / RunOnceEx） --- */
    { "HKLM\\...\\Run",                HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",             W64, 1 },
    { "HKLM\\...\\Run (Wow64)",        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",             W32, 1 },
    { "HKLM\\...\\RunOnce",            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",         W64, 1 },
    { "HKLM\\...\\RunOnce (Wow64)",    HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",         W32, 1 },
    { "HKLM\\...\\RunOnce\\Setup",     HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",  W64, 1 },
    { "HKLM\\...\\RunOnce\\Setup (W64)", HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup", W32, 1 },
    { "HKLM\\...\\RunOnceEx",          HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",       W64, 1 },
    /* --- HKLM RunServices 系列 --- */
    { "HKLM\\...\\RunServices",        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",     W64, 1 },
    { "HKLM\\...\\RunServicesOnce",    HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", W64, 1 },
    /* --- HKCU Run 系列（含 Wow64） --- */
    { "HKCU\\...\\Run",                HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",             W64, 1 },
    { "HKCU\\...\\Run (Wow64)",        HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",             W32, 1 },
    { "HKCU\\...\\RunOnce",            HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",         W64, 1 },
    { "HKCU\\...\\RunOnce (Wow64)",    HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",         W32, 1 },
    { "HKCU\\...\\RunServices",        HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",     W64, 1 },
    { "HKCU\\...\\RunServicesOnce",    HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", W64, 1 },
    /* --- ShellExecuteHooks（含 Wow64） --- */
    { "ShellExecuteHooks",             HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", W64, 1 },
    { "ShellExecuteHooks (Wow64)",     HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", W32, 1 },
    /* --- AppCertDlls --- */
    { "AppCertDlls",                   HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", W64, 1 },
    /* --- ShellServiceObjectDelayLoad（含 Wow64） --- */
    { "ShellServiceObjectDelayLoad",   HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", W64, 1 },
    { "ShellServiceObjectDelayLoad(W64)", HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", W32, 1 },
    /* --- IniFileMapping（含 Wow64） --- */
    { "IniFileMapping",                HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping", W64, 1 },
    { "IniFileMapping (Wow64)",        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping", W32, 1 },
    /* --- CLSID：只检测 HKCU 覆盖 HKLM 的劫持项（见 IsValueList == 4） --- */
    { "CLSID hijack (HKCU over HKLM)", HKEY_CURRENT_USER,  "SOFTWARE\\Classes\\CLSID",                                     W64, 4 },
    /* --- Winlogon\\Notify（含 Wow64） --- */
    { "Winlogon\\Notify",              HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", W64, 0 },
    { "Winlogon\\Notify (Wow64)",      HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", W32, 0 },
    /* --- Winlogon（Userinit / Shell） --- */
    { "Winlogon (Userinit/Shell)",     HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",     W64, 2 },
    /* --- Command Processor AutoRun --- */
    { "Command Processor (AutoRun)",   HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Command Processor",                        W64, 2 },
    { "Command Processor (HKCU)",      HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Command Processor",                        W64, 2 },
    /* --- Policies\\System --- */
    { "Policies\\System (HKLM)",       HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", W64, 2 },
    { "Policies\\System (HKCU)",       HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", W64, 2 },
    /* --- DllDirectory / DllDirectory32 --- */
    { "Session Manager\\DllDirectory", HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager",           W64, 3 },

    /* =====================================================================
     * 【2026-10-30 补】以下 11 项是从原版 PCHunter64.exe 的 UTF-16 字符串
     * 表逐条比对出的缺口 —— 原版 Startup Info 页覆盖、我方表里没有。
     * 原版字符串证据：'AppInit_DLLs' 'Wow64 AppInit_DLLs' 'BootExecute'
     * 'KnownDLLs' 'SharedTaskScheduler' 'PrintMonitors' 'PrintProviders'
     * 'StubPath' 'HKCU Winlogon' 'ScreenSave'
     * ===================================================================== */

    /* AppInit_DLLs：全局 DLL 注入点，恶意软件最常利用的持久化位置之一。
       Wow64 版本在 Wow6432Node 下，是独立的注册表树。 */
    { "AppInit_DLLs (HKLM)",           HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",      W64, 5 },
    { "AppInit_DLLs (Wow64)",          HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", W64, 5 },

    /* BootExecute：会话管理器启动时执行的程序，bootkit 常驻点 */
    { "BootExecute",                   HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager",           W64, 8 },

    /* KnownDLLs：系统预映射 DLL 列表，替换其中任一即为 DLL 劫持 */
    { "KnownDLLs",                     HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", W64, 1 },
    { "KnownDLLs (Wow64)",             HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs32", W64, 1 },

    /* SharedTaskScheduler：较少人检查的持久化点 */
    { "SharedTaskScheduler",           HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", W64, 1 },
    { "SharedTaskScheduler (Wow64)",   HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", W32, 1 },

    /* 打印机监视器 / 提供程序 */
    { "PrintMonitors",                 HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",          W64, 0 },
    { "PrintProviders",                HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Print\\Providers",         W64, 0 },

    /* StubPath：Active Setup 完成时执行的命令 */
    { "StubPath (Active Setup)",       HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Active Setup\\Installed Components",        W64, 6 },

    /* HKCU Winlogon：Userinit / Shell 的用户级覆盖 */
    { "HKCU Winlogon",                 HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",     W64, 2 },

    /* ScreenSave：屏保可执行文件被替换是常见持久化手法 */
    { "ScreenSave",                    HKEY_CURRENT_USER,  "Control Panel\\Desktop",                                        W64, 7 },
};

#define FE_STARTUP_LOC_COUNT (sizeof(g_StartupLocs)/sizeof(g_StartupLocs[0]))

static void FeAnsiFromWide(const WCHAR *w, char *a, size_t n)
{
    FeWideToAnsi(w, a, n);
}

/* 把某个值读成 ANSI 文本；非字符串类型标出类型与长度。 */
static void FeReadValueByName(HKEY hKey, const WCHAR *name, char *out, size_t outChars)
{
    DWORD type = 0, size = 0;
    WCHAR *buf;
    LONG st;

    out[0] = 0;
    st = RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
    if (st != ERROR_SUCCESS && st != ERROR_MORE_DATA)
        return;
    if (size == 0 || size > 0x10000) {
        out[0] = 0;
        return;
    }
    buf = (WCHAR *)calloc(size / sizeof(WCHAR) + 2, sizeof(WCHAR));
    if (!buf)
        return;
    st = RegQueryValueExW(hKey, name, NULL, &type, (LPBYTE)buf, &size);
    if (st == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
            FeWideToAnsi(buf, out, outChars);
        } else if (type == REG_DWORD && size >= 4) {
            sprintf_s(out, outChars, "(DWORD) 0x%lX", *(DWORD *)buf);
        } else {
            sprintf_s(out, outChars, "(type %lu, %lu bytes)", type, size);
        }
    }
    free(buf);
}

/* 取某个字符串值（不存在则填空）——用于 Winlogon 的 Userinit/Shell 等。 */
static void FeReadNamedString(HKEY root, const char *sub, REGSAM view,
                              const WCHAR *valueName, char *out, size_t outChars)
{
    HKEY hk = NULL;
    out[0] = 0;
    if (RegOpenKeyExW(root, NULL, 0, KEY_READ | view, &hk) == ERROR_SUCCESS) {
        RegCloseKey(hk);
    }
    /* 上面只是探测；真正打开用宽字符子键 */
    {
        WCHAR wsub[512];
        MultiByteToWideChar(CP_ACP, 0, sub, -1, wsub, 512);
        if (RegOpenKeyExW(root, wsub, 0, KEY_READ | view, &hk) == ERROR_SUCCESS) {
            DWORD type = 0, size = 0;
            if (RegQueryValueExW(hk, valueName, NULL, &type, NULL, &size) == ERROR_SUCCESS && size) {
                WCHAR *buf = (WCHAR *)calloc(size / sizeof(WCHAR) + 2, sizeof(WCHAR));
                if (buf) {
                    if (RegQueryValueExW(hk, valueName, NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
                        FeAnsiFromWide(buf, out, outChars);
                    free(buf);
                }
            }
            RegCloseKey(hk);
        }
    }
}

BOOL FeLoadStartupItems(FE_STARTUP_LIST *List)
{
    ULONG i;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;

    for (i = 0; i < FE_STARTUP_LOC_COUNT; i++) {
        const FE_STARTUP_LOC *loc = &g_StartupLocs[i];
        HKEY hk = NULL;
        WCHAR wsub[512];
        LONG st;
        DWORD idx;
        ULONG cap = 32;

        MultiByteToWideChar(CP_ACP, 0, loc->SubKey, -1, wsub, 512);
        st = RegOpenKeyExW(loc->Root, wsub, 0, KEY_READ | loc->Wow64, &hk);
        if (st != ERROR_SUCCESS)
            continue;

        if (loc->IsValueList == 1) {
            /* 枚举值 */
            for (idx = 0; ; idx++) {
                WCHAR nameW[512];
                DWORD nameLen = 512;
                DWORD type = 0, dataLen = 0;
                char nameA[512], dataA[FE_STARTUP_DATA_CHARS];
                FE_STARTUP_ENTRY *e;

                nameLen = 512;
                st = RegEnumValueW(hk, idx, nameW, &nameLen, NULL, &type, NULL, &dataLen);
                if (st == ERROR_NO_MORE_ITEMS)
                    break;
                if (st != ERROR_SUCCESS)
                    break;
                if (dataLen == 0)
                    continue;

                nameW[nameLen] = 0;
                nameA[0] = 0;
                FeAnsiFromWide(nameW, nameA, sizeof(nameA));
                FeReadValueByName(hk, nameW, dataA, sizeof(dataA));

                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : cap;
                    FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_STARTUP_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Location, sizeof(e->Location), "%s", loc->Label);
                sprintf_s(e->Name, sizeof(e->Name), "%s", nameA[0] ? nameA : "(Default)");
                sprintf_s(e->Data, sizeof(e->Data), "%s", dataA);
                sprintf_s(e->Hive, sizeof(e->Hive), "%s",
                          loc->Root == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU");
                sprintf_s(e->SubKey, sizeof(e->SubKey), "%s", loc->SubKey);
                e->View = (loc->Wow64 == KEY_WOW64_32KEY) ? 32 : 64;
            }
        } else if (loc->IsValueList == 0) {
            /* 枚举子键（CLSID / Winlogon\Notify）
             *
             * 注意：CLSID 整棵树有 6000+ 个子键，全部列出**不是**原版语义，
             * 也不是"自启动项"。原版这里的用途是检测**劫持**：正常的 CLSID
             * 处理程序都在 system32 / syswow64 / WinSxS 下，被劫持的会指向
             * 用户目录、临时目录或 ProgramData。所以只收"路径不在系统目录"
             * 的条目，以及完全没有 DLL 值的。
             *
             * 这样条目数从 6776 降到个位数，且每条都值得看。 */
            for (idx = 0; ; idx++) {
                WCHAR subW[512];
                DWORD subLen = 512;
                char subA[512];
                FE_STARTUP_ENTRY *e;
                char dllPath[FE_STARTUP_DATA_CHARS];

                subLen = 512;
                st = RegEnumKeyExW(hk, idx, subW, &subLen, NULL, NULL, NULL, NULL);
                if (st == ERROR_NO_MORE_ITEMS)
                    break;
                if (st != ERROR_SUCCESS)
                    break;
                subW[subLen] = 0;
                subA[0] = 0;
                FeAnsiFromWide(subW, subA, sizeof(subA));

                /* 子键下通常有 InprocServer32 / DllName */
                dllPath[0] = 0;
                {
                    char fullSub[768];
                    sprintf_s(fullSub, sizeof(fullSub), "%s\\%s\\InprocServer32", loc->SubKey, subA);
                    FeReadNamedString(loc->Root, fullSub, loc->Wow64, NULL, dllPath, sizeof(dllPath));
                    if (!dllPath[0]) {
                        sprintf_s(fullSub, sizeof(fullSub), "%s\\%s", loc->SubKey, subA);
                        FeReadNamedString(loc->Root, fullSub, loc->Wow64, L"DllName", dllPath, sizeof(dllPath));
                    }
                }

                /* 只保留"可疑"子键：DLL 路径不在系统目录，或压根没有 DLL 值。 */
                {
                    int suspect = 0;
                    if (!dllPath[0]) {
                        suspect = 1;
                    } else {
                        char lower[FE_STARTUP_DATA_CHARS];
                        size_t k;
                        int hasPath = 0;
                        for (k = 0; dllPath[k] && k < sizeof(lower) - 1; k++) {
                            lower[k] = (char)tolower((unsigned char)dllPath[k]);
                            if (lower[k] == '\\' || lower[k] == '/' || lower[k] == ':')
                                hasPath = 1;
                        }
                        lower[k] = 0;
                        if (!hasPath) {
                            /* 纯文件名（如 combase.dll）：系统目录解析，不报 */
                            suspect = 0;
                        } else if (!strstr(lower, "\\windows\\") &&
                                   !strstr(lower, "\\systemroot\\") &&
                                   !strstr(lower, "\\winsxs\\")) {
                            suspect = 1;
                        }
                    }
                    if (!suspect)
                        continue;
                }

                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : cap;
                    FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_STARTUP_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Location, sizeof(e->Location), "%s", loc->Label);
                sprintf_s(e->Name, sizeof(e->Name), "%s", subA);
                sprintf_s(e->Data, sizeof(e->Data), "%s", dllPath[0] ? dllPath : "(no dll value)");
                sprintf_s(e->Hive, sizeof(e->Hive), "%s",
                          loc->Root == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU");
                sprintf_s(e->SubKey, sizeof(e->SubKey), "%s", loc->SubKey);
                e->View = (loc->Wow64 == KEY_WOW64_32KEY) ? 32 : 64;
            }
        } else if (loc->IsValueList == 4) {
            /* CLSID 劫持检测：遍历 HKCU\Software\Classes\CLSID 的子键，
               若 HKLM\SOFTWARE\Classes\CLSID 下存在同名 CLSID，就比较两侧
               InprocServer32 的默认值；不同则记为可疑。
               这样条目数从数千降到"真正被覆盖的那几个"。 */
            for (idx = 0; ; idx++) {
                WCHAR subW[512];
                DWORD subLen = 512;
                char subA[512];
                char hkcuDll[FE_STARTUP_DATA_CHARS];
                char hklmDll[FE_STARTUP_DATA_CHARS];
                char hklmSub[768];
                FE_STARTUP_ENTRY *e;

                subLen = 512;
                st = RegEnumKeyExW(hk, idx, subW, &subLen, NULL, NULL, NULL, NULL);
                if (st == ERROR_NO_MORE_ITEMS)
                    break;
                if (st != ERROR_SUCCESS)
                    break;
                subW[subLen] = 0;
                subA[0] = 0;
                FeAnsiFromWide(subW, subA, sizeof(subA));

                /* HKCU 侧 */
                {
                    char sub[768];
                    sprintf_s(sub, sizeof(sub), "%s\\%s\\InprocServer32", loc->SubKey, subA);
                    FeReadNamedString(HKEY_CURRENT_USER, sub, KEY_WOW64_64KEY, NULL,
                                      hkcuDll, sizeof(hkcuDll));
                }
                /* HKLM 侧同名 CLSID */
                sprintf_s(hklmSub, sizeof(hklmSub), "SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", subA);
                FeReadNamedString(HKEY_LOCAL_MACHINE, hklmSub, KEY_WOW64_64KEY, NULL,
                                  hklmDll, sizeof(hklmDll));

                if (!hkcuDll[0])
                    continue;                       /* HKCU 没有实际句柄实现，不算覆盖 */
                if (hklmDll[0] && _stricmp(hkcuDll, hklmDll) == 0)
                    continue;                       /* 两侧完全一致，不是劫持 */

                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : cap;
                    FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_STARTUP_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Location, sizeof(e->Location), "%s", loc->Label);
                sprintf_s(e->Name, sizeof(e->Name), "%s", subA);
                sprintf_s(e->Data, sizeof(e->Data), "HKCU=%s  HKLM=%s",
                          hkcuDll, hklmDll[0] ? hklmDll : "(none)");
                sprintf_s(e->Hive, sizeof(e->Hive), "HKCU");
                sprintf_s(e->SubKey, sizeof(e->SubKey), "%s\\%s\\InprocServer32", loc->SubKey, subA);
                e->View = 64;
            }
        } else if (loc->IsValueList == 8) {
            /* == 8：REG_MULTI_SZ 多字符串值（BootExecute）
             *
             * 【2026-10-30 补】BootExecute 是 REG_MULTI_SZ，一个值里有多个
             * 命令行。FeReadNamedString 只取第一段，会把 "autocheck autochk *"
             * 之后的条目全部丢掉 —— 而恶意条目往往就藏在后面。这里逐段展开。 */
            DWORD type = 0, size = 0;
            if (RegQueryValueExW(hk, L"BootExecute", NULL, &type, NULL, &size) == ERROR_SUCCESS
                && size >= sizeof(WCHAR)) {
                WCHAR *mbuf = (WCHAR *)calloc(size / sizeof(WCHAR) + 2, sizeof(WCHAR));
                if (mbuf) {
                    if (RegQueryValueExW(hk, L"BootExecute", NULL, &type,
                                         (LPBYTE)mbuf, &size) == ERROR_SUCCESS) {
                        WCHAR *cur = mbuf;
                        while (*cur) {
                            char val[FE_STARTUP_DATA_CHARS];
                            FE_STARTUP_ENTRY *e;
                            val[0] = 0;
                            FeAnsiFromWide(cur, val, sizeof(val));
                            if (val[0]) {
                                if (List->Count >= List->Capacity) {
                                    ULONG newCap = List->Capacity ? List->Capacity * 2 : cap;
                                    FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                                        List->Items, newCap * sizeof(FE_STARTUP_ENTRY));
                                    if (!p) break;
                                    List->Items = p;
                                    List->Capacity = newCap;
                                }
                                e = &List->Items[List->Count++];
                                ZeroMemory(e, sizeof(*e));
                                sprintf_s(e->Location, sizeof(e->Location), "%s", loc->Label);
                                sprintf_s(e->Name, sizeof(e->Name), "%s", "BootExecute");
                                sprintf_s(e->Data, sizeof(e->Data), "%s", val);
                                sprintf_s(e->Hive, sizeof(e->Hive), "%s", "HKLM");
                                sprintf_s(e->SubKey, sizeof(e->SubKey), "%s", loc->SubKey);
                                e->View = 64;
                            }
                            cur += wcslen(cur) + 1;
                        }
                    }
                    free(mbuf);
                }
            }
        } else {
            /* == 2 / 3 / 5 / 6 / 7：只取具名值
             *
             * 【2026-10-30 补】原来这里只硬编码了 4 个值名，模式 5/6/7
             * 落到同一个分支于是取错了值。现在按模式选值名表：
             *   2 = Winlogon 类（Userinit / Shell / AutoRun / DllDirectory）
             *   3 = 单个 DllDirectory 类
             *   5 = AppInit_DLLs（Wow64 视图下的 Windows 键）
             *   6 = Active Setup 下的 StubPath
             *   7 = 屏保 ScreenSave */
            static const WCHAR *namesWinlogon[] = {
                L"Userinit", L"Shell", L"AutoRun", L"DllDirectory"
            };
            static const WCHAR *namesAppInit[] = { L"AppInit_DLLs", L"LoadAppInit_DLLs" };
            static const WCHAR *namesStubPath[] = { L"StubPath" };
            static const WCHAR *namesScreenSaver[] = { L"ScreenSaveActive", L"SCRNSAVE.EXE" };
            const WCHAR **fixedNames;
            ULONG fixedCount;

            if (loc->IsValueList == 5) {
                fixedNames = namesAppInit;
                fixedCount = (ULONG)(sizeof(namesAppInit) / sizeof(namesAppInit[0]));
            } else if (loc->IsValueList == 6) {
                fixedNames = namesStubPath;
                fixedCount = 1;
            } else if (loc->IsValueList == 7) {
                fixedNames = namesScreenSaver;
                fixedCount = 2;
            } else {
                fixedNames = namesWinlogon;
                fixedCount = (ULONG)(sizeof(namesWinlogon) / sizeof(namesWinlogon[0]));
            }
            {
            ULONG k;
            for (k = 0; k < fixedCount; k++) {
                char val[FE_STARTUP_DATA_CHARS];
                FE_STARTUP_ENTRY *e;
                char nameA[128];

                FeReadNamedString(loc->Root, loc->SubKey, loc->Wow64, fixedNames[k], val, sizeof(val));
                if (!val[0])
                    continue;
                nameA[0] = 0;
                FeAnsiFromWide(fixedNames[k], nameA, sizeof(nameA));

                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : cap;
                    FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_STARTUP_ENTRY));
                    if (!p) break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Location, sizeof(e->Location), "%s", loc->Label);
                sprintf_s(e->Name, sizeof(e->Name), "%s", nameA);
                sprintf_s(e->Data, sizeof(e->Data), "%s", val);
                sprintf_s(e->Hive, sizeof(e->Hive), "%s",
                          loc->Root == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU");
                sprintf_s(e->SubKey, sizeof(e->SubKey), "%s", loc->SubKey);
                e->View = (loc->Wow64 == KEY_WOW64_32KEY) ? 32 : 64;
            }
            }
        }
        RegCloseKey(hk);
    }
    return List->Count != 0;
}

void FeFreeStartupItems(FE_STARTUP_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintStartupItems(void)
{
    FE_STARTUP_LIST list;
    ULONG i;

    if (!FeLoadStartupItems(&list)) {
        printf("startup items: 0 (none found; GetLastError=%lu)\n", GetLastError());
        return FALSE;
    }
    printf("startup items: %lu\n", list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  [%2lu] %-34s %-28s %s\n",
               list.Items[i].View,
               list.Items[i].Location,
               list.Items[i].Name,
               list.Items[i].Data);
    }
    FeFreeStartupItems(&list);
    return TRUE;
}

/* 操作：删除某个启动项（Delete Startup） */
BOOL FeDeleteStartupItem(const FE_STARTUP_ENTRY *Item)
{
    HKEY hk = NULL;
    HKEY root;
    WCHAR wsub[512], wname[512];
    REGSAM view;
    LONG st;

    if (!Item)
        return FALSE;
    root = (strcmp(Item->Hive, "HKLM") == 0) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    view = (Item->View == 32) ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;

    MultiByteToWideChar(CP_ACP, 0, Item->SubKey, -1, wsub, 512);
    if (RegOpenKeyExW(root, wsub, 0, KEY_SET_VALUE | view, &hk) != ERROR_SUCCESS)
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, Item->Name, -1, wname, 512);
    st = RegDeleteValueW(hk, wname);
    RegCloseKey(hk);
    return st == ERROR_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * Startup Info 的两项破坏性操作（原版右键菜单）
 *
 *   Delete(Startup And File)  删除自启动项 + 删除它指向的文件
 *   Repair Startup            把启动项恢复到"系统默认"：
 *                             · Run 类：值存在但指向不存在的文件 → 删除该项
 *                             · 启动文件夹：项指向不存在的文件 → 删除 .lnk
 *                             · 其余情况视为无需修复，返回"无需修复"
 * ------------------------------------------------------------------------- */

/* 从自启动项的 Data 里取出可执行文件路径。
 * Data 可能是 "C:\x.exe -arg"、"\"C:\x y.exe\" -arg" 或裸路径。 */
static void FeStartupExtractPath(const char *Data, char *Out, size_t OutChars)
{
    size_t i = 0, n = 0;

    if (!Out || !OutChars)
        return;
    Out[0] = 0;
    if (!Data)
        return;
    while (Data[i] == ' ')
        i++;
    if (Data[i] == '"') {
        i++;
        while (Data[i] && Data[i] != '"' && n + 1 < OutChars)
            Out[n++] = Data[i++];
        Out[n] = 0;
        return;
    }
    while (Data[i] && n + 1 < OutChars) {
        /* 裸路径里遇到 " -" 认为参数开始 */
        if (Data[i] == ' ' && Data[i + 1] == '-')
            break;
        Out[n++] = Data[i++];
    }
    while (n && Out[n - 1] == ' ')
        n--;
    Out[n] = 0;
}

/* Delete(Startup And File)：删注册表值 + 删文件。
 * 两者分别返回，便于如实报告"只删掉了一半"。 */
BOOL FeDeleteStartupItemAndFile(const FE_STARTUP_ENTRY *Item,
                                char *DeletedPath, size_t PathChars,
                                BOOL *pRegDeleted, DWORD *pFileError)
{
    char path[FE_STARTUP_DATA_CHARS];
    WCHAR wpath[MAX_PATH];

    if (pRegDeleted) *pRegDeleted = FALSE;
    if (pFileError)  *pFileError = 0;
    if (DeletedPath && PathChars)
        DeletedPath[0] = 0;
    if (!Item)
        return FALSE;

    /* 【安全约束 2026-10-22】非 Run 类位置（Winlogon\Shell、Userinit、
       AppInit_DLLs 等）的 Data 不是"可执行文件路径"，删文件只会误伤系统。
       这些位置只删注册表值 —— 那是用户明确点"Delete"的意思，
       但绝不连带删除文件。 */
    {
        BOOL isRun = (strstr(Item->Location, "Run") != NULL);
        if (!isRun) {
            if (pRegDeleted)
                *pRegDeleted = FeDeleteStartupItem(Item);
            if (pFileError) *pFileError = 0;
            return pRegDeleted ? *pRegDeleted : FALSE;
        }
    }

    FeStartupExtractPath(Item->Data, path, sizeof(path));
    /* 展开环境变量，避免对 %windir%\... 这类项报"文件不存在" */
    if (path[0]) {
        char expanded[FE_STARTUP_DATA_CHARS];
        DWORD en = ExpandEnvironmentStringsA(path, expanded, sizeof(expanded));
        if (en > 0 && en <= sizeof(expanded))
            strcpy_s(path, sizeof(path), expanded);
    }
    if (pRegDeleted)
        *pRegDeleted = FeDeleteStartupItem(Item);

    if (!path[0]) {
        if (pFileError) *pFileError = ERROR_FILE_NOT_FOUND;
        return pRegDeleted ? *pRegDeleted : FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    if (!DeleteFileW(wpath)) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND && pRegDeleted && *pRegDeleted) {
            /* 文件本来就不在：注册表删掉即算完成 */
            if (DeletedPath && PathChars)
                strcpy_s(DeletedPath, PathChars, path);
            return TRUE;
        }
        if (pFileError) *pFileError = err;
        return FALSE;
    }
    if (DeletedPath && PathChars)
        strcpy_s(DeletedPath, PathChars, path);
    return TRUE;
}

/* Repair Startup：只处理"指向的文件已不存在"的项——把它删掉。
 * 返回列表里被修复的条数（pChecked 为总检查数）。 */
ULONG FeRepairStartupItems(ULONG *pChecked, FE_STARTUP_LIST *Repaired)
{
    FE_STARTUP_LIST list;
    ULONG i, fixed = 0;

    if (pChecked) *pChecked = 0;
    if (Repaired) {
        Repaired->Count = 0;
        Repaired->Capacity = 0;
        Repaired->Items = NULL;
    }
    if (!FeLoadStartupItems(&list))
        return 0;
    if (pChecked) *pChecked = list.Count;

    for (i = 0; i < list.Count; i++) {
        char path[FE_STARTUP_DATA_CHARS];
        WCHAR wpath[MAX_PATH];

        /* 【安全约束 2026-10-22】只修 Run/RunOnce 类的值。
           Shell / Userinit / AppInit_DLLs 这些 Winlogon 与系统关键值
           的 Data 不是"文件路径"，拿去比较文件存在性会把正常项当脏项删掉
           （实测误删过 Winlogon\Shell=explorer.exe 与 Userinit）。
           这类位置一律跳过，不做任何修复。 */
        if (strstr(list.Items[i].Location, "Run") == NULL)
            continue;
        FeStartupExtractPath(list.Items[i].Data, path, sizeof(path));
        /* 展开 %windir% / %SystemRoot% 等变量，否则正常项会被判定为"文件不存在"
           （实测误删了 SecurityHealth = %windir%\system32\SecurityHealthSystray.exe）。 */
        if (path[0]) {
            char expanded[FE_STARTUP_DATA_CHARS];
            DWORD en = ExpandEnvironmentStringsA(path, expanded, sizeof(expanded));
            if (en > 0 && en <= sizeof(expanded))
                strcpy_s(path, sizeof(path), expanded);
        }
        if (!path[0])
            continue;
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
        if (GetFileAttributesW(wpath) != INVALID_FILE_ATTRIBUTES)
            continue;                 /* 文件存在，无需修复 */
        if (!FeDeleteStartupItem(&list.Items[i]))
            continue;
        fixed++;
        if (Repaired) {
            if (Repaired->Count == Repaired->Capacity) {
                ULONG cap = Repaired->Capacity ? Repaired->Capacity * 2 : 16;
                FE_STARTUP_ENTRY *p = (FE_STARTUP_ENTRY *)realloc(
                    Repaired->Items, (size_t)cap * sizeof(FE_STARTUP_ENTRY));
                if (p) {
                    Repaired->Items = p;
                    Repaired->Capacity = cap;
                }
            }
            if (Repaired->Count < Repaired->Capacity)
                Repaired->Items[Repaired->Count++] = list.Items[i];
        }
    }
    FeFreeStartupItems(&list);
    return fixed;
}
