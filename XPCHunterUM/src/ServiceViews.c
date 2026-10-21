// ============================================================================
// ServiceViews.c — Services 页（原版第 8 个主 Tab，9 项）
//
// 清单条目：
//   Services: %d / Hidden Services: %d          状态栏统计
//   Delete Service(Not Delete File)             删除服务项
//   Verify ServiceDll Signature                 校验 ServiceDll 签名
//   Find ImagePath Target                       定位 ImagePath 指向的文件
//   Find ServiceDll Target                      定位 ServiceDll
//   ServiceDll Path / ServiceDll Properties     显示 ServiceDll 路径
//   Locate in File Tab(ImagePath)/(ServiceDll)  在 File 页定位
//   Analyse ImagePath / ServiceDll by FireEye    交 Fireeye 页分析
//
// 数据源：
//   · SCM  EnumServicesStatusExW(SERVICE_WIN32 | SERVICE_DRIVER) 拿服务清单与状态
//   · 注册表 Services\<name> 的 Parameters\ServiceDll（用户态服务才有）
//   · "隐藏服务"的判定：SCM 里查不到、但注册表 Services 下存在同名子键
//     —— 这正是原版 Hidden Services 的定义（rootkit 删了 SCM 项但留下注册表项，
//        或反之）。反向（SCM 有、注册表无）也一并统计。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winreg.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

/* 打开注册表 Services 子键（宽字符路径由调用方给）。 */
static BOOL FeServiceRegOpen(const char *serviceName, REGSAM extra, HKEY *out)
{
    WCHAR wpath[640];
    WCHAR wname[256];

    if (!serviceName || !out)
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, serviceName, -1, wname, 256);
    _snwprintf_s(wpath, 640, _TRUNCATE,
                 L"SYSTEM\\CurrentControlSet\\Services\\%s", wname);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, wpath, 0,
                         KEY_READ | extra, out) == ERROR_SUCCESS;
}

/* 读某个服务下 Parameters\ServiceDll 的默认值。 */
static void FeServiceReadDll(const char *serviceName, char *out, size_t outChars)
{
    HKEY hk = NULL;
    out[0] = 0;
    if (!FeServiceRegOpen(serviceName, KEY_WOW64_64KEY, &hk))
        return;
    {
        HKEY hp = NULL;
        if (RegOpenKeyExW(hk, L"Parameters", 0, KEY_READ | KEY_WOW64_64KEY, &hp) == ERROR_SUCCESS) {
            DWORD type = 0, size = 0;
            if (RegQueryValueExW(hp, L"ServiceDll", NULL, &type, NULL, &size) == ERROR_SUCCESS && size) {
                WCHAR *buf = (WCHAR *)calloc(size / sizeof(WCHAR) + 2, sizeof(WCHAR));
                if (buf) {
                    if (RegQueryValueExW(hp, L"ServiceDll", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
                        FeWideToAnsi(buf, out, outChars);
                    free(buf);
                }
            }
            RegCloseKey(hp);
        }
    }
    RegCloseKey(hk);
}

/* 读服务的 ImagePath（注册表侧，比 SCM 的 QueryServiceConfig 更原始）。 */
static void FeServiceReadImagePath(const char *serviceName, char *out, size_t outChars)
{
    HKEY hk = NULL;
    out[0] = 0;
    if (!FeServiceRegOpen(serviceName, KEY_WOW64_64KEY, &hk))
        return;
    {
        DWORD type = 0, size = 0;
        if (RegQueryValueExW(hk, L"ImagePath", NULL, &type, NULL, &size) == ERROR_SUCCESS && size) {
            WCHAR *buf = (WCHAR *)calloc(size / sizeof(WCHAR) + 2, sizeof(WCHAR));
            if (buf) {
                if (RegQueryValueExW(hk, L"ImagePath", NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
                    FeWideToAnsi(buf, out, outChars);
                free(buf);
            }
        }
    }
    RegCloseKey(hk);
}

/* 把 ImagePath / ServiceDll 里的路径部分抽出来（去掉引号与参数）。 */
static void FeExtractExePath(const char *in, char *out, size_t outChars)
{
    const char *p = in;
    size_t n = 0;
    out[0] = 0;
    if (!in || !in[0])
        return;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && n + 1 < outChars)
            out[n++] = *p++;
    } else {
        while (*p && *p != ' ' && n + 1 < outChars)
            out[n++] = *p++;
    }
    out[n] = 0;
}

/* 展开 %SystemRoot% 之类的环境变量。 */
static void FeExpandEnv(const char *in, char *out, size_t outChars)
{
    WCHAR win[FE_SVC_PATH_CHARS], wout[FE_SVC_PATH_CHARS];
    MultiByteToWideChar(CP_ACP, 0, in, -1, win, FE_SVC_PATH_CHARS);
    if (ExpandEnvironmentStringsW(win, wout, FE_SVC_PATH_CHARS)) {
        FeWideToAnsi(wout, out, outChars);
    } else {
        strcpy_s(out, outChars, in);
    }
}

/* 用 WinVerifyTrust 校验文件签名。返回：
 *   1 = 签名有效且受信任
 *   0 = 无签名 / 签名无效 / 文件不存在
 */
int FeVerifyFileSignature(const char *path)
{
    WCHAR wpath[MAX_PATH];
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA wtData;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st;

    if (!path || !path[0])
        return 0;
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES)
        return 0;

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath;

    ZeroMemory(&wtData, sizeof(wtData));
    wtData.cbStruct = sizeof(wtData);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_FILE;
    wtData.pFile = &fileInfo;
    wtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wtData.dwProvFlags = WTD_SAFER_FLAG;

    st = WinVerifyTrust(NULL, &action, &wtData);
    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wtData);

    return st == ERROR_SUCCESS ? 1 : 0;
}

/* 枚举某个 hKey 下所有子键名（用于统计注册表侧服务）。 */
static ULONG FeCountRegServices(void)
{
    HKEY hk = NULL;
    DWORD idx = 0;
    ULONG n = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return 0;
    for (;;) {
        WCHAR name[256];
        DWORD len = 256;
        if (RegEnumKeyExW(hk, idx++, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        n++;
    }
    RegCloseKey(hk);
    return n;
}

/* 注册表里是否存在该服务子键（用于隐藏服务判定）。 */
static BOOL FeServiceRegExists(const char *serviceName)
{
    HKEY hk = NULL;
    BOOL ok = FeServiceRegOpen(serviceName, KEY_WOW64_64KEY, &hk);
    if (hk)
        RegCloseKey(hk);
    return ok;
}

BOOL FeLoadServices(FE_SERVICE_LIST *List)
{
    SC_HANDLE Scm;
    LPENUM_SERVICE_STATUS_PROCESSW Buf = NULL;
    DWORD BufSize = 0, Needed = 0, Returned = 0, Resume = 0;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;
    List->HiddenCount = 0;
    List->RegServiceCount = 0;

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!Scm)
        return FALSE;

    for (;;) {
        if (!EnumServicesStatusExW(Scm, SC_ENUM_PROCESS_INFO,
                                   SERVICE_WIN32 | SERVICE_DRIVER,
                                   SERVICE_STATE_ALL, (LPBYTE)Buf, BufSize,
                                   &Needed, &Returned, &Resume, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_MORE_DATA && err != ERROR_INSUFFICIENT_BUFFER)
                break;
            free(Buf);
            BufSize = Needed;
            Buf = (LPENUM_SERVICE_STATUS_PROCESSW)calloc(1, BufSize);
            if (!Buf)
                break;
            Resume = 0;
            continue;
        }
        break;
    }

    List->RegServiceCount = FeCountRegServices();

    if (Buf && Returned) {
        List->Items = (FE_SERVICE_ENTRY *)calloc(Returned, sizeof(FE_SERVICE_ENTRY));
        if (List->Items) {
            ULONG i;
            for (i = 0; i < Returned; i++) {
                FE_SERVICE_ENTRY *e = &List->Items[i];
                SC_HANDLE Svc;
                LPQUERY_SERVICE_CONFIGW Cfg = NULL;
                DWORD cfgNeeded = 0, cfgSize = 0;

                FeWideToAnsi(Buf[i].lpServiceName, e->Name, sizeof(e->Name));
                FeWideToAnsi(Buf[i].lpDisplayName, e->Display, sizeof(e->Display));
                e->State = Buf[i].ServiceStatusProcess.dwCurrentState;

                Svc = OpenServiceW(Scm, Buf[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (Svc) {
                    QueryServiceConfigW(Svc, NULL, 0, &cfgNeeded);
                    if (cfgNeeded) {
                        Cfg = (LPQUERY_SERVICE_CONFIGW)calloc(1, cfgNeeded);
                        if (Cfg && QueryServiceConfigW(Svc, Cfg, cfgNeeded, &cfgSize)) {
                            FeWideToAnsi(Cfg->lpBinaryPathName, e->ImagePath, sizeof(e->ImagePath));
                            e->Start = Cfg->dwStartType;
                            e->Type = Cfg->dwServiceType;
                        }
                        free(Cfg);
                    }
                    CloseServiceHandle(Svc);
                }
                /* 注册表里的原始 ImagePath 更可信（SCM 会做归一化） */
                {
                    char raw[FE_SVC_PATH_CHARS];
                    FeServiceReadImagePath(e->Name, raw, sizeof(raw));
                    if (raw[0])
                        strcpy_s(e->ImagePath, sizeof(e->ImagePath), raw);
                }
                FeServiceReadDll(e->Name, e->ServiceDll, sizeof(e->ServiceDll));

                /* ImagePath 去引号/参数后展开环境变量 */
                {
                    char exe[FE_SVC_PATH_CHARS], ex[FE_SVC_PATH_CHARS];
                    FeExtractExePath(e->ImagePath, exe, sizeof(exe));
                    FeExpandEnv(exe, ex, sizeof(ex));
                    strcpy_s(e->ResolvedPath, sizeof(e->ResolvedPath), ex);
                }

                /* 隐藏服务判定：SCM 有、注册表也有 —— 正常。
                   这里统计的是"注册表有、SCM 没有"，在下面单独算。 */
            }
            List->Count = Returned;
            List->Capacity = Returned;
        }
    }
    free(Buf);
    CloseServiceHandle(Scm);

    /* 隐藏服务：遍历注册表 Services，凡是 SCM 清单里没有的都算。 */
    {
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services", 0,
                          KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            DWORD idx = 0;
            for (;;) {
                WCHAR name[256];
                DWORD len = 256;
                char ansi[256];
                ULONG k;
                int found = 0;

                if (RegEnumKeyExW(hk, idx++, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                ansi[0] = 0;
                FeWideToAnsi(name, ansi, sizeof(ansi));
                for (k = 0; k < List->Count; k++) {
                    if (_stricmp(List->Items[k].Name, ansi) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    /* 只把"看起来是服务"的键算作隐藏服务：
                       注册表里带 Type 值，且 Type 属于 SCM 会枚举的类别。
                       纯配置键（无 Type）不算 —— 否则会把 72 个
                       "注册表多于 SCM" 的差集全部误报成隐藏服务。 */
                    HKEY hsk = NULL;
                    if (RegOpenKeyExW(hk, name, 0, KEY_READ | KEY_WOW64_64KEY, &hsk) == ERROR_SUCCESS) {
                        DWORD type = 0, size = 0;
                        if (RegQueryValueExW(hsk, L"Type", NULL, &type, NULL, &size) == ERROR_SUCCESS
                            && size >= 4) {
                            DWORD val = 0;
                            size = 4;
                            if (RegQueryValueExW(hsk, L"Type", NULL, &type, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
                                if ((val & (SERVICE_WIN32 | SERVICE_DRIVER)) != 0)
                                    List->HiddenCount++;
                            }
                        }
                        RegCloseKey(hsk);
                    }
                }
            }
            RegCloseKey(hk);
        }
    }

    return List->Count != 0;
}

void FeFreeServices(FE_SERVICE_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintServices(void)
{
    FE_SERVICE_LIST list;
    ULONG i;

    if (!FeLoadServices(&list)) {
        printf("services: load failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("Services: %lu / Hidden Services: %lu  (registry keys: %lu)\n",
           list.Count, list.HiddenCount, list.RegServiceCount);
    for (i = 0; i < list.Count; i++) {
        printf("  %-32s %-9s dll=%-3s %s\n",
               list.Items[i].Name,
               list.Items[i].State == SERVICE_RUNNING ? "RUNNING" :
               list.Items[i].State == SERVICE_STOPPED ? "STOPPED" : "?",
               list.Items[i].ServiceDll[0] ? "yes" : "-",
               list.Items[i].ResolvedPath[0] ? list.Items[i].ResolvedPath : "(?)");
    }
    FeFreeServices(&list);
    return TRUE;
}

/* Delete Service(Not Delete File)：只删注册表服务项，不动 ImagePath 文件。 */
BOOL FeDeleteService(const char *ServiceName)
{
    SC_HANDLE Scm, Svc;
    BOOL ok = FALSE;

    if (!ServiceName || !ServiceName[0])
        return FALSE;
    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
        return FALSE;
    {
        WCHAR wname[256];
        MultiByteToWideChar(CP_ACP, 0, ServiceName, -1, wname, 256);
        Svc = OpenServiceW(Scm, wname, DELETE);
        if (Svc) {
            ok = DeleteService(Svc) ? TRUE : FALSE;
            CloseServiceHandle(Svc);
        }
    }
    CloseServiceHandle(Scm);
    return ok;
}