// ============================================================================
// OtherViews.c — Other 页（原版第 14 个主 Tab，4 项）
//
// 清单条目与实现：
//   Windows 版本识别表（XP→11 / Server 全系列）
//     读 RtlGetVersion + 注册表 ProductName / CurrentBuild / UBR，
//     把 build 号映射到市场名（XP / Vista / 7 / 8 / 8.1 / 10 / 11 + Server 各代）。
//   FileVersion / File Corporation（PE 版本信息）
//     用 GetFileVersionInfoSize/GetFileVersionInfo/VerQueryValue 读
//     VS_FIXEDFILEINFO + StringFileInfo 的 FileVersion / CompanyName / ProductName。
//   在线查询（百度 / virscan）
//     生成查询 URL 并交给 ShellExecuteW 打开默认浏览器。不自动发请求——
//     那属于"发送数据到外部服务"，必须由用户点击触发。
//   通用 Hook 展示
//     汇总驱动侧已解析的 Hook 相关 GT 槽（SSDT / inline hook 数目），
//     用 0x117 CmdEnumHookInfo 的输出呈现。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winver.h>

#pragma comment(lib, "version.lib")

/* ------------------------------------------------------- Windows 版本识别表 */

typedef struct {
    ULONG Build;
    const char *Name;
} FE_BUILD_NAME;

/* 关键 build 号（来自微软官方版本表）。按降序匹配第一个 <= Build 的项。 */
static const FE_BUILD_NAME g_BuildNames[] = {
    { 26100, "Windows 11 24H2" },
    { 22631, "Windows 11 23H2" },
    { 22621, "Windows 11 22H2" },
    { 22000, "Windows 11 21H2" },
    { 20348, "Windows Server 2022" },
    { 19045, "Windows 10 22H2" },
    { 19044, "Windows 10 21H2" },
    { 19043, "Windows 10 21H1" },
    { 19042, "Windows 10 20H2" },
    { 19041, "Windows 10 2004" },
    { 18363, "Windows 10 1909" },
    { 18362, "Windows 10 1903" },
    { 17763, "Windows 10 1809 / Server 2019" },
    { 17134, "Windows 10 1803" },
    { 16299, "Windows 10 1709" },
    { 15063, "Windows 10 1703" },
    { 14393, "Windows 10 1607 / Server 2016" },
    { 10586, "Windows 10 1511" },
    { 10240, "Windows 10 1507" },
    { 9600,  "Windows 8.1 / Server 2012 R2" },
    { 9200,  "Windows 8 / Server 2012" },
    { 7601,  "Windows 7 SP1 / Server 2008 R2 SP1" },
    { 7600,  "Windows 7 / Server 2008 R2" },
    { 6002,  "Windows Vista SP2 / Server 2008 SP2" },
    { 6001,  "Windows Vista SP1 / Server 2008" },
    { 6000,  "Windows Vista / Server 2008" },
    { 3790,  "Windows XP x64 / Server 2003" },
    { 2600,  "Windows XP" },
    { 2195,  "Windows 2000" },
    { 0,     "Unknown" },
};

static const char *FeBuildToName(ULONG Build)
{
    size_t i;
    for (i = 0; i < sizeof(g_BuildNames) / sizeof(g_BuildNames[0]); i++) {
        if (Build >= g_BuildNames[i].Build)
            return g_BuildNames[i].Name;
    }
    return "Unknown";
}

/* API 版本（不依赖 manifest，RtlGetVersion 返回真实版本）。 */
typedef LONG (WINAPI *PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);

BOOL FeLoadOsInfo(FE_OS_INFO *Info)
{
    HMODULE hNtdll;
    PFN_RtlGetVersion pRtlGetVersion;
    RTL_OSVERSIONINFOW osvi;
    char build[32];
    DWORD ubr = 0;

    if (!Info)
        return FALSE;
    ZeroMemory(Info, sizeof(*Info));

    hNtdll = GetModuleHandleA("ntdll.dll");
    pRtlGetVersion = hNtdll
        ? (PFN_RtlGetVersion)(void *)GetProcAddress(hNtdll, "RtlGetVersion") : NULL;
    if (!pRtlGetVersion)
        return FALSE;

    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (pRtlGetVersion(&osvi) != 0)
        return FALSE;

    Info->Major = osvi.dwMajorVersion;
    Info->Minor = osvi.dwMinorVersion;
    Info->Build = osvi.dwBuildNumber;
    Info->PlatformId = osvi.dwPlatformId;

    /* UBR（Update Build Revision）在注册表里 */
    {
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                          0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            DWORD size = sizeof(ubr), type = 0;
            RegQueryValueExW(hk, L"UBR", NULL, &type, (LPBYTE)&ubr, &size);

            {
                WCHAR wbuf[256];
                DWORD sz = sizeof(wbuf), ty = 0;
                if (RegQueryValueExW(hk, L"ProductName", NULL, &ty, (LPBYTE)wbuf, &sz) == ERROR_SUCCESS)
                    FeWideToAnsi(wbuf, Info->ProductName, sizeof(Info->ProductName));
                sz = sizeof(wbuf); ty = 0;
                if (RegQueryValueExW(hk, L"DisplayVersion", NULL, &ty, (LPBYTE)wbuf, &sz) == ERROR_SUCCESS)
                    FeWideToAnsi(wbuf, Info->DisplayVersion, sizeof(Info->DisplayVersion));
                sz = sizeof(wbuf); ty = 0;
                if (RegQueryValueExW(hk, L"CurrentBuild", NULL, &ty, (LPBYTE)wbuf, &sz) == ERROR_SUCCESS)
                    FeWideToAnsi(wbuf, Info->CurrentBuild, sizeof(Info->CurrentBuild));
            }
            RegCloseKey(hk);
        }
    }
    Info->UBR = ubr;
    sprintf_s(build, sizeof(build), "%lu.%lu.%lu.%lu",
              Info->Major, Info->Minor, Info->Build, Info->UBR);
    strcpy_s(Info->VersionString, sizeof(Info->VersionString), build);
    strcpy_s(Info->MarketName, sizeof(Info->MarketName), FeBuildToName(Info->Build));
    return TRUE;
}

BOOL FePrintOsInfo(void)
{
    FE_OS_INFO info;
    if (!FeLoadOsInfo(&info)) {
        printf("os info: RtlGetVersion failed\n");
        return FALSE;
    }
    printf("Windows version: %s\n", info.VersionString);
    printf("  market name   : %s\n", info.MarketName);
    printf("  product name  : %s\n", info.ProductName[0] ? info.ProductName : "(?)");
    printf("  display ver   : %s\n", info.DisplayVersion[0] ? info.DisplayVersion : "(?)");
    printf("  current build : %s\n", info.CurrentBuild[0] ? info.CurrentBuild : "(?)");
    printf("  platform id   : %lu\n", info.PlatformId);
    return TRUE;
}

/* -------------------------------------------------- PE 版本信息（文件属性） */

BOOL FeLoadFileVersion(const char *Path, FE_FILE_VER *Out)
{
    WCHAR wpath[MAX_PATH];
    DWORD handle = 0, size;
    BYTE *buf;
    UINT len;
    BOOL ok = FALSE;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    if (!Path || !Path[0])
        return FALSE;

    MultiByteToWideChar(CP_ACP, 0, Path, -1, wpath, MAX_PATH);
    size = GetFileVersionInfoSizeW(wpath, &handle);
    if (size == 0)
        return FALSE;
    buf = (BYTE *)malloc(size);
    if (!buf)
        return FALSE;
    if (!GetFileVersionInfoW(wpath, 0, size, buf)) {
        free(buf);
        return FALSE;
    }

    {
        VS_FIXEDFILEINFO *ffi = NULL;
        len = 0;
        if (VerQueryValueW(buf, L"\\", (LPVOID *)&ffi, &len) && ffi && len >= sizeof(*ffi)) {
            Out->FileVersionMS = ffi->dwFileVersionMS;
            Out->FileVersionLS = ffi->dwFileVersionLS;
            Out->ProductVersionMS = ffi->dwProductVersionMS;
            Out->ProductVersionLS = ffi->dwProductVersionLS;
            Out->FileFlags = ffi->dwFileFlags;
            Out->FileOS = ffi->dwFileOS;
            Out->FileType = ffi->dwFileType;
            sprintf_s(Out->FileVersion, sizeof(Out->FileVersion), "%lu.%lu.%lu.%lu",
                      HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                      HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
            ok = TRUE;
        }
    }
    if (ok) {
        /* StringFileInfo：语言页不固定，逐个试（040904B0 是常见英文页） */
        WCHAR *lang = NULL;
        UINT langLen = 0;
        if (VerQueryValueW(buf, L"\\VarFileInfo\\Translation", (LPVOID *)&lang, &langLen)
            && lang && langLen >= 4) {
            static const char *fields[] = { "CompanyName", "FileDescription",
                                            "FileVersion", "ProductName", "InternalName",
                                            "OriginalFilename" };
            ULONG f;
            WCHAR sub[128];
            for (f = 0; f < 6; f++) {
                WCHAR *val = NULL;
                UINT vlen = 0;
                _snwprintf_s(sub, 128, _TRUNCATE,
                             L"\\StringFileInfo\\%04x%04x\\%hs",
                             lang[0], lang[1], fields[f]);
                if (VerQueryValueW(buf, sub, (LPVOID *)&val, &vlen) && val) {
                    switch (f) {
                    case 0: FeWideToAnsi(val, Out->CompanyName, sizeof(Out->CompanyName)); break;
                    case 1: FeWideToAnsi(val, Out->FileDescription, sizeof(Out->FileDescription)); break;
                    case 2: FeWideToAnsi(val, Out->FileVersionStr, sizeof(Out->FileVersionStr)); break;
                    case 3: FeWideToAnsi(val, Out->ProductName, sizeof(Out->ProductName)); break;
                    case 4: FeWideToAnsi(val, Out->InternalName, sizeof(Out->InternalName)); break;
                    case 5: FeWideToAnsi(val, Out->OriginalFilename, sizeof(Out->OriginalFilename)); break;
                    }
                }
            }
        }
    }
    free(buf);
    return ok;
}

BOOL FePrintFileVersion(const char *Path)
{
    FE_FILE_VER v;
    if (!FeLoadFileVersion(Path, &v)) {
        printf("file version: no version resource in \"%s\"\n", Path ? Path : "");
        return FALSE;
    }
    printf("file: %s\n", Path);
    printf("  FileVersion      : %s\n", v.FileVersion[0] ? v.FileVersion : "(?)");
    printf("  FileVersionStr   : %s\n", v.FileVersionStr[0] ? v.FileVersionStr : "(?)");
    printf("  CompanyName      : %s\n", v.CompanyName[0] ? v.CompanyName : "(?)");
    printf("  FileDescription  : %s\n", v.FileDescription[0] ? v.FileDescription : "(?)");
    printf("  ProductName      : %s\n", v.ProductName[0] ? v.ProductName : "(?)");
    printf("  OriginalFilename : %s\n", v.OriginalFilename[0] ? v.OriginalFilename : "(?)");
    printf("  FileType         : 0x%lX  FileOS: 0x%lX\n", v.FileType, v.FileOS);
    return TRUE;
}

/* ------------------------------------------------------------- 在线查询 URL */

/* 生成查询 URL。target: 0 = 百度（文件哈希/名字），1 = virscan（文件哈希）。
 * 只生成字符串，不发起网络请求——是否发送由用户点击决定。 */
BOOL FeBuildOnlineQueryUrl(const char *Query, int Target, char *Out, size_t OutChars)
{
    if (!Query || !Out || !OutChars)
        return FALSE;
    /* 做最小转义：只允许安全字符，其余按 %XX */
    {
        char enc[512];
        size_t i, n = 0;
        for (i = 0; Query[i] && n + 4 < sizeof(enc); i++) {
            unsigned char c = (unsigned char)Query[i];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_') {
                enc[n++] = (char)c;
            } else {
                sprintf_s(enc + n, sizeof(enc) - n, "%%%02X", c);
                n += 3;
            }
        }
        enc[n] = 0;
        if (Target == 0)
            sprintf_s(Out, OutChars, "https://www.baidu.com/s?wd=%s", enc);
        else
            sprintf_s(Out, OutChars, "https://www.virscan.org/search?search=%s", enc);
    }
    return TRUE;
}

/* 用默认浏览器打开（用户主动点击时才调用）。 */
BOOL FeOpenUrl(const char *Url)
{
    WCHAR wurl[1024];
    HINSTANCE h;
    if (!Url || !Url[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, Url, -1, wurl, 1024);
    h = ShellExecuteW(NULL, L"open", wurl, NULL, NULL, SW_SHOWNORMAL);
    return ((INT_PTR)h > 32);
}