// ============================================================================
// FeFileTools.c — File 页的纯用户态工具集（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.7 的未完成清单：
//   Search File            搜索文件（CSearchFileDialog）      [已补全]
//   File MD5               文件哈希（CFileMd5Dialog）         [已补全]
//   File Association       文件关联（CFileAssociationDialog）  [已补全]
//   Move Pending           挂起删除/重命名（CMovePendingDialog）[已补全]
//   Rename File            重命名文件（CRenameFileNameDialog）  [已补全]
//   File Locker            文件解锁（CFileLockerDialog）        [未补全-需驱动]
//
// 全部为纯用户态 Win32 实现，不依赖驱动：
//   - 搜索：FindFirstFileExW + 递归（可限定深度/大小/名称通配）
//   - MD5：CryptoAPI（CryptAcquireContext + CryptCreateHash）
//   - 关联：读取 HKCU/HKCR 的 FileExts / 扩展名 ProgID
//   - Pending：MoveFileExW 的 MOVEFILE_DELAY_UNTIL_REBOOT，或查询
//              HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
//   - 重命名：MoveFileExW
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

/* ---- 1. 文件搜索 ---- */

#define FSR_MAX 8192
#define FSR_NAME_CHARS 260

typedef struct _FSR_ITEM {
    char Path[MAX_PATH * 2];
    ULONG64 Size;
    DWORD Attr;
} FSR_ITEM;

static FSR_ITEM *g_FsrItems = NULL;
static ULONG g_FsrCount = 0;

/* 通配符匹配（支持 * 和 ?），大小写无关 */
static BOOL FsrWildMatch(const char *Pattern, const char *Name)
{
    const char *p = Pattern, *n = Name;
    const char *star = NULL, *nstr = NULL;

    if (!Pattern || !Name)
        return FALSE;
    while (*n && *n != 0) {
        if (*p == '?' || (*p && tolower((unsigned char)*p) == tolower((unsigned char)*n))) {
            p++;
            n++;
        } else if (*p == '*') {
            star = p++;
            nstr = n;
        } else if (star) {
            p = star + 1;
            n = ++nstr;
        } else {
            return FALSE;
        }
    }
    while (*p == '*')
        p++;
    return *p == 0;
}

static void FsrAdd(const char *Path, ULONG64 Size, DWORD Attr)
{
    if (g_FsrCount >= FSR_MAX)
        return;
    if (!g_FsrItems) {
        g_FsrItems = (FSR_ITEM *)calloc(FSR_MAX, sizeof(FSR_ITEM));
        if (!g_FsrItems)
            return;
    }
    strncpy_s(g_FsrItems[g_FsrCount].Path, sizeof(g_FsrItems[g_FsrCount].Path),
              Path, _TRUNCATE);
    g_FsrItems[g_FsrCount].Size = Size;
    g_FsrItems[g_FsrCount].Attr = Attr;
    g_FsrCount++;
}

/* 递归搜索。Pattern 为文件通配（如 *.sys），MaxDepth 为最大目录深度，
   MinSize 为最小字节数（0 表示不限）。 */
static void FsrWalk(const char *Dir, const char *Pattern, int Depth, int MaxDepth,
                    ULONG64 MinSize, volatile LONG *Cancel)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char spec[MAX_PATH * 2];
    char child[MAX_PATH * 2];

    if (Cancel && InterlockedCompareExchange(Cancel, 0, 0) != 0)
        return;

    sprintf_s(spec, sizeof(spec), "%s\\*", Dir);
    /* 用基础 FindFirstFileA：FindFirstFileExA + FindExInfoBasic 在部分
       Windows SDK 组合下会因 WIN32_FIND_DATAA 与 EX 版结构体尺寸不一致而崩。 */
    h = FindFirstFileA(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (Cancel && InterlockedCompareExchange(Cancel, 0, 0) != 0)
            break;
        sprintf_s(child, sizeof(child), "%s\\%s", Dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (Depth < MaxDepth)
                FsrWalk(child, Pattern, Depth + 1, MaxDepth, MinSize, Cancel);
        } else {
            ULONG64 sz = ((ULONG64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz < MinSize)
                continue;
            if (FsrWildMatch(Pattern, fd.cFileName))
                FsrAdd(child, sz, fd.dwFileAttributes);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* 搜索入口：返回命中数，结果在 g_FsrItems[0..g_FsrCount) */
ULONG FeSearchFiles(const char *RootDir, const char *Pattern, int MaxDepth,
                    ULONG64 MinSize, volatile LONG *Cancel)
{
    if (g_FsrItems) {
        free(g_FsrItems);
        g_FsrItems = NULL;
    }
    g_FsrCount = 0;
    if (!RootDir || !RootDir[0] || !Pattern || !Pattern[0])
        return 0;
    FsrWalk(RootDir, Pattern, 0, MaxDepth, MinSize, Cancel);
    return g_FsrCount;
}

const char *FeSearchFileAt(ULONG Index, ULONG64 *OutSize, DWORD *OutAttr)
{
    if (!g_FsrItems || Index >= g_FsrCount)
        return NULL;
    if (OutSize) *OutSize = g_FsrItems[Index].Size;
    if (OutAttr) *OutAttr = g_FsrItems[Index].Attr;
    return g_FsrItems[Index].Path;
}

/* ---- 2. 文件哈希（MD5 / SHA-1 / SHA-256） ---- */

/* AlgId: CALG_MD5 / CALG_SHA1 / CALG_SHA_256 */
BOOL FeHashFile(const char *Path, ALG_ID AlgId, char *OutHex, int OutChars)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile;
    BYTE buf[65536];
    DWORD read = 0, hashLen = 0, i;
    BYTE digest[64];
    BOOL ok = FALSE;

    if (!Path || !OutHex || OutChars < 3)
        return FALSE;
    OutHex[0] = 0;

    hFile = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    /* PROV_RSA_FULL 支持 MD5/SHA1；PROV_RSA_AES 支持 SHA256 及以上。
       先用 AES（覆盖全部三种），失败再退回 FULL。 */
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            goto done;
    }
    if (!CryptCreateHash(hProv, AlgId, 0, 0, &hHash))
        goto done;
    while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0) {
        if (!CryptHashData(hHash, buf, read, 0))
            goto done;
    }
    hashLen = sizeof(digest);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &hashLen, 0))
        goto done;
    for (i = 0; i < hashLen && (int)(i * 2 + 3) <= OutChars; i++)
        sprintf_s(OutHex + i * 2, OutChars - i * 2, "%02X", digest[i]);
    ok = TRUE;

done:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return ok;
}

/* ---- 3. 文件关联 ---- */

/* 查扩展名对应的 ProgID 与打开命令。Ext 形如 ".txt"（可带点也可不带） */
BOOL FeGetFileAssociation(const char *Ext, char *ProgId, int ProgIdChars,
                          char *Command, int CommandChars)
{
    char key[512];
    WCHAR wkey[512];
    HKEY hk;
    DWORD cb;
    char buf[1024];

    if (ProgId) ProgId[0] = 0;
    if (Command) Command[0] = 0;
    if (!Ext || !Ext[0])
        return FALSE;

    /* 去掉前导点，再补上 */
    {
        const char *e = (Ext[0] == '.') ? Ext + 1 : Ext;
        /* 1) HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ext\UserChoice */
        sprintf_s(key, sizeof(key),
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.%s\\UserChoice", e);
        MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, wkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            cb = sizeof(buf) - 2;
            if (RegQueryValueExW(hk, L"ProgId", NULL, NULL, (BYTE *)buf, &cb) == ERROR_SUCCESS) {
                WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)buf, -1, ProgId, ProgIdChars, NULL, NULL);
                RegCloseKey(hk);
                goto have_progid;
            }
            RegCloseKey(hk);
        }
        /* 2) HKCR\.ext 的默认值 */
        sprintf_s(key, sizeof(key), ".%s", e);
        MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            cb = sizeof(buf) - 2;
            if (RegQueryValueExW(hk, NULL, NULL, NULL, (BYTE *)buf, &cb) == ERROR_SUCCESS) {
                WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)buf, -1, ProgId, ProgIdChars, NULL, NULL);
                RegCloseKey(hk);
                goto have_progid;
            }
            RegCloseKey(hk);
        }
        return FALSE;
    }

have_progid:
    if (Command && ProgId[0]) {
        sprintf_s(key, sizeof(key), "%s\\shell\\open\\command", ProgId);
        MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            cb = sizeof(buf) - 2;
            if (RegQueryValueExW(hk, NULL, NULL, NULL, (BYTE *)buf, &cb) == ERROR_SUCCESS)
                WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)buf, -1, Command, CommandChars, NULL, NULL);
            RegCloseKey(hk);
        }
    }
    return ProgId[0] != 0;
}

/* ---- 4. Pending 操作（挂起删除/重命名） ---- */

/* 查询系统当前挂起的文件操作（PendingFileRenameOperations）。
   返回条目数；Out 缓冲由调用方提供（每行一个操作，形如
   "\??\C:\path\file  !\??\C:\path\newname" 或 "\??\C:\path\file  "）。 */
BOOL FeQueryPendingFileOps(char *Out, int OutChars)
{
    WCHAR wkey[256];
    HKEY hk;
    DWORD cb = 0, type = 0;
    BYTE *data;
    BOOL ok = FALSE;

    if (Out && OutChars > 0)
        Out[0] = 0;
    MultiByteToWideChar(CP_ACP, 0,
                        "SYSTEM\\CurrentControlSet\\Control\\Session Manager", -1, wkey, 256);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hk, L"PendingFileRenameOperations", NULL, &type, NULL, &cb) != ERROR_SUCCESS ||
        cb == 0) {
        RegCloseKey(hk);
        return FALSE;
    }
    data = (BYTE *)malloc(cb + 2);
    if (!data) {
        RegCloseKey(hk);
        return FALSE;
    }
    if (RegQueryValueExW(hk, L"PendingFileRenameOperations", NULL, &type, data, &cb) == ERROR_SUCCESS) {
        /* REG_MULTI_SZ：源\0目标\0...（目标为空表示删除） */
        const WCHAR *p = (const WCHAR *)data;
        const WCHAR *end = (const WCHAR *)(data + cb);
        int pos = 0;
        BOOL isSrc = TRUE;
        while (p < end && *p) {
            char line[900];
            WideCharToMultiByte(CP_ACP, 0, p, -1, line, sizeof(line), NULL, NULL);
            if (isSrc) {
                if (pos + (int)strlen(line) + 4 < OutChars) {
                    if (pos) { strcat_s(Out, OutChars, "\r\n"); pos += 2; }
                    strcat_s(Out, OutChars, "DEL/REN  ");
                    strcat_s(Out, OutChars, line);
                    pos += (int)strlen(line) + 9;
                }
            } else if (line[0]) {
                if (pos + (int)strlen(line) + 4 < OutChars) {
                    strcat_s(Out, OutChars, "  ->  ");
                    strcat_s(Out, OutChars, line);
                    pos += (int)strlen(line) + 6;
                }
            }
            isSrc = !isSrc;
            p += wcslen(p) + 1;
        }
        ok = TRUE;
    }
    free(data);
    RegCloseKey(hk);
    return ok;
}

/* 安排一个文件在重启时删除（原版 Move Pending 的等价能力） */
BOOL FeScheduleDeleteOnReboot(const char *Path)
{
    WCHAR wp[MAX_PATH * 2];
    if (!Path || !Path[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, Path, -1, wp, MAX_PATH * 2);
    return MoveFileExW(wp, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
}

/* 安排一个文件在重启时改名 */
BOOL FeScheduleRenameOnReboot(const char *From, const char *To)
{
    WCHAR wf[MAX_PATH * 2], wt[MAX_PATH * 2];
    if (!From || !From[0] || !To || !To[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, From, -1, wf, MAX_PATH * 2);
    MultiByteToWideChar(CP_ACP, 0, To, -1, wt, MAX_PATH * 2);
    return MoveFileExW(wf, wt, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING) != FALSE;
}

/* ---- 5. 重命名文件 ---- */

BOOL FeRenameFileNow(const char *From, const char *To)
{
    WCHAR wf[MAX_PATH * 2], wt[MAX_PATH * 2];
    if (!From || !From[0] || !To || !To[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, From, -1, wf, MAX_PATH * 2);
    MultiByteToWideChar(CP_ACP, 0, To, -1, wt, MAX_PATH * 2);
    return MoveFileExW(wf, wt, MOVEFILE_REPLACE_EXISTING) != FALSE;
}