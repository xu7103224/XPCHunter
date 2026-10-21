// ============================================================================
// DriverOps.c — Kernel 页 Driver 子页的「驱动操作」（原版右键菜单 6 项）
//
// 原版这组操作是：
//   Delete Driver(File)          删除驱动文件
//   Delete Driver(File And Reg)  删除驱动文件 + 服务注册表键
//   Unload Driver(Dangerous)     停止服务（真正卸载驱动）
//   Verify Driver Signature      校验单个驱动文件签名
//   Verify All Driver Signature  批量校验
//   Locate in Registry Tab       跳到注册表页对应键（本页未实现，见清单）
//
// 全部走 SCM + WinVerifyTrust，不依赖驱动；路径解析要处理 ImagePath 的
// 三种常见写法：`\SystemRoot\...`、`\??\C:\...`、`system32\drivers\...`。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FE_DOP_PATH 1024

/* 读取服务的 ImagePath（REG_EXPAND_SZ 或 REG_SZ）。 */
static BOOL FeReadImagePath(const char *ServiceName, char *Out, size_t OutChars)
{
    WCHAR wname[FE_DRV_NAME_CHARS];
    WCHAR subkey[512];
    HKEY hk = NULL;
    DWORD type = 0, size = 0;
    LONG rc;

    if (!ServiceName || !Out || OutChars == 0)
        return FALSE;
    Out[0] = 0;
    MultiByteToWideChar(CP_ACP, 0, ServiceName, -1, wname, FE_DRV_NAME_CHARS);
    swprintf_s(subkey, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s", wname);

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                       KEY_READ | KEY_WOW64_64KEY, &hk);
    if (rc != ERROR_SUCCESS)
        return FALSE;

    /* 先问大小 */
    rc = RegQueryValueExW(hk, L"ImagePath", NULL, &type, NULL, &size);
    if (rc != ERROR_SUCCESS || size == 0 || size > 4096) {
        RegCloseKey(hk);
        return FALSE;
    }
    {
        WCHAR *wbuf = (WCHAR *)calloc(1, size + sizeof(WCHAR));
        if (!wbuf) {
            RegCloseKey(hk);
            return FALSE;
        }
        rc = RegQueryValueExW(hk, L"ImagePath", NULL, &type, (LPBYTE)wbuf, &size);
        RegCloseKey(hk);
        if (rc != ERROR_SUCCESS) {
            free(wbuf);
            return FALSE;
        }
        wbuf[size / sizeof(WCHAR)] = 0;
        {
            /* 去首尾引号 */
            WCHAR *p = wbuf;
            size_t len = wcslen(p);
            while (len && (p[len - 1] == L'"' || p[len - 1] == L' '))
                p[--len] = 0;
            if (p[0] == L'"')
                p++;
            /* `\??\C:\...` → `C:\...` */
            if (wcsncmp(p, L"\\??\\", 4) == 0)
                p += 4;
            /* `\SystemRoot\...` / `system32\...` → 绝对路径 */
            {
                WCHAR resolved[FE_DOP_PATH];
                if (_wcsnicmp(p, L"\\SystemRoot\\", 12) == 0) {
                    swprintf_s(resolved, FE_DOP_PATH, L"%%SystemRoot%%\\%s", p + 12);
                } else if (_wcsnicmp(p, L"\\SystemRoot", 11) == 0) {
                    swprintf_s(resolved, FE_DOP_PATH, L"%%SystemRoot%%%s", p + 11);
                } else if (_wcsnicmp(p, L"system32\\", 9) == 0 ||
                           _wcsnicmp(p, L"\\system32\\", 10) == 0) {
                    const WCHAR *q = (p[0] == L'\\') ? (p + 1) : p;
                    swprintf_s(resolved, FE_DOP_PATH, L"%%SystemRoot%%\\%s", q);
                } else {
                    wcsncpy_s(resolved, FE_DOP_PATH, p, _TRUNCATE);
                }
                {
                    WCHAR expanded[FE_DOP_PATH];
                    if (!ExpandEnvironmentStringsW(resolved, expanded, FE_DOP_PATH))
                        wcsncpy_s(expanded, FE_DOP_PATH, resolved, _TRUNCATE);
                    WideCharToMultiByte(CP_ACP, 0, expanded, -1, Out,
                                        (int)OutChars, NULL, NULL);
                }
            }
        }
        free(wbuf);
    }
    return Out[0] != 0;
}

/* 解析驱动文件的绝对路径；找不到文件时仍返回解析结果（便于报错）。 */
BOOL FeResolveDriverPath(const char *ServiceName, char *Out, size_t OutChars)
{
    return FeReadImagePath(ServiceName, Out, OutChars);
}

/* Unload Driver(Dangerous)：对服务发 STOP 控制。
 * 原版把这一项标成 Dangerous 是因为停错驱动会直接蓝屏。 */
BOOL FeUnloadDriverService(const char *ServiceName, DWORD *pError)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    BOOL ok = FALSE;

    if (pError)
        *pError = 0;
    if (!ServiceName || !ServiceName[0]) {
        if (pError) *pError = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        if (pError) *pError = GetLastError();
        return FALSE;
    }
    {
        WCHAR wname[FE_DRV_NAME_CHARS];
        MultiByteToWideChar(CP_ACP, 0, ServiceName, -1, wname, FE_DRV_NAME_CHARS);
        svc = OpenServiceW(scm, wname, SERVICE_STOP | SERVICE_QUERY_STATUS);
    }
    if (!svc) {
        if (pError) *pError = GetLastError();
        CloseServiceHandle(scm);
        return FALSE;
    }
    ZeroMemory(&st, sizeof(st));
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st))
        ok = TRUE;
    else if (pError)
        *pError = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

/* Delete Driver(File)：删除驱动文件本身。
 * 驱动仍在运行时删除会失败（共享冲突），这里如实把错误码返回。 */
BOOL FeDeleteDriverFile(const char *ServiceName, char *DeletedPath,
                        size_t PathChars, DWORD *pError)
{
    char path[FE_DOP_PATH];

    if (pError)
        *pError = 0;
    if (DeletedPath && PathChars)
        DeletedPath[0] = 0;
    if (!FeReadImagePath(ServiceName, path, sizeof(path))) {
        if (pError) *pError = ERROR_FILE_NOT_FOUND;
        return FALSE;
    }
    {
        WCHAR wpath[FE_DOP_PATH];
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, FE_DOP_PATH);
        if (!DeleteFileW(wpath)) {
            if (pError) *pError = GetLastError();
            return FALSE;
        }
    }
    if (DeletedPath && PathChars)
        strcpy_s(DeletedPath, PathChars, path);
    return TRUE;
}

/* Delete Driver(File And Reg)：删文件 + 删 Services\<name> 整棵注册表树。
 * 驱动服务的键常带 Instances\1（WDM/PNP 驱动），RegDeleteKeyW 遇到子键
 * 会返回 ERROR_ACCESS_DENIED(5)，所以这里必须用 RegDeleteTreeW。
 * 两个结果分别通过 pFileErr / pRegErr 返回，0 表示成功。 */
BOOL FeDeleteDriverFileAndReg(const char *ServiceName, char *DeletedPath,
                              size_t PathChars, DWORD *pFileErr, DWORD *pRegErr)
{
    DWORD fileErr = 0, regErr = 0;
    LONG rc;

    if (pFileErr)
        *pFileErr = 0;
    if (pRegErr)
        *pRegErr = 0;
    if (DeletedPath && PathChars)
        DeletedPath[0] = 0;

    if (!FeDeleteDriverFile(ServiceName, DeletedPath, PathChars, &fileErr) && pFileErr)
        *pFileErr = fileErr;

    {
        WCHAR wname[FE_DRV_NAME_CHARS];
        WCHAR subkey[512];
        MultiByteToWideChar(CP_ACP, 0, ServiceName, -1, wname, FE_DRV_NAME_CHARS);
        swprintf_s(subkey, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s", wname);
        rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey);
        if (rc == ERROR_FILE_NOT_FOUND)
            rc = ERROR_SUCCESS;
        if (rc != ERROR_SUCCESS)
            regErr = (DWORD)rc;
    }
    if (pRegErr)
        *pRegErr = regErr;
    return (pFileErr && *pFileErr) ? FALSE : (regErr == 0);
}

/* Verify All Driver Signature：遍历 SCM 里所有内核驱动服务，逐个校验文件。
 * 文件不存在记为 missing，不参与 valid/invalid 计数。 */
void FeVerifyAllDrivers(ULONG *pValid, ULONG *pInvalid, ULONG *pMissing, ULONG *pTotal)
{
    FE_DRIVER_LIST list;

    if (pValid) *pValid = 0;
    if (pInvalid) *pInvalid = 0;
    if (pMissing) *pMissing = 0;
    if (pTotal) *pTotal = 0;

    if (!FeLoadDrivers(&list))
        return;
    if (pTotal)
        *pTotal = list.Count;
    {
        ULONG i;
        for (i = 0; i < list.Count; i++) {
            char path[FE_DOP_PATH];
            WCHAR wpath[FE_DOP_PATH];
            if (!FeReadImagePath(list.Items[i].Name, path, sizeof(path))) {
                if (pMissing) (*pMissing)++;
                continue;
            }
            MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, FE_DOP_PATH);
            if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES) {
                if (pMissing) (*pMissing)++;
                continue;
            }
            if (FeVerifyFileSignature(path)) {
                if (pValid) (*pValid)++;
            } else {
                if (pInvalid) (*pInvalid)++;
            }
        }
    }
    FeFreeDrivers(&list);
}
/* --drvop-cli <op> [name]
 *   verifyall                 批量校验所有驱动服务
 *   resolve <name>            解析 ImagePath
 *   verify <name>             校验单个驱动文件签名
 *   unload <name>             停止服务（危险）
 *   delfile <name>            删除驱动文件
 *   delfilereg <name>         删除驱动文件 + 服务注册表键
 * 返回 0 表示操作成功。 */
BOOL FeDriverOpsCli(const char *CmdLine)
{
    const char *p = CmdLine ? strstr(CmdLine, "--drvop-cli") : NULL;
    char op[64], name[FE_DRV_NAME_CHARS], path[FE_DOP_PATH];
    int n;

    if (!p)
        return FALSE;
    p += strlen("--drvop-cli");
    while (*p == ' ')
        p++;
    op[0] = 0;
    name[0] = 0;
    n = sscanf_s(p, "%63s %127s", op, (unsigned)sizeof(op),
                 name, (unsigned)sizeof(name));

    if (n < 1) {
        printf("usage: --drvop-cli verifyall | resolve|verify|unload|delfile|delfilereg <ServiceName>\n");
        return TRUE;
    }

    if (_stricmp(op, "verifyall") == 0) {
        ULONG valid = 0, invalid = 0, missing = 0, total = 0;
        FeVerifyAllDrivers(&valid, &invalid, &missing, &total);
        printf("Verify All Driver Signature: total=%lu valid=%lu invalidOrUnsigned=%lu missingFile=%lu\n",
               (unsigned long)total, (unsigned long)valid,
               (unsigned long)invalid, (unsigned long)missing);
        return TRUE;
    }

    if (n < 2) {
        printf("%s: missing service name\n", op);
        return TRUE;
    }

    if (_stricmp(op, "resolve") == 0) {
        if (FeResolveDriverPath(name, path, sizeof(path)))
            printf("%s -> %s\n", name, path);
        else
            printf("%s -> (no ImagePath)\n", name);
        return TRUE;
    }
    if (_stricmp(op, "verify") == 0) {
        WCHAR wpath[FE_DOP_PATH];
        int trusted;
        if (!FeResolveDriverPath(name, path, sizeof(path))) {
            printf("%s: cannot resolve ImagePath\n", name);
            return TRUE;
        }
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, FE_DOP_PATH);
        if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES) {
            printf("%s: file not found (%s)\n", name, path);
            return TRUE;
        }
        trusted = FeVerifyFileSignature(path);
        printf("%s: %s   (%s)\n", name,
               trusted ? "signature valid and trusted" : "no signature or not trusted",
               path);
        return TRUE;
    }
    if (_stricmp(op, "unload") == 0) {
        DWORD err = 0;
        BOOL ok = FeUnloadDriverService(name, &err);
        printf("Unload %s: %s (GetLastError=%lu)\n", name, ok ? "stop requested" : "failed",
               (unsigned long)err);
        return TRUE;
    }
    if (_stricmp(op, "delfile") == 0) {
        DWORD err = 0;
        FeDeleteDriverFile(name, path, sizeof(path), &err);
        printf("Delete %s: %s (GetLastError=%lu)\n", name, err ? "failed" : path,
               (unsigned long)err);
        return TRUE;
    }
    if (_stricmp(op, "delfilereg") == 0) {
        DWORD fileErr = 0, regErr = 0;
        FeDeleteDriverFileAndReg(name, path, sizeof(path), &fileErr, &regErr);
        printf("Delete(File+Reg) %s: file=%s(%lu) regkey=%s(%lu)\n", name,
               fileErr ? "failed" : path, (unsigned long)fileErr,
               regErr ? "failed" : "deleted", (unsigned long)regErr);
        return TRUE;
    }
    printf("unknown op: %s\n", op);
    return TRUE;
}
