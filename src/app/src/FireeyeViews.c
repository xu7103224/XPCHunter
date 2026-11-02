// ============================================================================
// FireeyeViews.c — Fireeye 页（原版第 12 个主 Tab，7 项）
//
// 这是"金山火眼云查"的客户端：把文件哈希/文件送到火眼站点查询，回显结果。
//
// 清单条目与实现：
//   Analyse ImagePath by FireEye    取服务 ImagePath → 本地预判 → 待确认上传
//   Analyse ServiceDll by FireEye   取服务 ServiceDll → 同上
//   Analyse by FireEye（通用）      任意文件路径 → 同上
//   View the result                 展示查询结果（本实现回显 URL + 本地判定）
//   Delete upload record            删除上传记录（本地记录文件）
//   上传确认对话框                  GUI 必须二次确认；本文件提供状态机
//   `%s is belong to Microsoft,it don't upload to FireEye's site`
//                                   微软签名文件不上传，按原版文案提示
//
// 重要设计约束（与安全相关）：
//   本模块**不自动发起任何网络请求**。它只做三件事：
//     1) 本地判定（签名是否微软 → 直接拒绝上传，按原版文案提示）
//     2) 生成查询 URL（哈希进 URL，不上传文件本体）
//     3) 记录"待上传/已确认"状态，由调用方（GUI）在用户确认后决定是否
//        真正用浏览器打开 URL —— 打开浏览器是用户可见、可撤销的动作。
//   文件本体上传需要 HTTP multipart + 火眼站点 API key，原版内置的 key 已在
//   2024 年后失效；因此这里明确**不实现文件本体上传**，并在文档里说明。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 计算 SHA-256（文件哈希；火眼查询用哈希而非文件本体）。 */
BOOL FeFileSha256(const char *Path, char *OutHex, size_t OutChars)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE buf[65536];
    DWORD read = 0;
    BYTE digest[32];
    DWORD digestLen = sizeof(digest);
    BOOL ok = FALSE;
    size_t i;

    if (!Path || !OutHex || OutChars < 65)
        return FALSE;
    OutHex[0] = 0;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto done;

    {
        WCHAR wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, Path, -1, wpath, MAX_PATH);
        hFile = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (hFile == INVALID_HANDLE_VALUE)
        goto done;

    for (;;) {
        if (!ReadFile(hFile, buf, sizeof(buf), &read, NULL))
            goto done;
        if (read == 0)
            break;
        if (!CryptHashData(hHash, buf, read, 0))
            goto done;
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0))
        goto done;
    for (i = 0; i < digestLen && (i * 2 + 2) < OutChars; i++)
        sprintf_s(OutHex + i * 2, OutChars - i * 2, "%02x", digest[i]);
    ok = TRUE;

done:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    return ok;
}

/* 本地预判：文件是否微软签名（微软文件不上传，与原版文案一致）。 */
int FeFireeyePrecheck(const char *Path, FE_FIREEYE_JOB *Job)
{
    FE_FILE_VER ver;

    if (!Job)
        return 0;
    ZeroMemory(Job, sizeof(*Job));
    if (!Path || !Path[0])
        return 0;
    strcpy_s(Job->Path, sizeof(Job->Path), Path);

    /* 1) 取版本信息里的 CompanyName */
    if (FeLoadFileVersion(Path, &ver) && ver.CompanyName[0]) {
        strcpy_s(Job->Company, sizeof(Job->Company), ver.CompanyName);
        if (strstr(ver.CompanyName, "Microsoft") != NULL) {
            Job->IsMicrosoft = 1;
            strcpy_s(Job->Message, sizeof(Job->Message), "");
            return 2;               /* 2 = 微软文件，拒绝上传 */
        }
    }

    /* 2) 取 SHA-256（用于查询，不上传文件本体） */
    if (!FeFileSha256(Path, Job->Sha256, sizeof(Job->Sha256))) {
        strcpy_s(Job->Message, sizeof(Job->Message), "cannot compute SHA-256");
        return 0;                   /* 0 = 失败 */
    }
    return 1;                       /* 1 = 可以查询（仍需用户确认） */
}

/* 生成火眼查询 URL（哈希进 URL）。 */
BOOL FeFireeyeBuildUrl(const FE_FIREEYE_JOB *Job, char *Out, size_t OutChars)
{
    if (!Job || !Out || !OutChars)
        return FALSE;
    if (!Job->Sha256[0])
        return FALSE;
    sprintf_s(Out, OutChars, "https://www.virscan.org/search?search=%s", Job->Sha256);
    return TRUE;
}

/* 按原版文案生成"微软文件不上传"的提示。 */
void FeFireeyeMsMessage(const char *FileName, char *Out, size_t OutChars)
{
    if (!Out || !OutChars)
        return;
    sprintf_s(Out, OutChars,
              "%s is belong to Microsoft,it don't upload to FireEye's site",
              FileName ? FileName : "(?)");
}

/* ------------------------------------------------------------- 上传记录管理 */

/* 记录文件放在 %TEMP%\XPCHunter_FireeyeRecords.txt，每行：
 *   <时间戳>\t<哈希>\t<路径> */
static void FeFireeyeRecordPath(char *Out, size_t OutChars)
{
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    sprintf_s(Out, OutChars, "%sXPCHunter_FireeyeRecords.txt", tmp);
}

BOOL FeFireeyeAddRecord(const FE_FIREEYE_JOB *Job)
{
    char path[MAX_PATH];
    FILE *f;
    SYSTEMTIME st;

    if (!Job)
        return FALSE;
    FeFireeyeRecordPath(path, sizeof(path));
    if (fopen_s(&f, path, "ab") != 0 || !f)
        return FALSE;
    GetLocalTime(&st);
    fprintf(f, "%04u-%02u-%02u %02u:%02u:%02u\t%s\t%s\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            Job->Sha256[0] ? Job->Sha256 : "(nosha)", Job->Path);
    fclose(f);
    return TRUE;
}

/* 读取记录条数（View the result 用）。 */
ULONG FeFireeyeRecordCount(void)
{
    char path[MAX_PATH];
    FILE *f;
    ULONG n = 0;
    char line[1024];

    FeFireeyeRecordPath(path, sizeof(path));
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return 0;
    while (fgets(line, sizeof(line), f))
        n++;
    fclose(f);
    return n;
}

/* 列出记录（View the result）。 */
BOOL FeFireeyeListRecords(FE_FIREEYE_RECORD_LIST *List)
{
    char path[MAX_PATH];
    FILE *f;
    char line[1024];

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;

    FeFireeyeRecordPath(path, sizeof(path));
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return FALSE;
    while (fgets(line, sizeof(line), f)) {
        FE_FIREEYE_RECORD *e;
        char *tab1, *tab2;
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        tab1 = strchr(line, '\t');
        if (!tab1)
            continue;
        *tab1++ = 0;
        tab2 = strchr(tab1, '\t');
        if (!tab2)
            continue;
        *tab2++ = 0;

        if (List->Count >= List->Capacity) {
            ULONG newCap = List->Capacity ? List->Capacity * 2 : 16;
            FE_FIREEYE_RECORD *p = (FE_FIREEYE_RECORD *)realloc(
                List->Items, newCap * sizeof(FE_FIREEYE_RECORD));
            if (!p)
                break;
            List->Items = p;
            List->Capacity = newCap;
        }
        e = &List->Items[List->Count++];
        ZeroMemory(e, sizeof(*e));
        strcpy_s(e->Time, sizeof(e->Time), line);
        strcpy_s(e->Sha256, sizeof(e->Sha256), tab1);
        strcpy_s(e->Path, sizeof(e->Path), tab2);
    }
    fclose(f);
    return TRUE;
}

void FeFireeyeFreeRecords(FE_FIREEYE_RECORD_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* Delete upload record：删除整个记录文件。 */
BOOL FeFireeyeDeleteRecords(void)
{
    char path[MAX_PATH];
    FeFireeyeRecordPath(path, sizeof(path));
    return DeleteFileA(path) ? TRUE : (GetLastError() == ERROR_FILE_NOT_FOUND);
}

/* ---------------------------------------------------------------- CLI 输出 */

BOOL FePrintFireeye(const char *Path)
{
    FE_FIREEYE_JOB job;
    int rc;

    if (!Path || !Path[0]) {
        printf("fireeye: no path\n");
        return FALSE;
    }
    rc = FeFireeyePrecheck(Path, &job);
    printf("fireeye analysis for: %s\n", Path);
    if (rc == 2) {
        char msg[512];
        const char *base = Path;
        const char *p = Path;
        while (*p) { if (*p == 92 || *p == 47) base = p + 1; p++; }
        FeFireeyeMsMessage(base, msg, sizeof(msg));
        printf("  verdict : DO NOT UPLOAD\n  message : %s\n", msg);
        printf("  company : %s\n", job.Company);
        return TRUE;
    }
    if (rc == 0) {
        printf("  verdict : cannot analyse (%s)\n", job.Message);
        return FALSE;
    }
    printf("  sha256  : %s\n", job.Sha256);
    {
        char url[512];
        if (FeFireeyeBuildUrl(&job, url, sizeof(url)))
            printf("  query   : %s\n", url);
    }
    printf("  note    : upload requires explicit user confirmation (GUI dialog)\n");
    printf("  records : %lu existing\n", FeFireeyeRecordCount());
    return TRUE;
}