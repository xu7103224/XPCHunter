// ============================================================================
// FeFileDlg.c — File 页的交互层（2026-10-29 新增）
//
// 把 FeFileTools.c 的纯数据能力接到界面上。为了不引入 82 个 MFC 对话框的
// 复杂度，这里统一用「状态栏输出 + 输入框」的方式，与原版对话框等价：
//
//   CSearchFileDialog        → FeFileSearchDialog（输入目录/通配/深度/最小体积）
//   CFileMd5Dialog           → FeFileHashView（MD5 + SHA1 + SHA256 三行状态）
//   CFileAssociationDialog   → FeFileAssociationView（ProgID + 命令行）
//   CMovePendingDialog       → FeFilePendingView（列出所有挂起操作）
//   CRenameFileNameDialog    → 复用 DoPromptText + FeRenameFileNow
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

/* 搜索：在 File 页直接换个"结果视图"——把命中项填进同一个列表。
   返回命中数；0 表示无命中或参数无效。 */
ULONG FeFileSearchDialog(HWND Owner, char *OutDir, int DirChars,
                         char *OutPattern, int PatChars, int *OutDepth, ULONG64 *OutMinSize)
{
    char dir[MAX_PATH * 2];
    char pat[128];
    char extra[128];
    int depth = 6;
    ULONG64 minSize = 0;

    if (OutDir && DirChars > 0 && OutDir[0])
        strncpy_s(dir, sizeof(dir), OutDir, _TRUNCATE);
    else if (g_hFlDir) {
        GetWindowTextA(g_hFlDir, dir, sizeof(dir));
        if (!dir[0])
            strcpy_s(dir, sizeof(dir), "C:\\Windows");
    } else {
        strcpy_s(dir, sizeof(dir), "C:\\Windows");
    }
    strcpy_s(pat, sizeof(pat), "*.*");

    if (!DoPromptText(Owner, "Search File - Directory",
                      "Root directory to search:", dir, sizeof(dir)))
        return 0;
    if (!DoPromptText(Owner, "Search File - Pattern",
                      "File pattern (wildcards, e.g. *.sys):", pat, sizeof(pat)))
        return 0;
    sprintf_s(extra, sizeof(extra), "%d", depth);
    if (DoPromptText(Owner, "Search File - Depth",
                     "Max subdirectory depth (0 = current dir only):", extra, sizeof(extra))) {
        int d = atoi(extra);
        if (d >= 0 && d <= 32)
            depth = d;
    }

    if (OutDir && DirChars > 0) strncpy_s(OutDir, DirChars, dir, _TRUNCATE);
    if (OutPattern && PatChars > 0) strncpy_s(OutPattern, PatChars, pat, _TRUNCATE);
    if (OutDepth) *OutDepth = depth;
    if (OutMinSize) *OutMinSize = minSize;
    return 1;
}

/* 哈希视图：三行状态（MD5 / SHA1 / SHA256） */
BOOL FeFileHashView(HWND Owner, const char *Path)
{
    char md5[80] = { 0 }, sha1[80] = { 0 }, sha256[80] = { 0 };
    char msg[900];
    BOOL ok1, ok2, ok3;

    if (!Path || !Path[0]) {
        if (g_hFlStatus) SetWindowTextA(g_hFlStatus, "File MD5: select a file first");
        return FALSE;
    }
    if (g_hFlStatus) SetWindowTextA(g_hFlStatus, "File MD5: hashing...");
    ok1 = FeHashFile(Path, CALG_MD5, md5, sizeof(md5));
    ok2 = FeHashFile(Path, CALG_SHA1, sha1, sizeof(sha1));
    ok3 = FeHashFile(Path, CALG_SHA_256, sha256, sizeof(sha256));

    sprintf_s(msg, sizeof(msg),
              "MD5=%s | SHA1=%s | SHA256=%s  [%s]",
              ok1 ? md5 : "(fail)", ok2 ? sha1 : "(fail)", ok3 ? sha256 : "(fail)", Path);
    if (g_hFlStatus) SetWindowTextA(g_hFlStatus, msg);
    (void)Owner;
    return ok1 || ok2 || ok3;
}

/* 关联视图：扩展名 -> ProgID -> 命令行 */
BOOL FeFileAssociationView(HWND Owner, const char *Path)
{
    char ext[64], progid[256] = { 0 }, cmd[1024] = { 0 };
    char msg[1400];
    const char *dot;

    if (!Path || !Path[0]) {
        if (g_hFlStatus) SetWindowTextA(g_hFlStatus, "File Association: select a file first");
        return FALSE;
    }
    dot = strrchr(Path, '.');
    if (!dot || strlen(dot) >= sizeof(ext)) {
        if (g_hFlStatus) SetWindowTextA(g_hFlStatus, "File Association: file has no extension");
        return FALSE;
    }
    strncpy_s(ext, sizeof(ext), dot, _TRUNCATE);

    if (!FeGetFileAssociation(ext, progid, sizeof(progid), cmd, sizeof(cmd))) {
        sprintf_s(msg, sizeof(msg), "File Association: %s has no registered handler", ext);
        if (g_hFlStatus) SetWindowTextA(g_hFlStatus, msg);
        return FALSE;
    }
    sprintf_s(msg, sizeof(msg), "Association: %s -> %s | open: %s", ext, progid,
              cmd[0] ? cmd : "(no open command)");
    if (g_hFlStatus) SetWindowTextA(g_hFlStatus, msg);
    (void)Owner;
    return TRUE;
}

/* Pending 视图：一次性把所有挂起操作写入状态栏（截断到可读长度） */
BOOL FeFilePendingView(HWND Owner)
{
    char buf[4096];
    char msg[4600];

    if (!FeQueryPendingFileOps(buf, sizeof(buf))) {
        if (g_hFlStatus)
            SetWindowTextA(g_hFlStatus,
                           "Pending: no PendingFileRenameOperations (no file operation "
                           "scheduled for the next reboot)");
        return FALSE;
    }
    sprintf_s(msg, sizeof(msg), "Pending file operations at next reboot:\r\n%s", buf);
    MessageBoxA(Owner, msg, "Move Pending", MB_ICONINFORMATION | MB_OK);
    if (g_hFlStatus)
        SetWindowTextA(g_hFlStatus, "Pending: listed scheduled file operations");
    return TRUE;
}