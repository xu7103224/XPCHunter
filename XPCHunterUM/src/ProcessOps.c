// ============================================================================
// ProcessOps.c — Process 页的进程操作（原版右键菜单）
//
//   Kill                 0x28（PID + EPROCESS），已在 ProcessViews.c
//   Force Kill           0xA2（只给 EPROCESS，绕过 PID 校验）
//   Kill By Process Tree 先枚举进程树，从叶子往根终止
//   Kill And Delete File 终止后删除映像文件（先试直接删，失败登记重启删除）
//   Suspend / Resume     NtSuspendProcess / NtResumeProcess
//   Dump Memory          按区间把目标进程内存写到文件（ReadProcessMemory）
//
// 进程树用 Toolhelp32 快照建立父子关系，和任务管理器的层级一致。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

typedef LONG (NTAPI *PFN_NtSuspendProcess)(HANDLE);
typedef LONG (NTAPI *PFN_NtResumeProcess)(HANDLE);

static PFN_NtSuspendProcess FeNtSuspend(void)
{
    static PFN_NtSuspendProcess p;
    if (!p)
        p = (PFN_NtSuspendProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                 "NtSuspendProcess");
    return p;
}

static PFN_NtResumeProcess FeNtResume(void)
{
    static PFN_NtResumeProcess p;
    if (!p)
        p = (PFN_NtResumeProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                "NtResumeProcess");
    return p;
}

/* Force Kill：只凭 EPROCESS 号走 0xA2，不看 PID 是否还活着。 */
BOOL FeForceKillProcess(XPCH_CLIENT *Client, ULONG Pid)
{
    FE_PROCESS_LIST list;
    ULONG64 eprocess = 0;
    ULONG i;
    BOOL ok;

    if (!Client || !Client->Opened || !Pid)
        return FALSE;
    if (!FeLoadProcessList(Client, FE_PROC_DEFAULT_MAX, &list))
        return FALSE;
    for (i = 0; i < list.Count; i++) {
        if (list.Items[i].Pid == Pid) {
            eprocess = list.Items[i].Eprocess;
            break;
        }
    }
    FeFreeProcessList(&list);
    if (!eprocess)
        return FALSE;
    ok = FeKillProcess(Client, Pid, eprocess, TRUE);
    return ok;
}

/* Suspend / Resume 整个进程。 */
BOOL FeSuspendResumeProcess(ULONG Pid, BOOL Suspend)
{
    HANDLE h;
    LONG st = -1;

    if (!Pid)
        return FALSE;
    h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE, Pid);
    if (!h)
        return FALSE;
    if (Suspend) {
        PFN_NtSuspendProcess fn = FeNtSuspend();
        if (fn)
            st = fn(h);
    } else {
        PFN_NtResumeProcess fn = FeNtResume();
        if (fn)
            st = fn(h);
    }
    CloseHandle(h);
    return st == 0;
}

/* 把 root 及其所有后代按"叶子优先"排好（后序：先子后父）。
 * 返回收集到的 PID 数；Pids[0] 会是最深的叶子之一，最后才是 root。 */
ULONG FeCollectProcessTree(ULONG RootPid, ULONG *Pids, ULONG MaxPids)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    ULONG *allPids = NULL, *allParent = NULL;
    ULONG allCount = 0, allCap = 0;
    ULONG i;

    if (!Pids || !MaxPids)
        return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (allCount == allCap) {
                ULONG cap = allCap ? allCap * 2 : 128;
                ULONG *np = (ULONG *)realloc(allPids, cap * sizeof(ULONG));
                ULONG *pp = (ULONG *)realloc(allParent, cap * sizeof(ULONG));
                if (!np || !pp) {
                    free(np ? np : allPids);
                    free(pp ? pp : allParent);
                    allPids = NULL;
                    allParent = NULL;
                    break;
                }
                allPids = np;
                allParent = pp;
                allCap = cap;
            }
            allPids[allCount] = pe.th32ProcessID;
            allParent[allCount] = pe.th32ParentProcessID;
            allCount++;
            ZeroMemory(&pe, sizeof(pe));
            pe.dwSize = sizeof(pe);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!allPids)
        return 0;

    /* 逐层收集，每层放进结果数组；这样天然是"从上到下"，
     * 终止时倒序执行就是叶子优先。 */
    {
        ULONG count = 0;
        ULONG *level = (ULONG *)malloc(allCount * sizeof(ULONG));
        ULONG levelCount = 0;

        if (!level) {
            free(allPids);
            free(allParent);
            return 0;
        }
        if (count < MaxPids)
            Pids[count++] = RootPid;
        level[levelCount++] = RootPid;

        for (;;) {
            ULONG nextCount = 0;
            ULONG *next = (ULONG *)malloc(allCount * sizeof(ULONG));
            if (!next)
                break;
            for (i = 0; i < allCount; i++) {
                ULONG l;
                for (l = 0; l < levelCount; l++) {
                    if (allParent[i] == level[l] && allPids[i] != RootPid) {
                        next[nextCount++] = allPids[i];
                        if (count < MaxPids)
                            Pids[count++] = allPids[i];
                        break;
                    }
                }
            }
            free(level);
            level = next;
            levelCount = nextCount;
            if (!levelCount)
                break;
        }
        free(level);

        /* 倒序：先子后父 */
        for (i = 0; i < count / 2; i++) {
            ULONG t = Pids[i];
            Pids[i] = Pids[count - 1 - i];
            Pids[count - 1 - i] = t;
        }
        free(allPids);
        free(allParent);
        return count;
    }
}

/* 进程是否还在（OpenProcess 打不开且错误是"参数无效"即已退出）。 */
static BOOL FeProcessStillExists(ULONG Pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (h) {
        CloseHandle(h);
        return TRUE;
    }
    return GetLastError() != ERROR_INVALID_PARAMETER;
}

/* Kill By Process Tree：从叶子往根杀。
 * 杀父进程会让子进程连带退出（此时驱动对子进程的 0xA2 会"失败"），
 * 所以判定一律以"进程是否已消失"为准，并对残留项再补杀几轮。 */
BOOL FeKillProcessTree(XPCH_CLIENT *Client, ULONG RootPid,
                       ULONG *pKilled, ULONG *pFailed)
{
    ULONG pids[512];
    ULONG count, i, round, killed = 0, failed = 0;

    if (pKilled) *pKilled = 0;
    if (pFailed) *pFailed = 0;
    count = FeCollectProcessTree(RootPid, pids, 512);
    if (!count)
        return FALSE;

    for (round = 0; round < 3; round++) {
        ULONG remaining = 0;
        for (i = 0; i < count; i++) {
            if (!FeProcessStillExists(pids[i]))
                continue;
            FeForceKillProcess(Client, pids[i]);
            Sleep(150);
        }
        /* 本轮结束后统计 */
        for (i = 0; i < count; i++) {
            if (FeProcessStillExists(pids[i]))
                remaining++;
        }
        if (!remaining)
            break;
    }

    for (i = 0; i < count; i++) {
        if (FeProcessStillExists(pids[i]))
            failed++;
        else
            killed++;
    }
    if (pKilled) *pKilled = killed;
    if (pFailed) *pFailed = failed;
    return failed == 0;
}

/* 取进程映像路径（QueryFullProcessImageNameW）。 */
BOOL FeGetProcessImagePath(ULONG Pid, char *Out, size_t OutChars)
{
    HANDLE h;
    WCHAR wpath[1024];
    DWORD len = 1024;

    if (!Out || !OutChars)
        return FALSE;
    Out[0] = 0;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!h)
        return FALSE;
    if (!QueryFullProcessImageNameW(h, 0, wpath, &len)) {
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);
    WideCharToMultiByte(CP_ACP, 0, wpath, -1, Out, (int)OutChars, NULL, NULL);
    return Out[0] != 0;
}

/* Kill And Delete File：先终止，再删映像文件。
 * 文件被占用时（进程刚退出、句柄没释放）退化为"重启时删除"，并如实报告。 */
BOOL FeKillAndDeleteProcessFile(XPCH_CLIENT *Client, ULONG Pid,
                                char *DeletedPath, size_t PathChars,
                                DWORD *pError, BOOL *pRebootDelete)
{
    char path[1024];
    WCHAR wpath[1024];
    BOOL killed;

    if (pError) *pError = 0;
    if (pRebootDelete) *pRebootDelete = FALSE;
    if (DeletedPath && PathChars)
        DeletedPath[0] = 0;

    if (!FeGetProcessImagePath(Pid, path, sizeof(path))) {
        if (pError) *pError = GetLastError();
        return FALSE;
    }
    killed = FeForceKillProcess(Client, Pid);
    Sleep(300);
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 1024);
    if (DeleteFileW(wpath)) {
        if (DeletedPath && PathChars)
            strcpy_s(DeletedPath, PathChars, path);
        return TRUE;
    }
    {
        DWORD err = GetLastError();
        if (MoveFileExW(wpath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            if (pRebootDelete) *pRebootDelete = TRUE;
            if (DeletedPath && PathChars)
                strcpy_s(DeletedPath, PathChars, path);
            return killed;
        }
        if (pError) *pError = err;
    }
    return FALSE;
}

/* Dump Memory：把 [Base, Base+Size) 读出来写成文件。
 * 用 ReadProcessMemory 分块读，读不到的部分填 0 并继续（和原版"尽量取"一致）。 */
BOOL FeDumpMemoryToFile(ULONG Pid, ULONG64 Base, ULONG64 Size,
                        const char *OutPath, ULONG64 *pWritten)
{
    HANDLE h, f;
    BYTE *buf;
    DWORD chunk = 0x10000;
    ULONG64 done = 0;
    BOOL ok = TRUE;

    if (pWritten) *pWritten = 0;
    if (!OutPath || !OutPath[0] || !Size)
        return FALSE;
    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!h)
        return FALSE;
    if (fopen_s(&f, OutPath, "wb") != 0) {
        CloseHandle(h);
        return FALSE;
    }
    buf = (BYTE *)malloc(chunk);
    if (!buf) {
        fclose(f);
        CloseHandle(h);
        return FALSE;
    }
    while (done < Size) {
        SIZE_T want = (SIZE_T)((Size - done) < chunk ? (Size - done) : chunk);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, (LPCVOID)(ULONG_PTR)(Base + done), buf, want, &got) || got != want) {
            if (got > 0) {
                fwrite(buf, 1, got, f);
                done += got;
                continue;
            }
            /* 整块读不到：填零后继续，除非整段都读不到 */
            memset(buf, 0, want);
            fwrite(buf, 1, want, f);
            done += want;
            ok = FALSE;
        } else {
            fwrite(buf, 1, got, f);
            done += got;
        }
    }
    free(buf);
    fclose(f);
    CloseHandle(h);
    if (pWritten) *pWritten = done;
    return done > 0;
}
