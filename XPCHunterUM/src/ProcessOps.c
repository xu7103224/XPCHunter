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

/* ---------------------------------------------------------------------------
 * Process 页状态栏与 Ring3 可达性
 *
 * 原版状态栏：`Processes: %d, Hidden Processes: %d, Ring3 Inaccessible Processes: %d`
 *   Processes              驱动 EPROCESS 链表里的进程数（0xE4）
 *   Hidden Processes       在驱动链表里、但用户态 Toolhelp32 快照里没有的进程
 *   Ring3 Inaccessible     OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) 失败的进程
 * 两个后者都是"用户态看不见"的度量，正好对应原版的这两个计数。
 * ------------------------------------------------------------------------- */

BOOL FeIsProcessRing3Accessible(ULONG Pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (h) {
        CloseHandle(h);
        return TRUE;
    }
    return FALSE;
}

/* 用 Toolhelp32 快照建一个 PID 集合，供 Hidden 判定使用。 */
typedef struct _FE_PIDSET {
    ULONG *Items;
    ULONG  Count;
    ULONG  Capacity;
} FE_PIDSET;

static BOOL FePidSetHas(const FE_PIDSET *Set, ULONG Pid)
{
    ULONG i;
    for (i = 0; i < Set->Count; i++)
        if (Set->Items[i] == Pid)
            return TRUE;
    return FALSE;
}

static BOOL FePidSetAdd(FE_PIDSET *Set, ULONG Pid)
{
    if (Set->Count == Set->Capacity) {
        ULONG cap = Set->Capacity ? Set->Capacity * 2 : 256;
        ULONG *p = (ULONG *)realloc(Set->Items, cap * sizeof(ULONG));
        if (!p)
            return FALSE;
        Set->Items = p;
        Set->Capacity = cap;
    }
    Set->Items[Set->Count++] = Pid;
    return TRUE;
}

static void FeBuildUserPidSet(FE_PIDSET *Set)
{
    HANDLE snap;
    PROCESSENTRY32W pe;

    ZeroMemory(Set, sizeof(*Set));
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!FePidSetAdd(Set, pe.th32ProcessID))
                break;
            ZeroMemory(&pe, sizeof(pe));
            pe.dwSize = sizeof(pe);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* 统计三个数。Inaccessible[i] 与 List->Items[i] 一一对应（可选输出）。 */
BOOL FeComputeProcessStatus(const FE_PROCESS_LIST *List,
                            ULONG *pHidden, ULONG *pInaccessible,
                            BOOL *pInaccessibleFlags)
{
    FE_PIDSET users;
    ULONG i, hidden = 0, inaccessible = 0;

    if (!List)
        return FALSE;
    FeBuildUserPidSet(&users);
    for (i = 0; i < List->Count; i++) {
        BOOL inUser = FePidSetHas(&users, List->Items[i].Pid);
        BOOL accessible = FeIsProcessRing3Accessible(List->Items[i].Pid);
        if (!inUser)
            hidden++;
        if (!accessible)
            inaccessible++;
        if (pInaccessibleFlags)
            pInaccessibleFlags[i] = accessible;
    }
    free(users.Items);
    if (pHidden) *pHidden = hidden;
    if (pInaccessible) *pInaccessible = inaccessible;
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * View Timer / View HotKey
 *
 * 原版这两页展示进程的定时器与热键。它们在内核里没有对应命令
 * （命令表里没有 Timer/HotKey 项），但两者的用户态句柄都可枚举：
 *   Timer   类型名为 "Timer" 的句柄（NtQuerySystemInformation 全系统句柄表）
 *   HotKey  进程注册的热键（RegisterHotKey 产生 USER32 侧对象，用户态
 *           可通过按线程窗口的热键列表枚举；这里用 GetGUIThreadInfo 拿
 *           前台/该进程线程的 hwndActive，再用 WM_GETDLGCODE 不可行 ——
 *           真实的表在 win32k，只能从驱动取。为不伪造数据，HotKey 页在
 *           取不到时明确显示 "no data source"，不编造条目。）
 *
 * Timer 是有真实数据源的，这里实现它；HotKey 保持未实现并如实标注。
 * ------------------------------------------------------------------------- */

BOOL FeLoadProcessTimers(ULONG Pid, ULONG MaxCount, FE_HANDLE_LIST *List)
{
    FE_HANDLE_LIST all;
    ULONG i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 512;
    if (!FeLoadProcessHandles(Pid, 8192, &all))
        return FALSE;

    List->Items = (FE_HANDLE_ENTRY *)calloc(MaxCount, sizeof(FE_HANDLE_ENTRY));
    if (!List->Items) {
        FeFreeProcessHandles(&all);
        return FALSE;
    }
    List->Capacity = MaxCount;

    for (i = 0; i < all.Count && List->Count < List->Capacity; i++) {
        if (_stricmp(all.Items[i].TypeName, "Timer") != 0)
            continue;
        List->Items[List->Count++] = all.Items[i];
    }
    FeFreeProcessHandles(&all);
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * 模块搜索（原版 Modules 视图的五项 F 菜单）
 *
 *   Find Module               按名字子串在所有进程的模块里找
 *   Find Unsigned Module      模块文件无有效 Authenticode 签名
 *   Find Not Signature Module 模块文件没有签名段（和上一条的差别：这里还要求
 *                             文件本身不可读/无 PE 签名目录，更严格）
 *   Find Target               找"藏在模块映射外"的可执行区域：目标进程里
 *                             可执行但不对应任何已知模块的内存区
 *   Find Hidden Item          模块在进程里加载了，但磁盘上没有对应文件
 *
 * 全部只读，不需要驱动。结果写进调用方给的 FE_MODSEARCH_LIST。
 * ------------------------------------------------------------------------- */

static void FeModSearchAdd(FE_MODSEARCH_LIST *List, ULONG Pid, const char *Name,
                           ULONG64 Base, ULONG64 Size, const char *Detail)
{
    FE_MODSEARCH_ENTRY *e;

    if (!List)
        return;
    if (List->Count == List->Capacity) {
        ULONG cap = List->Capacity ? List->Capacity * 2 : 32;
        FE_MODSEARCH_ENTRY *p = (FE_MODSEARCH_ENTRY *)realloc(
            List->Items, (size_t)cap * sizeof(FE_MODSEARCH_ENTRY));
        if (!p)
            return;
        List->Items = p;
        List->Capacity = cap;
    }
    e = &List->Items[List->Count++];
    ZeroMemory(e, sizeof(*e));
    e->Pid = Pid;
    strncpy_s(e->Name, sizeof(e->Name), Name ? Name : "", _TRUNCATE);
    e->Base = Base;
    e->Size = Size;
    strncpy_s(e->Detail, sizeof(e->Detail), Detail ? Detail : "", _TRUNCATE);
}

void FeFreeModSearch(FE_MODSEARCH_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 所有进程 PID 快照（模块搜索要遍历全系统）。 */
static ULONG FeAllPids(ULONG *Pids, ULONG MaxPids)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    ULONG n = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (n < MaxPids)
                Pids[n++] = pe.th32ProcessID;
            ZeroMemory(&pe, sizeof(pe));
            pe.dwSize = sizeof(pe);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

BOOL FeFindModulesByName(const char *Needle, FE_MODSEARCH_LIST *List)
{
    static ULONG pids[2048];
    ULONG count, i;
    ULONG hits = 0;

    if (!List || !Needle)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    count = FeAllPids(pids, 2048);
    for (i = 0; i < count; i++) {
        FE_MODULE_LIST mods;
        ULONG k;
        if (!FeLoadProcessModules(pids[i], 4096, &mods))
            continue;
        for (k = 0; k < mods.Count; k++) {
            char name[256];
            char path[FE_MODULE_PATH_CHARS * 2];
            FeWideToAnsi(mods.Items[k].Name, name, sizeof(name));
            FeWideToAnsi(mods.Items[k].Path, path, sizeof(path));
            if (_strnicmp(name, Needle, strlen(Needle)) != 0 &&
                strstr(path, Needle) == NULL)
                continue;
            FeModSearchAdd(List, pids[i], name, mods.Items[k].Base,
                           mods.Items[k].Size, path);
            hits++;
        }
        FeFreeProcessModules(&mods);
    }
    return TRUE;
}

/* Find Unsigned / Find Not Signature：对每个模块的文件做 WinVerifyTrust。
 * 两者差别：
 *   Unsigned      文件存在但签名校验不过（= 用户态能看到的"未签名"）
 *   NotSignature  文件连 PE 安全目录都没有（更严格，比 Unsigned 少）
 * 为了不重复扫两遍，这里一次扫完，按 Mode 决定收集哪一类。 */
BOOL FeFindUnsignedModules(int StrictNoSignatureDir, FE_MODSEARCH_LIST *List)
{
    static ULONG pids[2048];
    ULONG count, i;
    ULONG checked = 0;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    count = FeAllPids(pids, 2048);
    for (i = 0; i < count; i++) {
        FE_MODULE_LIST mods;
        ULONG k;
        if (!FeLoadProcessModules(pids[i], 4096, &mods))
            continue;
        for (k = 0; k < mods.Count; k++) {
            char name[256];
            char path[FE_MODULE_PATH_CHARS * 2];
            WCHAR wpath[FE_MODULE_PATH_CHARS];
            FeWideToAnsi(mods.Items[k].Name, name, sizeof(name));
            FeWideToAnsi(mods.Items[k].Path, path, sizeof(path));
            if (!path[0])
                continue;
            /* 只查有磁盘文件的 */
            MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, FE_MODULE_PATH_CHARS);
            if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES)
                continue;
            checked++;
            if (StrictNoSignatureDir) {
                /* 检查 PE 安全目录是否为空 */
                HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ |
                                       FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                       OPEN_EXISTING, 0, NULL);
                BOOL hasDir = TRUE;
                if (h != INVALID_HANDLE_VALUE) {
                    IMAGE_DOS_HEADER dos;
                    DWORD got = 0;
                    hasDir = FALSE;
                    if (ReadFile(h, &dos, sizeof(dos), &got, NULL) && got == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE) {
                        /* 【2026-10-22 修正】原来读进 IMAGE_NT_HEADERS32 再强转成
                           IMAGE_OPTIONAL_HEADER64 —— 结构体大小不同，DataDirectory
                           的偏移也就不同，读出来必然是垃圾（结果 nosig 比 unsigned
                           还多）。改为按 Magic 分两次读正确的结构体。 */
                        IMAGE_NT_HEADERS64 nt64;
                        if (SetFilePointer(h, dos.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
                            ReadFile(h, &nt64, sizeof(nt64), &got, NULL) && got == sizeof(nt64) &&
                            nt64.Signature == IMAGE_NT_SIGNATURE) {
                            if (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                                hasDir = nt64.OptionalHeader.DataDirectory[
                                    IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0;
                            else {
                                /* 32 位映像：重新按 32 位头读一遍 */
                                IMAGE_NT_HEADERS32 nt32;
                                DWORD got32 = 0;
                                if (SetFilePointer(h, dos.e_lfanew, NULL, FILE_BEGIN) !=
                                    INVALID_SET_FILE_POINTER &&
                                    ReadFile(h, &nt32, sizeof(nt32), &got32, NULL) &&
                                    got32 == sizeof(nt32))
                                    hasDir = nt32.OptionalHeader.DataDirectory[
                                        IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0;
                            }
                        }
                    }
                    CloseHandle(h);
                }
                if (hasDir)
                    continue;          /* 有签名目录，不算 */
                FeModSearchAdd(List, pids[i], name, mods.Items[k].Base,
                               mods.Items[k].Size, path);
            } else {
                if (FeVerifyFileSignature(path))
                    continue;          /* 内嵌签名有效且受信任 */
                {
                    /* 明确标注判据：这里只校验内嵌签名。系统 catalog 签名的
                       文件（如 uxtheme.dll）也会落进结果，Detail 里说明，
                       避免读者把"无内嵌签名"当成"完全未签名"。 */
                    char detail[FE_MSEARCH_DETAIL_CHARS];
                    sprintf_s(detail, sizeof(detail),
                              "%s  [no embedded signature, trust=0x%08lX]",
                              path, (unsigned long)g_LastTrustStatus);
                    FeModSearchAdd(List, pids[i], name, mods.Items[k].Base,
                                   mods.Items[k].Size, detail);
                }
            }
        }
        FeFreeProcessModules(&mods);
    }
    (void)checked;
    return TRUE;
}

/* Find Target：目标进程里"可执行但不对应任何模块"的内存区。
 * 用 VirtualQueryEx 拿属性，再与模块列表比对区间。 */
BOOL FeFindTargetRegions(ULONG Pid, FE_MODSEARCH_LIST *List)
{
    FE_MODULE_LIST mods;
    HANDLE h;
    ULONG64 addr = 0;
    const ULONG64 userLimit = 0x7FFFFFFEFFFFULL;
    MEMORY_BASIC_INFORMATION mbi;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!FeLoadProcessModules(Pid, 4096, &mods))
        return FALSE;
    h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!h) {
        FeFreeProcessModules(&mods);
        return FALSE;
    }
    {
        ULONG committed = 0, exec = 0;
    while (addr < userLimit) {
        ULONG k;
        BOOL inside = FALSE;
        SIZE_T got = VirtualQueryEx(h, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi));
        if (!got)
            break;
        if (mbi.RegionSize == 0) {
            addr += 0x1000;
            continue;
        }
        if (mbi.State == MEM_COMMIT)
            committed++;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            exec++;
            ULONG64 rbase = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
            ULONG64 rsize = (ULONG64)mbi.RegionSize;
            for (k = 0; k < mods.Count; k++) {
                ULONG64 mbase = mods.Items[k].Base;
                ULONG64 msize = mods.Items[k].Size;
                /* Size 为 0 的模块没有可信区间，不能拿来"覆盖"任何区域 */
                if (!mbase || !msize)
                    continue;
                if (rbase < mbase + msize && mbase < rbase + rsize) {
                    inside = TRUE;
                    break;
                }
            }
            /* 【2026-10-22】原版 Find Target 抓的是"可执行但未映射任何模块"的
               区域。这里额外要求 Type != MEM_IMAGE —— MEM_IMAGE 区域即使
               不在模块列表里（如已卸载模块的残影）也应归 Hidden Item 处理，
               不算 Target。 */
            if (!inside && mbi.Type != MEM_IMAGE) {
                char detail[128];
                sprintf_s(detail, sizeof(detail),
                          "executable region, no module: protect=0x%lX type=0x%lX",
                          (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
                FeModSearchAdd(List, Pid, "(no module)", rbase, rsize, detail);
            }
        }
        addr = (ULONG64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    /* 统计信息用于判断"0 条"是真干净还是枚举受限 */
    {
        char d[192];
        sprintf_s(d, sizeof(d),
                  "scanned %lu regions (%lu committed, %lu executable), %lu modules, %lu hits",
                  (unsigned long)(committed + exec), (unsigned long)committed,
                  (unsigned long)exec, mods.Count, List->Count);
        FeModSearchAdd(List, Pid, "(scan)", 0, 0, d);
    }
    }
    CloseHandle(h);
    FeFreeProcessModules(&mods);
    return TRUE;
}

/* Find Hidden Item：模块在进程里加载但磁盘上没有对应文件。 */
BOOL FeFindHiddenModules(FE_MODSEARCH_LIST *List)
{
    static ULONG pids[2048];
    ULONG count, i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    count = FeAllPids(pids, 2048);
    for (i = 0; i < count; i++) {
        FE_MODULE_LIST mods;
        ULONG k;
        if (!FeLoadProcessModules(pids[i], 4096, &mods))
            continue;
        for (k = 0; k < mods.Count; k++) {
            char name[256];
            char path[FE_MODULE_PATH_CHARS * 2];
            WCHAR wpath[FE_MODULE_PATH_CHARS];
            FeWideToAnsi(mods.Items[k].Name, name, sizeof(name));
            FeWideToAnsi(mods.Items[k].Path, path, sizeof(path));
            if (!path[0]) {
                FeModSearchAdd(List, pids[i], name, mods.Items[k].Base,
                               mods.Items[k].Size, "(module has no path)");
                continue;
            }
            MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, FE_MODULE_PATH_CHARS);
            if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES)
                FeModSearchAdd(List, pids[i], name, mods.Items[k].Base,
                               mods.Items[k].Size, path);
        }
        FeFreeProcessModules(&mods);
    }
    return TRUE;
}
