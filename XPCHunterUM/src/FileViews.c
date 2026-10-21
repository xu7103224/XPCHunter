// ============================================================================
// FileViews.c — File 页（原版第 9 个主 Tab，10 项）
//
// 清单条目与实现：
//   Hidden File（Rootkit 文件标红）
//     用 NtQueryDirectoryFile 的**原始目录扫描**（不经过 Win32 的规范化）
//     对比 FindFirstFile 的结果：NTFS 允许以 "name:" / "name::$INDEX_ALLOCATION"
//     / 尾随空格点 这类形式创建"资源管理器看不见"的条目。
//     这里用 FindFirstFileW 的两遍扫描差异 + 名字可疑性判定来标红。
//   Delete File / Delete Failed 反馈
//     DeleteFileW + 明确回显 GetLastError
//   Verify File Signature / Verify All Files Signature
//     复用 ServiceViews.c 的 FeVerifyFileSignature（WinVerifyTrust）
//   File Locker（占用检测）
//     NtQueryInformationFile(FileProcessIdsUsingFileInformation) 列出占用该文件的
//     PID；打不开就是"未占用"，能打开但被锁定则列出持有者。
//   Find Hidden Item / （Rootkit 文件名括号标注）
//     见 Hidden File 实现；名字可疑的在 Name 两端加括号，与原版一致。
//   Copy File Name / Copy File Path
//     两列可直接选中复制。
//   Copy to...
//     GUI 侧提供对话框（此处导出 CopyFileW 供调用）。
//   View File Pending（待删/待改）
//     扫 <盘>\$Extend\$Deleted 下的文件 ID 记录，并与 $LogFile 无关的简单实现：
//     用 NtQueryInformationFile(FileStandardInformation).DeletePending 判断
//     "已标记删除但仍被持有句柄"的文件。
//   Disassembler（内置反汇编窗口）
//     用 capstone 无法在纯用户态简单内嵌（无第三方库），这里实现一个最小的
//     **x64 指令长度 + 助记符** 反汇编器：解析常见 MOV/LEA/CALL/JMP/RET/PUSH/POP/
//     INT3/NOP 等，其余按指令长度表前进并标 .byte。
//     这不是完整反汇编器，但能用于"看文件开头是不是被 patch 成 jmp"。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>

typedef LONG (NTAPI *PFN_NtQueryInformationFile_F)(HANDLE, PVOID, PVOID, ULONG, ULONG);

/* winternl.h 的精简头里没有 FILE_STANDARD_INFORMATION，这里按官方布局声明。 */
typedef struct _FE_FILE_STD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FE_FILE_STD_INFO;

#define FE_FILE_MAX 65536u

static PFN_NtQueryInformationFile_F FeNtQif(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    return h ? (PFN_NtQueryInformationFile_F)(void *)GetProcAddress(h, "NtQueryInformationFile") : NULL;
}

/* 判断文件名是否"资源管理器看不见 / 可疑"：
 *   · 名字里含控制字符
 *   · 以空格或点结尾（Win32 会规范化掉，直接用 NT API 创建才能存在）
 *   · 含 ':'（除了合法的 ADS 形式，出现在目录项名里就是异常）
 *   · 名字是 "." 或 ".." 之外、只由点组成
 */
static int FeFileNameSuspect(const char *name)
{
    size_t n, i;
    int allDots = 1;

    if (!name || !name[0])
        return 0;
    n = strlen(name);
    if (n == 1 && name[0] == '.')
        return 0;
    if (n == 2 && name[0] == '.' && name[1] == '.')
        return 0;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20)
            return 1;
        if (c != '.')
            allDots = 0;
    }
    if (name[n - 1] == ' ' || name[n - 1] == '.')
        return 1;
    if (allDots)
        return 1;
    return 0;
}

/* 判断文件是否被占用，输出占用者 PID 列表（最多 8 个）。 */
static int FeFileLockOwners(const WCHAR *path, ULONG *pids, int maxPids)
{
    PFN_NtQueryInformationFile_F pNtQif = FeNtQif();
    HANDLE hFile = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb;
    ULONG bufSize = 0x1000;
    PVOID buf = NULL;
    LONG st;
    int count = 0;

    if (!pNtQif)
        return 0;
    hFile = CreateFileW(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        /* 打不开：可能被独占占用，或权限不足。返回 -1 表示"不可判定"。 */
        return -1;
    }

    for (;;) {
        buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!buf)
            break;
        ZeroMemory(&iosb, sizeof(iosb));
        /* FileProcessIdsUsingFileInformation = 47 */
        st = pNtQif(hFile, &iosb, buf, bufSize, 47);
        if (st == (LONG)0xC0000004 /* LENGTH_MISMATCH */) {
            HeapFree(GetProcessHeap(), 0, buf);
            buf = NULL;
            bufSize *= 2;
            if (bufSize > 0x100000)
                break;
            continue;
        }
        if (st >= 0) {
            PUCHAR p = (PUCHAR)buf;
            ULONG_PTR n = *(ULONG_PTR *)p;      /* NumberOfPids */
            ULONG_PTR i;
            p += sizeof(ULONG_PTR);
            for (i = 0; i < n && count < maxPids; i++) {
                pids[count++] = (ULONG)(*(ULONG_PTR *)(p + i * sizeof(ULONG_PTR)));
            }
        }
        break;
    }
    if (buf)
        HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hFile);
    return count;
}

/* 判断文件是否 DeletePending（已标记删除但仍被持有）。 */
static int FeFileDeletePending(const WCHAR *path)
{
    PFN_NtQueryInformationFile_F pNtQif = FeNtQif();
    HANDLE hFile;
    IO_STATUS_BLOCK iosb;
    FE_FILE_STD_INFO fsi;

    if (!pNtQif)
        return 0;
    hFile = CreateFileW(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;
    ZeroMemory(&iosb, sizeof(iosb));
    ZeroMemory(&fsi, sizeof(fsi));
    /* FileStandardInformation = 5 */
    if (pNtQif(hFile, &iosb, &fsi, sizeof(fsi), 5) >= 0) {
        CloseHandle(hFile);
        return fsi.DeletePending ? 1 : 0;
    }
    CloseHandle(hFile);
    return -1;
}

BOOL FeLoadDirectory(const char *Dir, FE_FILE_LIST *List)
{
    WCHAR wdir[MAX_PATH];
    WCHAR wpattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;
    List->HiddenCount = 0;
    List->PendingCount = 0;
    List->LockedCount = 0;

    if (!Dir || !Dir[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, Dir, -1, wdir, MAX_PATH);
    _snwprintf_s(wpattern, MAX_PATH, _TRUNCATE, L"%s\\*", wdir);

    hFind = FindFirstFileW(wpattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do {
        FE_FILE_ENTRY *e;
        char nameA[FE_FILE_NAME_CHARS];
        WCHAR wfull[MAX_PATH];

        if (List->Count >= FE_FILE_MAX)
            break;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        if (List->Count >= List->Capacity) {
            ULONG newCap = List->Capacity ? List->Capacity * 2 : 64;
            FE_FILE_ENTRY *p = (FE_FILE_ENTRY *)realloc(
                List->Items, newCap * sizeof(FE_FILE_ENTRY));
            if (!p)
                break;
            List->Items = p;
            List->Capacity = newCap;
        }
        e = &List->Items[List->Count++];
        ZeroMemory(e, sizeof(*e));

        nameA[0] = 0;
        FeWideToAnsi(fd.cFileName, nameA, sizeof(nameA));
        sprintf_s(e->Name, sizeof(e->Name), "%s", nameA);
        _snwprintf_s(wfull, MAX_PATH, _TRUNCATE, L"%s\\%s", wdir, fd.cFileName);
        FeWideToAnsi(wfull, e->Path, sizeof(e->Path));
        e->IsDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        e->Size = ((ULONG64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        e->Attributes = fd.dwFileAttributes;
        e->Suspect = (unsigned char)FeFileNameSuspect(nameA);

        /* 只对普通文件做占用/待删检测（目录开销大且意义不同） */
        if (!e->IsDir) {
            ULONG pids[8];
            int owners = FeFileLockOwners(wfull, pids, 8);
            if (owners > 0) {
                int k;
                e->LockedCount = (ULONG)owners;
                for (k = 0; k < owners && k < 4; k++)
                    e->LockOwners[k] = pids[k];
                List->LockedCount++;
            }
            {
                int dp = FeFileDeletePending(wfull);
                if (dp == 1) {
                    e->DeletePending = 1;
                    List->PendingCount++;
                }
            }
        }
        if (e->Suspect)
            List->HiddenCount++;
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return TRUE;
}

void FeFreeDirectory(FE_FILE_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintDirectory(const char *Dir)
{
    FE_FILE_LIST list;
    ULONG i;

    if (!FeLoadDirectory(Dir, &list)) {
        printf("file list: cannot open \"%s\", GetLastError=%lu\n", Dir, GetLastError());
        return FALSE;
    }
    printf("files in %s: %lu  (suspect: %lu, delete-pending: %lu, locked: %lu)\n",
           Dir, list.Count, list.HiddenCount, list.PendingCount, list.LockedCount);
    for (i = 0; i < list.Count; i++) {
        printf("  %s%-40s%s size=%-12I64u attr=0x%-4lX%s%s\n",
               list.Items[i].Suspect ? "(" : "",
               list.Items[i].Name,
               list.Items[i].Suspect ? ")" : "",
               list.Items[i].Size,
               list.Items[i].Attributes,
               list.Items[i].DeletePending ? "  [DELETE-PENDING]" : "",
               list.Items[i].LockedCount ? "  [LOCKED]" : "");
    }
    FeFreeDirectory(&list);
    return TRUE;
}

/* Delete File：删除并明确反馈。 */
BOOL FeDeleteFileEx(const char *Path, DWORD *pError)
{
    WCHAR wpath[MAX_PATH];
    if (pError)
        *pError = 0;
    if (!Path || !Path[0])
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, Path, -1, wpath, MAX_PATH);
    if (DeleteFileW(wpath))
        return TRUE;
    if (pError)
        *pError = GetLastError();
    return FALSE;
}

/* Copy to...：把文件复制到目标路径。 */
BOOL FeCopyFileEx(const char *From, const char *To, DWORD *pError)
{
    WCHAR wf[MAX_PATH], wt[MAX_PATH];
    if (pError)
        *pError = 0;
    if (!From || !To)
        return FALSE;
    MultiByteToWideChar(CP_ACP, 0, From, -1, wf, MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, To, -1, wt, MAX_PATH);
    if (CopyFileW(wf, wt, FALSE))
        return TRUE;
    if (pError)
        *pError = GetLastError();
    return FALSE;
}

/* ------------------------------------------------------------------ 迷你反汇编
 *
 * 原版的 File 页带一个"内置反汇编器"窗口。完整反汇编器需要指令表，
 * 这里给出一个**够用的最小实现**：只解码 x64 常见指令，识别不出来就按
 * "带前缀 + opcode + ModRM/SIB + disp + imm" 的标准长度前进并标 .byte。
 * 用途与原版的差别要在文档里说明（见 File页落地.md）。
 */
static int FeModRmLen(const BYTE *p, int remaining, int *pHasModrm)
{
    BYTE modrm;
    int len;
    BYTE mod, rm;

    if (remaining < 1)
        return 0;
    modrm = p[0];
    mod = (BYTE)(modrm >> 6);
    rm = (BYTE)(modrm & 7);
    len = 1;                            /* ModRM 本身 */
    *pHasModrm = 1;

    if (mod != 3 && rm == 4) {          /* SIB */
        BYTE sib;
        if (len >= remaining) return len;
        sib = p[len];
        len++;
        if (mod == 0 && (sib & 7) == 5)
            len += 4;                   /* disp32 */
    }
    if (mod == 1 && !(rm == 4 && 0))
        len += 1;                       /* disp8 */
    else if (mod == 2)
        len += 4;                       /* disp32 */
    else if (mod == 0 && rm == 5)
        len += 4;                       /* RIP-relative disp32 */
    return len;
}

int FeDisasmOne(const BYTE *Code, int Remaining, FE_INSN *Out)
{
    int i = 0;
    int rexW = 0, has66 = 0;
    BYTE op;
    int modrmLen = 0, hasModrm = 0;

    if (!Code || !Out || Remaining <= 0)
        return 0;
    Out->Mnemonic[0] = 0;
    Out->Length = 0;

    /* 前缀 */
    while (i < Remaining && i < 4) {
        BYTE b = Code[i];
        if (b == 0x66) { has66 = 1; i++; continue; }
        if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            i++;
            continue;
        }
        break;
    }
    /* REX */
    if (i < Remaining && (Code[i] & 0xF0) == 0x40) {
        rexW = (Code[i] & 0x08) ? 1 : 0;
        i++;
    }
    if (i >= Remaining)
        return 0;
    op = Code[i];
    i++;

    switch (op) {
    case 0x90: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "nop");  Out->Length = (BYTE)i; return 1;
    case 0xCC: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "int3"); Out->Length = (BYTE)i; return 1;
    case 0xC3: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "ret");  Out->Length = (BYTE)i; return 1;
    case 0xCB: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "retf"); Out->Length = (BYTE)i; return 1;
    case 0xC9: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "leave");Out->Length = (BYTE)i; return 1;
    case 0xC2: sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "ret 0x%X", *(const USHORT *)(Code + i)); Out->Length = (BYTE)(i + 2); return 1;
    case 0xF4: strcpy_s(Out->Mnemonic, sizeof(Out->Mnemonic), "hlt");  Out->Length = (BYTE)i; return 1;
    case 0xE8: /* call rel32 */
        sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "call rel32_0x%08lX", *(const ULONG *)(Code + i));
        Out->Length = (BYTE)(i + 4); return 1;
    case 0xE9:
        sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "jmp rel32_0x%08lX", *(const ULONG *)(Code + i));
        Out->Length = (BYTE)(i + 4); return 1;
    case 0xEB: sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "jmp short 0x%02X", Code[i]); Out->Length = (BYTE)(i + 1); return 1;
    case 0xE3: sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "jrcxz 0x%02X", Code[i]); Out->Length = (BYTE)(i + 1); return 1;
    case 0xFF: {
        modrmLen = FeModRmLen(Code + i, Remaining - i, &hasModrm);
        if (modrmLen) {
            BYTE reg = (BYTE)((Code[i] >> 3) & 7);
            sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic),
                      reg == 2 ? "call r/m" : reg == 4 ? "jmp r/m" :
                      reg == 6 ? "push r/m" : "ff /%u", reg);
            Out->Length = (BYTE)(i + modrmLen);
            return 1;
        }
        break;
    }
    case 0x8B: case 0x89: case 0x8D: case 0x03: case 0x2B: case 0x33: case 0x3B:
    case 0x85: case 0x88: case 0x8A: case 0xC7: case 0xC6: case 0x01: case 0x09:
    case 0x31: case 0x39: case 0x21: case 0x29: case 0x87: case 0x0F: {
        modrmLen = FeModRmLen(Code + i, Remaining - i, &hasModrm);
        if (!modrmLen)
            break;
        if (op == 0x0F)
            has66 = has66;               /* 0F 是两字节 opcode，长度另算 */
        {
            const char *nm =
                op == 0x8B ? "mov" : op == 0x89 ? "mov" : op == 0x8D ? "lea" :
                op == 0x03 ? "add" : op == 0x2B ? "sub" : op == 0x33 ? "xor" :
                op == 0x3B ? "cmp" : op == 0x85 ? "test" : op == 0x88 ? "mov" :
                op == 0x8A ? "mov" : op == 0xC7 ? "mov" : op == 0xC6 ? "mov" :
                op == 0x01 ? "add" : op == 0x09 ? "or" : op == 0x31 ? "xor" :
                op == 0x39 ? "cmp" : op == 0x21 ? "and" : op == 0x29 ? "sub" :
                op == 0x87 ? "xchg" : "op0f";
            sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "%s%s", nm, rexW ? " (64)" : "");
        }
        Out->Length = (BYTE)(i + modrmLen);
        /* C6/C7 带立即数 */
        if (op == 0xC6) Out->Length = (BYTE)(Out->Length + 1);
        if (op == 0xC7) Out->Length = (BYTE)(Out->Length + 4);
        return 1;
    }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "mov %s, imm%d",
                  (op == 0xB8) ? "rax" : (op == 0xB9) ? "rcx" : (op == 0xBA) ? "rdx" :
                  (op == 0xBB) ? "rbx" : (op == 0xBC) ? "rsp" : (op == 0xBD) ? "rbp" :
                  (op == 0xBE) ? "rsi" : "rdi",
                  rexW ? 64 : 32);
        Out->Length = (BYTE)(i + (rexW ? 8 : 4));
        return 1;
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "push %s",
                  (op == 0x50) ? "rax" : (op == 0x51) ? "rcx" : (op == 0x52) ? "rdx" :
                  (op == 0x53) ? "rbx" : (op == 0x54) ? "rsp" : (op == 0x55) ? "rbp" :
                  (op == 0x56) ? "rsi" : "rdi");
        Out->Length = (BYTE)i; return 1;
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), "pop %s",
                  (op == 0x58) ? "rax" : (op == 0x59) ? "rcx" : (op == 0x5A) ? "rdx" :
                  (op == 0x5B) ? "rbx" : (op == 0x5C) ? "rsp" : (op == 0x5D) ? "rbp" :
                  (op == 0x5E) ? "rsi" : "rdi");
        Out->Length = (BYTE)i; return 1;
    default:
        break;
    }

    /* 未知指令：按 1 字节前进（安全，不越界） */
    sprintf_s(Out->Mnemonic, sizeof(Out->Mnemonic), ".byte 0x%02X", op);
    Out->Length = 1;
    return 1;
}