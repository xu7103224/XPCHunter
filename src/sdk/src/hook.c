/* ============================================================================
 * hook.c —— SSDT / Ring0 Hook 查询、Ring3 Hook 扫描
 *
 * 0x117 的输出布局（实机解码 + 原始反汇编双向确认）：
 *   +0x00 DWORD Build
 *   +0x04 DWORD Count1     第一张表条目数
 *   +0x08 DWORD Count2     第二张表条目数
 *   +0x0C DWORD 保留
 *   +0x10 起，每条 40 字节：
 *     +0x00 BYTE  FlagAddr    表项当前值 != 磁盘原始值
 *     +0x01 BYTE  FlagBytes   内存前 16 字节 != 磁盘 16 字节
 *     +0x04 DWORD Index       表内索引
 *     +0x08 QWORD Current     当前地址
 *     +0x10 QWORD Original    磁盘原始地址
 *     +0x18 BYTE[16] 磁盘原始指令
 *
 * 缓冲要求：40 * (Count1 - 1) + 56，Count1=454 时约 18KB。给小了返回 0。
 * ==========================================================================*/
#include "XpchSdk_internal.h"
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>

#define RING0_HEADER_SIZE    0x10u
#define RING0_ENTRY_SIZE     40u
#define RING0_MAX_ENTRIES    4096u
#define RING0_OUT_BUF        0x20000u

/* 反汇编前 16 字节，产出助记符串（简化版：只按常见指令长度切分） */
static void DecodeDisasm(const BYTE *Bytes, char *Out, ULONG OutChars)
{
    ULONG pos = 0, n = 0, o = 0;

    if (!Out || !OutChars)
        return;
    Out[0] = 0;

    while (pos < 16 && n < 4 && o + 16 < OutChars) {
        BYTE b = Bytes[pos];
        ULONG len = 1;
        const char *mn = "?";

        /* 只识别最常见的几种前缀/指令，够做展示用 */
        if (b == 0x48 || b == 0x4C || b == 0x40) {
            /* REX 前缀，真正指令在后面 */
            if (pos + 1 < 16) {
                BYTE op = Bytes[pos + 1];
                if (op == 0x89 || op == 0x8B)      { len = 3; mn = "mov"; }
                else if (op == 0x8D)               { len = 3; mn = "lea"; }
                else if (op == 0x39 || op == 0x3B) { len = 3; mn = "cmp"; }
                else if (op == 0xFF)               { len = 3; mn = "call/jmp"; }
                else if (op == 0x85)               { len = 3; mn = "test"; }
                else if (op == 0x33 || op == 0x31) { len = 3; mn = "xor"; }
                else if (op == 0x83)               { len = 4; mn = "cmp/sub"; }
                else if (op == 0xE9)               { len = 6; mn = "jmp"; }
                else if (op == 0x8F)               { len = 2; mn = "pop"; }
                else                               { len = 2; mn = "?"; }
            }
        } else if (b == 0xE9) { len = 5;  mn = "jmp"; }
        else if (b == 0xEB)   { len = 2;  mn = "jmp short"; }
        else if (b == 0xC3)   { len = 1;  mn = "ret"; }
        else if (b == 0xCC)   { len = 1;  mn = "int3"; }
        else if (b == 0x90)   { len = 1;  mn = "nop"; }
        else if (b == 0xFF)   { len = 3;  mn = "call/jmp"; }
        else if (b == 0x50 || (b >= 0x58 && b <= 0x5F)) { len = 1; mn = "push/pop"; }
        else if (b == 0xE8)   { len = 5;  mn = "call"; }
        else if (b == 0x8B || b == 0x89) { len = 3; mn = "mov"; }
        else if (b == 0x8D)   { len = 3;  mn = "lea"; }
        else if (b == 0x33)   { len = 3;  mn = "xor"; }
        else if (b == 0xF6 || b == 0xF7) { len = 3; mn = "test"; }
        else if (b == 0x74 || b == 0x75) { len = 2; mn = "jcc"; }
        else if (b == 0x0F)   { len = 4;  mn = "jcc/setcc"; }

        if (n)
            o += (ULONG)sprintf_s(Out + o, OutChars - o, "; ");
        o += (ULONG)sprintf_s(Out + o, OutChars - o, "%s", mn);
        pos += len;
        n++;
    }

    if (n == 0)
        strcpy_s(Out, OutChars, "(undecoded)");
}

XPCH_STATUS XpchEnumSsdtHooks(XPCH_SESSION *Session,
                              XPCH_SSDT_ENTRY **Entries, ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *Buf;
    XPCH_STATUS St;
    ULONG Build, Count1, Count2, Total, i, off;
    XPCH_SSDT_ENTRY *Items;

    if (!Session || !Entries || !Count)
        return XPCH_E_INVALID_ARG;
    *Entries = NULL;
    *Count = 0;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    Buf = (BYTE *)XpchAlloc(RING0_OUT_BUF);
    if (!Buf)
        return XPCH_E_NO_MEMORY;

    St = XpchInvokeRaw(Session, CMD_ENUM_HOOK_INFO, NULL, 0,
                       Buf, RING0_OUT_BUF);
    if (St != XPCH_OK) {
        XpchFreeInternal(Buf);
        return St;
    }

    Build  = *(const ULONG *)(Buf + 0x00);
    Count1 = *(const ULONG *)(Buf + 0x04);
    Count2 = *(const ULONG *)(Buf + 0x08);

    if (Count1 == 0 && Count2 == 0) {
        XpchFreeInternal(Buf);
        return XPCH_E_NO_DATA;
    }

    Total = Count1 + Count2;
    if (Total > RING0_MAX_ENTRIES)
        Total = RING0_MAX_ENTRIES;
    if (RING0_HEADER_SIZE + (ULONG64)RING0_ENTRY_SIZE * Total > RING0_OUT_BUF)
        Total = (RING0_OUT_BUF - RING0_HEADER_SIZE) / RING0_ENTRY_SIZE;
    if (Total == 0) {
        XpchFreeInternal(Buf);
        return XPCH_E_BAD_RESPONSE;
    }

    Items = (XPCH_SSDT_ENTRY *)XpchAlloc(
                (SIZE_T)Total * sizeof(XPCH_SSDT_ENTRY));
    if (!Items) {
        XpchFreeInternal(Buf);
        return XPCH_E_NO_MEMORY;
    }

    off = RING0_HEADER_SIZE;
    for (i = 0; i < Total; i++, off += RING0_ENTRY_SIZE) {
        XPCH_SSDT_ENTRY *E = &Items[i];
        E->TableIndex    = (i < Count1) ? 1 : 2;
        E->AddressPatched = Buf[off + 0x00] ? TRUE : FALSE;
        E->BytesPatched   = Buf[off + 0x01] ? TRUE : FALSE;
        E->Index         = *(const ULONG *)(Buf + off + 0x04);
        E->Current       = *(const ULONG64 *)(Buf + off + 0x08);
        E->Original      = *(const ULONG64 *)(Buf + off + 0x10);
        memcpy(E->OriginalBytes, Buf + off + 0x18, 16);
        DecodeDisasm(E->OriginalBytes, E->Disasm, XPCH_HOOK_DISASM_CHARS);
    }

    XpchFreeInternal(Buf);
    *Entries = Items;
    *Count = Total;
    return XPCH_OK;
}

/* ---------------------------------------------------------------------------
 * Ring3 Hook 扫描
 *
 * 简化实现：只做 IAT 劫持检测（跨模块指向）。inline patch 需要读磁盘模块
 * 做逐字节比对，代价高且误报多，SDK 里不默认开启。
 * -------------------------------------------------------------------------*/
XPCH_STATUS XpchScanProcessHooks(XPCH_SESSION *Session, ULONG Pid,
                                 XPCH_RING3_HOOK **Hooks, ULONG *Count)
{
    XPCH_MODULE_INFO *Mods = NULL;
    ULONG ModCount = 0, i, n = 0, Cap = 64;
    XPCH_RING3_HOOK *Out;
    HANDLE Proc;
    XPCH_STATUS St;

    UNREFERENCED_PARAMETER(Session);

    if (!Hooks || !Count)
        return XPCH_E_INVALID_ARG;
    *Hooks = NULL;
    *Count = 0;

    St = XpchEnumModules(Pid, &Mods, &ModCount);
    if (St != XPCH_OK)
        return St;

    Proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (!Proc) {
        XpchFreeInternal(Mods);
        return XPCH_E_ACCESS_DENIED;
    }

    Out = (XPCH_RING3_HOOK *)XpchAlloc(Cap * sizeof(XPCH_RING3_HOOK));
    if (!Out) {
        CloseHandle(Proc);
        XpchFreeInternal(Mods);
        return XPCH_E_NO_MEMORY;
    }

    /* 对每个模块扫导入表：IAT 表项指向的地址若落在所有模块之外，
       或者落在「不是该导入名所属模块」的范围内，视为可疑。 */
    for (i = 0; i < ModCount; i++) {
        IMAGE_DOS_HEADER Dos;
        IMAGE_NT_HEADERS Nt;
        IMAGE_DATA_DIRECTORY ImpDir;
        SIZE_T Got = 0;
        ULONG k;

        if (!ReadProcessMemory(Proc, (LPCVOID)(ULONG_PTR)Mods[i].Base,
                               &Dos, sizeof(Dos), &Got))
            continue;
        if (Dos.e_magic != IMAGE_DOS_SIGNATURE)
            continue;
        if (!ReadProcessMemory(Proc,
                               (LPCVOID)(ULONG_PTR)(Mods[i].Base + Dos.e_lfanew),
                               &Nt, sizeof(Nt), &Got))
            continue;
        if (Nt.Signature != IMAGE_NT_SIGNATURE)
            continue;
        if (Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            continue;

        ImpDir = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!ImpDir.VirtualAddress || !ImpDir.Size)
            continue;

        for (k = 0; k < ImpDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); k++) {
            IMAGE_IMPORT_DESCRIPTOR Desc;
            ULONG64 DescAddr = Mods[i].Base + ImpDir.VirtualAddress
                             + (ULONG64)k * sizeof(Desc);

            if (!ReadProcessMemory(Proc, (LPCVOID)(ULONG_PTR)DescAddr,
                                   &Desc, sizeof(Desc), &Got))
                break;
            if (!Desc.Name)
                break;

            /* 扫该模块的 IAT 表项 */
            if (Desc.FirstThunk) {
                ULONG t;
                for (t = 0; t < 4096; t++) {
                    ULONG64 SlotAddr = Mods[i].Base + Desc.FirstThunk
                                     + (ULONG64)t * 8;
                    ULONG64 Target = 0;
                    BOOL InAnyModule = FALSE;
                    ULONG q;

                    if (!ReadProcessMemory(Proc, (LPCVOID)(ULONG_PTR)SlotAddr,
                                           &Target, sizeof(Target), &Got))
                        break;
                    if (!Target)
                        break;

                    for (q = 0; q < ModCount; q++) {
                        if (Target >= Mods[q].Base
                            && Target < Mods[q].Base + Mods[q].Size) {
                            InAnyModule = TRUE;
                            break;
                        }
                    }
                    /* 指向模块外 → 可能是外部注入；指向别的模块 → 正常跨模块导入。
                       SDK 这里只报「完全在模块之外」这种明确可疑的情况。 */
                    if (!InAnyModule) {
                        if (n >= Cap) {
                            XPCH_RING3_HOOK *Grown = (XPCH_RING3_HOOK *)XpchAlloc(
                                    (SIZE_T)(Cap * 2) * sizeof(XPCH_RING3_HOOK));
                            if (!Grown)
                                break;
                            memcpy(Grown, Out, (SIZE_T)n * sizeof(XPCH_RING3_HOOK));
                            XpchFreeInternal(Out);
                            Out = Grown;
                            Cap *= 2;
                        }
                        Out[n].IatAddress = SlotAddr;
                        Out[n].Target = Target;
                        /* Mods[i].Name 本身就是 WCHAR，直接拷贝 */
                        lstrcpynW(Out[n].Owner, Mods[i].Name, 64);
                        Out[n].TargetModule[0] = 0;
                        n++;
                    }
                }
            }
        }
    }

    CloseHandle(Proc);
    XpchFreeInternal(Mods);

    if (n == 0) {
        XpchFreeInternal(Out);
        return XPCH_OK;          /* 无 hook 不是错误，Count=0 */
    }

    *Hooks = Out;
    *Count = n;
    return XPCH_OK;
}

/* ============================================================
 * 签名校验
 * ============================================================*/
XPCH_STATUS XpchVerifyFileSignature(const WCHAR *Path,
                                    XPCH_SIGNATURE_STATE *State)
{
    WINTRUST_FILE_INFO FileInfo;
    WINTRUST_DATA WtData;
    GUID Action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG St;
    DWORD Attr;

    if (!Path || !State)
        return XPCH_E_INVALID_ARG;
    *State = XPCH_SIG_UNKNOWN;

    Attr = GetFileAttributesW(Path);
    if (Attr == INVALID_FILE_ATTRIBUTES)
        return XPCH_E_NOT_FOUND;

    ZeroMemory(&FileInfo, sizeof(FileInfo));
    FileInfo.cbStruct = sizeof(FileInfo);
    FileInfo.pcwszFilePath = Path;

    ZeroMemory(&WtData, sizeof(WtData));
    WtData.cbStruct = sizeof(WtData);
    WtData.dwUIChoice = WTD_UI_NONE;
    WtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WtData.dwUnionChoice = WTD_CHOICE_FILE;
    WtData.pFile = &FileInfo;
    WtData.dwStateAction = WTD_STATEACTION_VERIFY;
    WtData.dwProvFlags = WTD_REVOKE_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
                       | WTD_DISABLE_MD2_MD4;

    St = WinVerifyTrust(NULL, &Action, &WtData);

    WtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &Action, &WtData);

    if (St == ERROR_SUCCESS) {
        *State = XPCH_SIG_VALID;
    } else if ((DWORD)St == TRUST_E_NOSIGNATURE) {
        *State = XPCH_SIG_UNSIGNED;
    } else if ((DWORD)St == TRUST_E_SUBJECT_FORM_UNKNOWN
               || (DWORD)St == TRUST_E_PROVIDER_UNKNOWN) {
        *State = XPCH_SIG_UNSIGNED;
    } else {
        *State = XPCH_SIG_INVALID;
    }
    return XPCH_OK;
}

/* ============================================================
 * 读进程内存（0x20）
 *
 * 0x20 CmdReadProcessMemory 的入参是 8 字节地址，输出写回固定位置。
 * 这个命令的语义是「读一次、结果由驱动决定写哪」，不适合任意长度读取。
 * SDK 这里改用 ReadProcessMemory 实现（可靠且能读任意长度），
 * 驱动版留给需要绕过用户态保护的高级场景。
 * ============================================================*/
XPCH_STATUS XpchReadProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                  ULONG64 Address, ULONG Size,
                                  BYTE **Buffer, ULONG *Read)
{
    HANDLE Proc;
    BYTE *Buf;
    SIZE_T Got = 0;
    BOOL Ok;

    UNREFERENCED_PARAMETER(Session);

    if (!Buffer || !Read)
        return XPCH_E_INVALID_ARG;
    *Buffer = NULL;
    *Read = 0;

    if (!Pid || !Address || !Size)
        return XPCH_E_INVALID_ARG;

    Proc = OpenProcess(PROCESS_VM_READ, FALSE, Pid);
    if (!Proc)
        return XPCH_E_ACCESS_DENIED;

    Buf = (BYTE *)XpchAlloc(Size);
    if (!Buf) {
        CloseHandle(Proc);
        return XPCH_E_NO_MEMORY;
    }

    Ok = ReadProcessMemory(Proc, (LPCVOID)(ULONG_PTR)Address,
                           Buf, Size, &Got);
    CloseHandle(Proc);

    if (!Ok && Got == 0) {
        XpchFreeInternal(Buf);
        return XPCH_E_ACCESS_DENIED;
    }

    *Buffer = Buf;
    *Read = (ULONG)Got;
    return XPCH_OK;
}