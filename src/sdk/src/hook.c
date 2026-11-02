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
/* 远程读：经 0x023 把目标进程内存拷到本地固定缓冲。返回实际拷贝字节数。 */
static ULONG XpRmRead(XPCH_SESSION *Session, ULONG Pid,
                      ULONG64 Address, void *Local, ULONG Size)
{
    BYTE *Buf = NULL;
    ULONG Got = 0;

    if (XpchReadProcessMemory(Session, Pid, Address, Size, &Buf, &Got) != XPCH_OK)
        return 0;
    if (Got > Size)
        Got = Size;
    memcpy(Local, Buf, Got);
    XpchFree(Buf);
    return Got;
}

XPCH_STATUS XpchScanProcessHooks(XPCH_SESSION *Session, ULONG Pid,
                                 XPCH_RING3_HOOK **Hooks, ULONG *Count)
{
    XPCH_MODULE_INFO *Mods = NULL;
    ULONG ModCount = 0, i, n = 0, Cap = 64;
    XPCH_RING3_HOOK *Out;
    XPCH_STATUS St;

    if (!Session || !Hooks || !Count)
        return XPCH_E_INVALID_ARG;
    *Hooks = NULL;
    *Count = 0;

    /* 全内核数据链：模块列表走 0x09B，远程内存读走 0x023。
       不使用 OpenProcess / ReadProcessMemory。 */
    St = XpchEnumModules(Session, Pid, &Mods, &ModCount);
    if (St != XPCH_OK)
        return St;

    Out = (XPCH_RING3_HOOK *)XpchAlloc(Cap * sizeof(XPCH_RING3_HOOK));
    if (!Out) {
        XpchFreeInternal(Mods);
        return XPCH_E_NO_MEMORY;
    }

    /* 远程读辅助：经 0x023 一次拷回 Size 字节到本地缓冲，成功返回实际字节数 */
#define XP_RM_READ(Addr, BufLocal, Sz) \
    XpRmRead(Session, Pid, (ULONG64)(ULONG_PTR)(Addr), (BufLocal), (ULONG)(Sz))

    for (i = 0; i < ModCount; i++) {
        BYTE Hdr[0x1000];
        IMAGE_DOS_HEADER Dos;
        IMAGE_NT_HEADERS64 Nt;
        IMAGE_DATA_DIRECTORY ImpDir;
        ULONG k;

        if (Mods[i].Size < sizeof(IMAGE_DOS_HEADER))
            continue;
        if (XP_RM_READ(Mods[i].Base, Hdr, sizeof(Hdr)) == 0)
            continue;

        memcpy(&Dos, Hdr, sizeof(Dos));
        if (Dos.e_magic != IMAGE_DOS_SIGNATURE)
            continue;
        if ((ULONG)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(Hdr))
            continue;
        memcpy(&Nt, Hdr + Dos.e_lfanew, sizeof(Nt));
        if (Nt.Signature != IMAGE_NT_SIGNATURE)
            continue;
        if (Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            continue;

        ImpDir = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!ImpDir.VirtualAddress || !ImpDir.Size)
            continue;

        /* 逐个导入描述符：远程读描述符（每项 20 字节） */
        for (k = 0; k < ImpDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); k++) {
            IMAGE_IMPORT_DESCRIPTOR Desc;
            ULONG64 DescAddr = Mods[i].Base + ImpDir.VirtualAddress
                             + (ULONG64)k * sizeof(Desc);
            ULONG t;
            BYTE *IatBuf = NULL;
            ULONG IatGot = 0;
            ULONG IatEntries;

            if (XP_RM_READ(DescAddr, &Desc, sizeof(Desc)) == 0)
                break;
            if (!Desc.Name)
                break;

            if (!Desc.FirstThunk)
                continue;

            /* IAT 数组整块远程读（最多 4096 项 = 32KB；读多少算多少） */
            {
                ULONG Want = 4096 * 8;
                XpchReadProcessMemory(Session, Pid,
                        Mods[i].Base + Desc.FirstThunk,
                        Want, &IatBuf, &IatGot);
            }
            if (!IatBuf || IatGot < 8)
                continue;

            IatEntries = IatGot / 8;
            for (t = 0; t < IatEntries; t++) {
                ULONG64 Target;
                BOOLEAN InAnyModule = FALSE;
                ULONG q;

                memcpy(&Target, IatBuf + (SIZE_T)t * 8, 8);
                if (!Target)
                    break;

                for (q = 0; q < ModCount; q++) {
                    if (Target >= Mods[q].Base
                        && Target < Mods[q].Base + Mods[q].Size) {
                        InAnyModule = TRUE;
                        break;
                    }
                }
                if (!InAnyModule) {
                    XPCH_RING3_HOOK *Grown;
                    if (n >= Cap) {
                        Grown = (XPCH_RING3_HOOK *)XpchAlloc(
                                (SIZE_T)(Cap * 2) * sizeof(XPCH_RING3_HOOK));
                        if (!Grown)
                            break;
                        memcpy(Grown, Out, (SIZE_T)n * sizeof(XPCH_RING3_HOOK));
                        XpchFreeInternal(Out);
                        Out = Grown;
                        Cap *= 2;
                    }
                    Out[n].IatAddress = Mods[i].Base + Desc.FirstThunk
                                      + (ULONG64)t * 8;
                    Out[n].Target = Target;
                    lstrcpynW(Out[n].Owner, Mods[i].Name, 64);
                    Out[n].TargetModule[0] = 0;
                    n++;
                }
            }
            if (IatBuf)
                XpchFreeInternal(IatBuf);
        }
    }

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
