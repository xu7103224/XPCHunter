/* ============================================================================
 * inject.c —— 手工映射 PE 到目标进程（manual map）
 *
 * 【架构】映射逻辑全部在本文件（三环 SDK）完成，只调用驱动的
 * 读写/原语命令，不使用任何三环跨进程 API：
 *   - 目标内存分配/释放/远程线程          —— 0x09B 子命令
 *   - 映像内容写入（节区/重定位/IAT）     —— 0x081 写
 *   - 导出表解析（目标进程模块导出）      —— 0x023 读
 *   - 目标模块清单（找依赖的基址）        —— SDK 侧 PEB 遍历
 *
 * 流程：读文件 → 解析 PE → 本地按虚拟布局展开节区 → 远程分配 →
 *       本地应用重定位 → 本地解析导入（读目标导出表） →
 *       整块分片写回 → 入口引导桩 → 远程线程调 DllMain。
 *
 * 已知限制（文档化）：
 *   - 仅 PE32+（x64 DLL）；依赖的 DLL 必须已在目标进程加载
 *   - 不处理 TLS 回调；映射结果不进 PEB Ldr 链
 * ==========================================================================*/
#include "XpchSdk_internal.h"
#include <stdio.h>

/* 分步追踪：设 XPCH_INJ_TRACE=1 时输出到 stderr */
static int XpInjTrace(void)
{
    static int On = -1;
    if (On < 0) {
        char Buf[8];
        On = (GetEnvironmentVariableA("XPCH_INJ_TRACE", Buf, sizeof(Buf)) && Buf[0] == '1');
    }
    return On;
}
#define XP_INJ_STEP(n, st) do { if (XpInjTrace()) fprintf(stderr, "[inj] step %d -> %d\n", (n), (int)(st)); } while (0)

/* ---- 0x09B 子命令号（与驱动 CmdXpchProcessOp 对应）---- */
#define XPCH_PROCOP_ALLOC        0u
#define XPCH_PROCOP_FREE         1u
#define XPCH_PROCOP_PROTECT      2u
#define XPCH_PROCOP_CREATETHREAD 3u

#define XPCH_INJ_WRITE_CHUNK     0x8000u        /* 单次 0x081 写 32KB */
#define XPCH_INJ_MAX_IMAGE       0x10000000u    /* 映像上限 256MB */
#define XPCH_INJ_MAX_SECTIONS    96u
#define XPCH_INJ_MAX_IMPORTS     0x400u
#define XPCH_INJ_MAX_THUNKS      0x4000u
#define XPCH_INJ_MAX_READ        0x100000u      /* 单次远程读 1MB */
#define XPCH_INJ_FORWARD_DEPTH   8u             /* 导出转发链深上限 */
#define XPCH_INJ_STUB_OFF        0x40u          /* 引导桩落在 DOS stub 区 */

/* winnt.h 这两个结构用 union 成员名，本地重定义更直观 */
#pragma pack(push, 4)
typedef struct _XPCH_INJ_BASE_RELOC {
    ULONG PageRva;
    ULONG BlockSize;
} XPCH_INJ_BASE_RELOC;

typedef struct _XPCH_INJ_IMPORT_DESC {
    ULONG OriginalFirstThunk;
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} XPCH_INJ_IMPORT_DESC;
#pragma pack(pop)

/* 进程原语封装：{u64 Pid; u32 Op; u32 Pad; u64 A1,A2,A3} -> {u64 Value} */
static XPCH_STATUS XpInjProcessOp(XPCH_SESSION *Session, ULONG Pid, ULONG Op,
                                  ULONG64 A1, ULONG64 A2, ULONG64 A3,
                                  ULONG64 *Value)
{
#pragma pack(push, 1)
    struct {
        ULONG64 Pid;
        ULONG   Op;
        ULONG   Pad;
        ULONG64 A1;
        ULONG64 A2;
        ULONG64 A3;
    } In;
#pragma pack(pop)
    ULONG64 Out = 0;
    XPCH_STATUS St;

    In.Pid = (ULONG64)Pid;
    In.Op  = Op;
    In.Pad = 0;
    In.A1  = A1;
    In.A2  = A2;
    In.A3  = A3;

    St = XpchInvokeRaw(Session, CMD_X_PROCESS_OP, &In, sizeof(In),
                       &Out, sizeof(Out));
    if (Value)
        *Value = Out;
    if (XpInjTrace())
        fprintf(stderr, "[inj] procop op=%lu st=%d val=%llx\n",
                (unsigned long)Op, (int)St, (unsigned long long)Out);
    return St;
}

/* 远程读辅助：一次读 Size 字节到调用方缓冲（驱动保证全有或全无） */
static XPCH_STATUS XpInjRead(XPCH_SESSION *Session, ULONG Pid, ULONG64 Addr,
                             void *Out, ULONG Size)
{
    XPCH_STATUS St;
    BYTE *Buf = NULL;
    ULONG Got = 0;

    if (!Size || Size > XPCH_INJ_MAX_READ)
        return XPCH_E_INVALID_ARG;
    St = XpchReadProcessMemory(Session, Pid, Addr, Size, &Buf, &Got);
    if (St != XPCH_OK)
        return St;
    if (Got != Size) {
        XpchFreeInternal(Buf);
        return XPCH_E_BAD_RESPONSE;
    }
    memcpy(Out, Buf, Size);
    XpchFreeInternal(Buf);
    return XPCH_OK;
}

/* 远程写辅助：分块写，单块 32KB */
static XPCH_STATUS XpInjWrite(XPCH_SESSION *Session, ULONG Pid, ULONG64 Dst,
                              const BYTE *Src, ULONG Size)
{
    ULONG Done = 0;

    while (Done < Size) {
        ULONG Chunk = Size - Done;
        XPCH_STATUS St;
        if (Chunk > XPCH_INJ_WRITE_CHUNK)
            Chunk = XPCH_INJ_WRITE_CHUNK;
        St = XpchWriteProcessMemory(Session, Pid, Dst + Done,
                                    Src + Done, Chunk);
        if (St != XPCH_OK)
            return St;
        Done += Chunk;
    }
    return XPCH_OK;
}

/* ==================================================================
 * 导出解析
 * ==================================================================*/

/* 在目标模块清单里按映像名找模块（不区分大小写） */
static XPCH_STATUS XpInjFindModule(XPCH_SESSION *Session, ULONG Pid,
                                   const WCHAR *DllName,
                                   XPCH_MODULE_INFO **ModsOut, ULONG *CountOut,
                                   ULONG64 *Base, ULONG64 *Size)
{
    XPCH_MODULE_INFO *Mods = NULL;
    ULONG N = 0, i;
    XPCH_STATUS St;

    *Base = 0;
    *Size = 0;
    if (ModsOut && CountOut && *ModsOut) {
        Mods = *ModsOut;
        N = *CountOut;
    } else {
        St = XpchEnumModules(Session, Pid, &Mods, &N);
        if (St != XPCH_OK)
            return St;
        if (ModsOut && CountOut) {
            *ModsOut = Mods;
            *CountOut = N;
        } else {
            /* 调用方无缓存：用完即释放（本函数是叶子，直接返回前释放） */
            for (i = 0; i < N; i++)
                if (_wcsicmp(Mods[i].Name, DllName) == 0) {
                    *Base = Mods[i].Base;
                    *Size = Mods[i].Size;
                    XpchFreeInternal(Mods);
                    return XPCH_OK;
                }
            XpchFreeInternal(Mods);
            return XPCH_E_NOT_FOUND;
        }
    }

    for (i = 0; i < N; i++) {
        if (_wcsicmp(Mods[i].Name, DllName) == 0) {
            *Base = Mods[i].Base;
            *Size = Mods[i].Size;
            return XPCH_OK;
        }
    }
    return XPCH_E_NOT_FOUND;
}

/* 读目标模块的导出目录并解析符号；支持导出转发（递归，链深受限） */
static XPCH_STATUS XpInjResolveExport(XPCH_SESSION *Session, ULONG Pid,
                                      XPCH_MODULE_INFO **ModsCache,
                                      ULONG *ModsCount,
                                      ULONG64 ModBase, const char *FuncName,
                                      ULONG Ordinal, ULONG Depth,
                                      ULONG64 *OutAddr)
{
    BYTE Nh[0x400];
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS64 Nt;
    IMAGE_EXPORT_DIRECTORY Exp;
    ULONG64 ExpDirRva, ExpDirSize;
    XPCH_STATUS St;

    *OutAddr = 0;
    if (Depth > XPCH_INJ_FORWARD_DEPTH)
        return XPCH_E_NOT_FOUND;

    St = XpInjRead(Session, Pid, ModBase, Nh, sizeof(Nh));
    if (St != XPCH_OK)
        return St;
    memcpy(&Dos, Nh, sizeof(Dos));
    if (Dos.e_magic != IMAGE_DOS_SIGNATURE)
        return XPCH_E_BAD_RESPONSE;
    if ((ULONG)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(Nh))
        return XPCH_E_BAD_RESPONSE;
    memcpy(&Nt, Nh + Dos.e_lfanew, sizeof(Nt));
    if (Nt.Signature != IMAGE_NT_SIGNATURE ||
        Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return XPCH_E_BAD_RESPONSE;

    ExpDirRva  = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExpDirSize = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!ExpDirRva || !ExpDirSize)
        return XPCH_E_NOT_FOUND;

    St = XpInjRead(Session, Pid, ModBase + ExpDirRva, &Exp, sizeof(Exp));
    if (St != XPCH_OK)
        return St;

    {
        ULONG64 FuncRva = 0;

        if (FuncName == NULL) {
            /* 按序号：Ordinal 是相对 Exp.Base 的 */
            ULONG64 Idx = (ULONG64)Ordinal - Exp.Base;
            ULONG32 Fn;
            if (Idx >= Exp.NumberOfFunctions)
                return XPCH_E_NOT_FOUND;
            St = XpInjRead(Session, Pid,
                           ModBase + Exp.AddressOfFunctions + Idx * 4,
                           &Fn, 4);
            if (St != XPCH_OK)
                return St;
            FuncRva = Fn;
        } else {
            /* 按名字：整块读名字 RVA 数组 + 序号数组 + 名字字符串区 */
            ULONG N = Exp.NumberOfNames;
            ULONG32 *Names = NULL;
            USHORT *Ords = NULL;
            BYTE *Blob = NULL;
            ULONG BlobLen, MinRva = 0xFFFFFFFFu, MaxRva = 0;
            ULONG i;
            LONG Hit = -1;

            if (!N || N > XPCH_INJ_MAX_THUNKS)
                return XPCH_E_NOT_FOUND;

            Names = (ULONG32 *)XpchAlloc((SIZE_T)N * 4);
            Ords = (USHORT *)XpchAlloc((SIZE_T)N * 2);
            if (!Names || !Ords) {
                XpchFreeInternal(Names);
                XpchFreeInternal(Ords);
                return XPCH_E_NO_MEMORY;
            }
            St = XpInjRead(Session, Pid, ModBase + Exp.AddressOfNames,
                           Names, N * 4);
            if (St == XPCH_OK)
                St = XpInjRead(Session, Pid, ModBase + Exp.AddressOfNameOrdinals,
                               Ords, N * 2);
            if (St != XPCH_OK) {
                XpchFreeInternal(Names);
                XpchFreeInternal(Ords);
                return St;
            }
            for (i = 0; i < N; i++) {
                if (Names[i] < MinRva) MinRva = Names[i];
                if (Names[i] > MaxRva) MaxRva = Names[i];
            }

            Hit = -1;
            if (MaxRva >= MinRva &&
                (SIZE_T)(MaxRva - MinRva) + 128 <= XPCH_INJ_MAX_READ) {
                /* 名字字符串区是连续的，一次读出后本地匹配 */
                BlobLen = (MaxRva - MinRva) + 128;
                Blob = (BYTE *)XpchAlloc(BlobLen);
                if (Blob) {
                    St = XpInjRead(Session, Pid, ModBase + MinRva,
                                   Blob, BlobLen);
                    if (St == XPCH_OK) {
                        for (i = 0; i < N; i++) {
                            SIZE_T Off = Names[i] - MinRva;
                            const char *P;
                            if (Off >= BlobLen)
                                continue;
                            P = (const char *)Blob + Off;
                            /* 必须在缓冲区内以 NUL 结束 */
                            if (!memchr(P, 0, BlobLen - Off))
                                continue;
                            if (_stricmp(P, FuncName) == 0) {
                                Hit = (LONG)i;
                                break;
                            }
                        }
                    }
                    XpchFreeInternal(Blob);
                    Blob = NULL;
                }
            }
            if (Hit < 0) {
                /* 兜底：逐个读名字串（慢路径） */
                for (i = 0; i < N && Hit < 0; i++) {
                    char NameBuf[128];
                    St = XpInjRead(Session, Pid, ModBase + Names[i],
                                   NameBuf, sizeof(NameBuf) - 1);
                    if (St != XPCH_OK)
                        break;
                    NameBuf[sizeof(NameBuf) - 1] = 0;
                    if (_stricmp(NameBuf, FuncName) == 0)
                        Hit = (LONG)i;
                }
            }
            if (Hit < 0) {
                XpchFreeInternal(Names);
                XpchFreeInternal(Ords);
                return XPCH_E_NOT_FOUND;
            }
            {
                ULONG32 Fn;
                St = XpInjRead(Session, Pid,
                               ModBase + Exp.AddressOfFunctions
                               + (ULONG64)Ords[Hit] * 4,
                               &Fn, 4);
                XpchFreeInternal(Names);
                XpchFreeInternal(Ords);
                if (St != XPCH_OK)
                    return St;
                FuncRva = Fn;
            }
        }

        /* 导出转发：函数 RVA 落在导出目录内 => 值是转发串 "Dll.Func" */
        if (FuncRva >= ExpDirRva && FuncRva < ExpDirRva + ExpDirSize) {
            char Fwd[160];
            const char *Dot;
            size_t DllLen;
            WCHAR DllName[64];
            ULONG64 DllBase = 0, DllSize = 0, Sub = 0;
            XPCH_STATUS S2;
            char SubName[128];
            ULONG SubOrd = 0;

            St = XpInjRead(Session, Pid, ModBase + FuncRva, Fwd, sizeof(Fwd) - 1);
            if (St != XPCH_OK)
                return St;
            Fwd[sizeof(Fwd) - 1] = 0;
            Dot = strchr(Fwd, '.');
            if (!Dot || Dot == Fwd)
                return XPCH_E_NOT_FOUND;
            DllLen = (size_t)(Dot - Fwd);
            if (DllLen >= 64)
                return XPCH_E_NOT_FOUND;

            {
                int k;
                for (k = 0; k < (int)DllLen; k++)
                    DllName[k] = (WCHAR)(unsigned char)Fwd[k];
                DllName[DllLen] = 0;
                /* 无扩展名则补 .dll */
                if (!wcschr(DllName, L'.')) {
                    DllName[DllLen] = L'.';
                    DllName[DllLen + 1] = L'd';
                    DllName[DllLen + 2] = L'l';
                    DllName[DllLen + 3] = L'l';
                    DllName[DllLen + 4] = 0;
                }
            }

            S2 = XpInjFindModule(Session, Pid, DllName, ModsCache, ModsCount,
                                 &DllBase, &DllSize);
            if (S2 != XPCH_OK)
                return S2;

            if (Dot[1] == '#') {
                SubOrd = (ULONG)strtoul(Dot + 2, NULL, 10);
                S2 = XpInjResolveExport(Session, Pid, ModsCache, ModsCount,
                                        DllBase, NULL, SubOrd, Depth + 1, &Sub);
            } else {
                size_t SubLen = strlen(Dot + 1);
                if (SubLen >= sizeof(SubName))
                    return XPCH_E_NOT_FOUND;
                memcpy(SubName, Dot + 1, SubLen + 1);
                S2 = XpInjResolveExport(Session, Pid, ModsCache, ModsCount,
                                        DllBase, SubName, 0, Depth + 1, &Sub);
            }
            if (S2 != XPCH_OK)
                return S2;
            *OutAddr = Sub;
            return XPCH_OK;
        }

        *OutAddr = ModBase + FuncRva;
        return XPCH_OK;
    }
}

/* ==================================================================
 * 本地映像处理
 * ==================================================================*/

/* BASE 重定位：NewBase != OldBase 时改写本地映像里的绝对地址 */
static XPCH_STATUS XpInjApplyRelocs(BYTE *Local, ULONG LocalSize,
                                    ULONG RelocRva, ULONG RelocSize,
                                    ULONG64 OldBase, ULONG64 NewBase)
{
    ULONG64 Delta = NewBase - OldBase;
    ULONG Off = 0;
    LONG64 SDelta = (LONG64)Delta;

    if (!RelocRva || !RelocSize || OldBase == NewBase)
        return XPCH_OK;

    while (Off + sizeof(IMAGE_BASE_RELOCATION) <= RelocSize) {
        XPCH_INJ_BASE_RELOC *Blk =
            (IMAGE_BASE_RELOCATION *)(Local + RelocRva + Off);
        ULONG Count, i;
        WORD *Entries;

        if (Blk->BlockSize < sizeof(IMAGE_BASE_RELOCATION))
            break;
        if (RelocRva + Off + Blk->BlockSize > LocalSize)
            break;
        Count = (Blk->BlockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        Entries = (WORD *)(Blk + 1);

        for (i = 0; i < Count; i++) {
            WORD E = Entries[i];
            ULONG Type = E >> 12;
            ULONG Ofs = E & 0xFFF;
            ULONG64 Pos = (ULONG64)Blk->PageRva + Ofs;

            if (Type == IMAGE_REL_BASED_ABSOLUTE)
                continue;
            if (Pos + 8 > LocalSize)
                return XPCH_E_BAD_RESPONSE;
            if (Type == IMAGE_REL_BASED_DIR64)
                *(ULONG64 *)(Local + Pos) += (ULONG64)SDelta;
            else if (Type == IMAGE_REL_BASED_HIGHLOW)
                *(ULONG32 *)(Local + Pos) += (ULONG32)SDelta;
            else
                return XPCH_E_BAD_RESPONSE;   /* 其余类型 x64 不应出现 */
        }
        Off += Blk->BlockSize;
    }
    return XPCH_OK;
}

/* 导入解析：读目标导出表，回填本地映像的 IAT */
static XPCH_STATUS XpInjResolveImports(XPCH_SESSION *Session, ULONG Pid,
                                       BYTE *Local, ULONG LocalSize,
                                       ULONG ImportRva, ULONG ImportSize)
{
    XPCH_MODULE_INFO *Mods = NULL;
    ULONG ModsCount = 0;
    ULONG DescIdx;
    XPCH_STATUS St = XPCH_OK;

    if (!ImportRva || !ImportSize)
        return XPCH_OK;
    if (ImportRva + ImportSize > LocalSize)
        return XPCH_E_BAD_RESPONSE;

    for (DescIdx = 0; DescIdx < XPCH_INJ_MAX_IMPORTS; DescIdx++) {
        XPCH_INJ_IMPORT_DESC *Desc =
            (IMAGE_IMPORT_DESCRIPTOR *)(Local + ImportRva)
            + DescIdx;
        const char *DllName;
        WCHAR DllW[64];
        size_t DllLen;
        ULONG64 ModBase = 0, ModSize = 0;
        ULONG IntRva, IatRva;
        ULONG ThunkIdx;
        ULONG64 *Iat;

        if ((ULONG)((BYTE *)Desc - Local) + sizeof(*Desc) > LocalSize)
            break;
        if (!Desc->Name)
            break;                       /* 全零描述符 = 表尾 */

        DllName = (const char *)(Local + Desc->Name);
        if (!memchr(DllName, 0, 64))
            return XPCH_E_BAD_RESPONSE;
        DllLen = strlen(DllName);
        if (DllLen == 0 || DllLen >= 64)
            return XPCH_E_BAD_RESPONSE;
        {
            ULONG k;
            for (k = 0; k <= DllLen; k++)
                DllW[k] = (WCHAR)(unsigned char)DllName[k];
        }

        St = XpInjFindModule(Session, Pid, DllW, &Mods, &ModsCount,
                             &ModBase, &ModSize);
        if (St != XPCH_OK) {
            St = XPCH_E_NOT_FOUND;       /* 依赖未加载（文档化限制） */
            break;
        }

        IntRva = Desc->OriginalFirstThunk;
        IatRva = Desc->FirstThunk;
        if (!IatRva)
            continue;
        if (!IntRva)
            IntRva = IatRva;

        for (ThunkIdx = 0; ThunkIdx < XPCH_INJ_MAX_THUNKS; ThunkIdx++) {
            ULONG64 *Int = (ULONG64 *)(Local + IntRva)
                         + ThunkIdx;
            ULONG64 Thunk;
            ULONG64 Addr = 0;

            if ((ULONG)((BYTE *)Int - Local) + 8 > LocalSize)
                break;
            Thunk = *Int;
            if (!Thunk)
                break;

            if (Thunk & 0x8000000000000000ULL) {
                /* 按序号导入 */
                St = XpInjResolveExport(Session, Pid, &Mods, &ModsCount,
                                        ModBase, NULL,
                                        (ULONG)(Thunk & 0xFFFF),
                                        0, &Addr);
            } else {
                /* 按名字导入：Thunk 是 IMAGE_IMPORT_BY_NAME 的 RVA */
                IMAGE_IMPORT_BY_NAME *Ibn;
                if (Thunk + 2 + 1 > LocalSize)
                    return XPCH_E_BAD_RESPONSE;
                Ibn = (IMAGE_IMPORT_BY_NAME *)(Local + Thunk);
                St = XpInjResolveExport(Session, Pid, &Mods, &ModsCount,
                                        ModBase, (const char *)Ibn->Name,
                                        0, 0, &Addr);
            }
            if (St != XPCH_OK)
                goto Done;

            Iat = (ULONG64 *)(Local + IatRva) + ThunkIdx;
            if ((ULONG)((BYTE *)Iat - Local) + 8 > LocalSize)
                return XPCH_E_BAD_RESPONSE;
            *Iat = Addr;
        }
    }
    St = XPCH_OK;

Done:
    XpchFreeInternal(Mods);
    return St;
}

/* ==================================================================
 * 入口引导桩
 *
 * 远程线程入口不能直接用 DllMain（线程例程只收 1 个参数），
 * 在 DOS stub 区写引导桩：固定 (base, DLL_PROCESS_ATTACH, 0)
 * 三参调用入口后，**显式调用 RtlExitUserThread 结束线程**。
 *
 * 【为什么必须 exit 不能 ret】RtlCreateUserThread 创建的线程没有
 * BaseThreadInitThunk 包装，例程 return 会弹出栈上的垃圾返回地址
 * 直接崩溃整个目标进程（实机验证：进程 Vads 归零、线程全灭，
 * 注入表象"成功"但目标已死）。必须 RtlExitUserThread(0)。
 * ==================================================================*/
#define XPCH_INJ_STUB_SIZE 56u

static void XpInjBuildStub(BYTE *Stub, ULONG64 ImageBase, ULONG64 Entry,
                           ULONG64 ExitThread)
{
    BYTE *P = Stub;

    /* 48 B9 <imm64>   mov rcx, ImageBase */
    *P++ = 0x48; *P++ = 0xB9;
    memcpy(P, &ImageBase, 8); P += 8;
    /* BA 01 00 00 00  mov edx, DLL_PROCESS_ATTACH */
    *P++ = 0xBA; *P++ = 0x01; *P++ = 0x00; *P++ = 0x00; *P++ = 0x00;
    /* 45 33 C0        xor r8d, r8d */
    *P++ = 0x45; *P++ = 0x33; *P++ = 0xC0;
    /* 48 B8 <imm64>   mov rax, Entry */
    *P++ = 0x48; *P++ = 0xB8;
    memcpy(P, &Entry, 8); P += 8;
    /* 48 83 EC 28     sub rsp, 0x28   （对齐 + 影子空间） */
    *P++ = 0x48; *P++ = 0x83; *P++ = 0xEC; *P++ = 0x28;
    /* FF D0           call rax        （调用 DllMain） */
    *P++ = 0xFF; *P++ = 0xD0;

    /* 33 C9           xor ecx, ecx    （ExitCode = 0） */
    *P++ = 0x33; *P++ = 0xC9;
    /* 48 B8 <imm64>   mov rax, RtlExitUserThread */
    *P++ = 0x48; *P++ = 0xB8;
    memcpy(P, &ExitThread, 8); P += 8;
    /* FF D0           call rax        （永不返回） */
    *P++ = 0xFF; *P++ = 0xD0;
    /* EB FE           jmp $           （保底：不该走到） */
    *P++ = 0xEB; *P++ = 0xFE;
}

/* ==================================================================
 * XpchInjectDll —— 主流程
 * ==================================================================*/
XPCH_STATUS XpchInjectDll(XPCH_SESSION *Session, ULONG Pid,
                          const WCHAR *DllPath, ULONG Flags,
                          ULONG64 *RemoteBase)
{
    XPCH_SESSION_IMPL *Impl;
    XPCH_STATUS St = XPCH_OK;
    HANDLE File = INVALID_HANDLE_VALUE;
    LARGE_INTEGER FSize;
    BYTE *FileBuf = NULL;
    BYTE *Local = NULL;
    ULONG64 Base = 0;
    ULONG FileSize = 0;
    ULONG64 EntryPoint, ImageBase, NtBase;
    ULONG SizeOfImage, SizeOfHeaders, RelocRva, RelocSize, ImportRva, ImportSize;
    ULONG64 Delta;
    WORD NumSections;
    ULONG i;
    BOOL Run;

    if (RemoteBase)
        *RemoteBase = 0;
    if (!Session || !DllPath || !RemoteBase || (Flags & ~0x3u))
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    /* ---- 1. 读 DLL 文件（自身文件的三环读，非跨进程访问） ---- */
    File = CreateFileW(DllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return XPCH_E_NOT_FOUND;
    if (!GetFileSizeEx(File, &FSize) || FSize.QuadPart <= 0
        || FSize.QuadPart > (LONGLONG)XPCH_INJ_MAX_IMAGE) {
        CloseHandle(File);
        return XPCH_E_INVALID_ARG;
    }
    FileSize = (ULONG)FSize.QuadPart;
    FileBuf = (BYTE *)XpchAlloc(FileSize);
    if (!FileBuf) {
        CloseHandle(File);
        return XPCH_E_NO_MEMORY;
    }
    {
        DWORD Got = 0;
        if (!ReadFile(File, FileBuf, FileSize, &Got, NULL) || Got != FileSize) {
            CloseHandle(File);
            St = XPCH_E_BAD_RESPONSE;
            goto FailNoBase;
        }
    }
    CloseHandle(File);
    File = INVALID_HANDLE_VALUE;

    /* ---- 2. 解析 PE（仅 PE32+） ---- */
    {
        IMAGE_DOS_HEADER Dos;
        IMAGE_NT_HEADERS64 Nt;

        if (FileSize < sizeof(Dos) + sizeof(Nt)) {
            St = XPCH_E_INVALID_ARG;
            goto FailNoBase;
        }
        memcpy(&Dos, FileBuf, sizeof(Dos));
        if (Dos.e_magic != IMAGE_DOS_SIGNATURE
            || (ULONG)Dos.e_lfanew < sizeof(Dos)
            || (ULONG)Dos.e_lfanew + sizeof(Nt) > FileSize) {
            St = XPCH_E_INVALID_ARG;
            goto FailNoBase;
        }
        memcpy(&Nt, FileBuf + Dos.e_lfanew, sizeof(Nt));
        if (Nt.Signature != IMAGE_NT_SIGNATURE
            || Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            St = XPCH_E_NOT_SUPPORTED;     /* 仅 x64 DLL */
            goto FailNoBase;
        }
        if (Nt.FileHeader.NumberOfSections > XPCH_INJ_MAX_SECTIONS
            || Nt.OptionalHeader.NumberOfRvaAndSizes < 16) {
            St = XPCH_E_BAD_RESPONSE;
            goto FailNoBase;
        }

        NtBase        = (ULONG64)Dos.e_lfanew;
        SizeOfImage   = Nt.OptionalHeader.SizeOfImage;
        SizeOfHeaders = Nt.OptionalHeader.SizeOfHeaders;
        EntryPoint    = Nt.OptionalHeader.AddressOfEntryPoint;
        ImageBase     = Nt.OptionalHeader.ImageBase;
        RelocRva      = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        RelocSize     = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        ImportRva     = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        ImportSize    = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (SizeOfImage < 0x1000 || SizeOfImage > XPCH_INJ_MAX_IMAGE
            || SizeOfHeaders > SizeOfImage
            || RelocRva + RelocSize > SizeOfImage
            || ImportRva + ImportSize > SizeOfImage) {
            St = XPCH_E_BAD_RESPONSE;
            goto FailNoBase;
        }
        NumSections = Nt.FileHeader.NumberOfSections;
    }

    /* ---- 3. 本地展开节区（虚拟布局） ---- */
    Local = (BYTE *)XpchAlloc(SizeOfImage);
    if (!Local) {
        St = XPCH_E_NO_MEMORY;
        goto FailNoBase;
    }
    memcpy(Local, FileBuf, min(SizeOfHeaders, FileSize));
    {
        IMAGE_SECTION_HEADER *Sec = (IMAGE_SECTION_HEADER *)
            (FileBuf + NtBase + sizeof(IMAGE_NT_HEADERS64));
        for (i = 0; i < NumSections; i++) {
            ULONG Va = Sec[i].VirtualAddress;
            ULONG Vs = Sec[i].Misc.VirtualSize;
            ULONG Sr = Sec[i].SizeOfRawData;
            ULONG Pr = Sec[i].PointerToRawData;
            ULONG n;

            if (!Vs)
                continue;
            if (Va >= SizeOfImage || Va + Vs > SizeOfImage) {
                St = XPCH_E_BAD_RESPONSE;
                goto FailNoBase;
            }
            if (!Sr || !Pr)
                continue;                  /* BSS/未初始化：保持 0 */
            n = (Vs < Sr) ? Vs : Sr;
            if (Pr + n > FileSize)
                n = FileSize - Pr;         /* 截断畸形条目 */
            memcpy(Local + Va, FileBuf + Pr, n);
        }
    }
    XpchFreeInternal(FileBuf);
    FileBuf = NULL;

    /* ---- 4. 远程分配（RWX，0x09B Op=0） ---- */
    St = XpInjProcessOp(Session, Pid, XPCH_PROCOP_ALLOC,
                        SizeOfImage, 0, 0, &Base);
    XP_INJ_STEP(1, St);
    if (St != XPCH_OK || !Base) {
        if (St == XPCH_OK)
            St = XPCH_E_NO_MEMORY;
        goto FailNoBase;
    }
    if (Base & 0xFFF) {                    /* 系统保证页对齐 */
        St = XPCH_E_BAD_RESPONSE;
        goto FailWithBase;
    }

    /* ---- 5. 本地应用重定位 + 解析导入（都在本地缓冲改，随后一次写回） ---- */
    Delta = Base - ImageBase;
    St = XpInjApplyRelocs(Local, SizeOfImage, RelocRva, RelocSize,
                          ImageBase, Base);
    XP_INJ_STEP(2, St);
    if (St != XPCH_OK)
        goto FailWithBase;

    St = XpInjResolveImports(Session, Pid, Local, SizeOfImage,
                             ImportRva, ImportSize);
    XP_INJ_STEP(3, St);
    if (St != XPCH_OK)
        goto FailWithBase;

    /* ---- 6. 整块写回（分片 32KB，0x081）：先有映像，再谈执行 ---- */
    St = XpInjWrite(Session, Pid, Base, Local, SizeOfImage);
    XP_INJ_STEP(4, St);
    if (St != XPCH_OK)
        goto FailWithBase;
    XpchFreeInternal(Local);
    Local = NULL;

    /* ---- 7. 引导桩 + 远程线程（默认执行 DllMain；XPCH_INJECT_NORUN 关闭） ---- */
    Run = !(Flags & XPCH_INJECT_NORUN);
    if (Run && EntryPoint) {
        BYTE Stub[XPCH_INJ_STUB_SIZE];
        ULONG64 Tid = 0;
        ULONG64 ExitThread = 0;

        if (NtBase < XPCH_INJ_STUB_OFF + XPCH_INJ_STUB_SIZE) {
            St = XPCH_E_BAD_RESPONSE;      /* e_lfanew 太靠前，桩放不下 */
            goto FailWithBase;
        }

        /* 必须在目标进程里解析 RtlExitUserThread（stub 结尾要调用它） */
        {
            XPCH_MODULE_INFO *M = NULL;
            ULONG MN = 0, k;
            ULONG64 NtBaseAddr = 0, NtSize = 0;
            if (XpchEnumModules(Session, Pid, &M, &MN) == XPCH_OK) {
                for (k = 0; k < MN; k++)
                    if (_wcsicmp(M[k].Name, L"ntdll.dll") == 0) {
                        NtBaseAddr = M[k].Base;
                        NtSize = M[k].Size;
                        break;
                    }
                XpchFreeInternal(M);
            }
            if (NtBaseAddr)
                (void)XpInjResolveExport(Session, Pid, NULL, NULL,
                                         NtBaseAddr, "RtlExitUserThread",
                                         0, 0, &ExitThread);
        }
        if (!ExitThread) {
            St = XPCH_E_NOT_SUPPORTED;     /* 目标无 ntdll，无法安全退出线程 */
            goto FailWithBase;
        }

        XpInjBuildStub(Stub, Base, Base + EntryPoint, ExitThread);
        St = XpInjWrite(Session, Pid, Base + XPCH_INJ_STUB_OFF,
                        Stub, sizeof(Stub));
        XP_INJ_STEP(5, St);
        if (St != XPCH_OK)
            goto FailWithBase;

        St = XpInjProcessOp(Session, Pid, XPCH_PROCOP_CREATETHREAD,
                            Base + XPCH_INJ_STUB_OFF, 0, 0, &Tid);
        XP_INJ_STEP(6, St);
        if (St != XPCH_OK)
            goto FailWithBase;
        /* 线程已派发：不再回收映像（DllMain 可能已运行） */
    }

    *RemoteBase = Base;
    return XPCH_OK;

FailWithBase:
    if (Base)
        XpInjProcessOp(Session, Pid, XPCH_PROCOP_FREE, Base, 0, 0, NULL);
FailNoBase:
    if (FileBuf)
        XpchFreeInternal(FileBuf);
    if (Local)
        XpchFreeInternal(Local);
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    return St;
}
