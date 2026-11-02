// ============================================================================
// HookViews.c — Ring0 Hooks / Ring3 Hooks 页（原版第 3、4 个主 Tab，共 5 项）
//
// 清单条目：
//   Ring0 Hooks（3 项）
//     Hook 表枚举
//     `Restore Over. Hooks/Patches` 恢复
//     `Restore KernelCallbackTable Replaced`
//   Ring3 Hooks（2 项）
//     Hook 表枚举
//     `%s-->Ring3 Hook` 展示
//
// 【Ring0 三项的状态：受阻，已定位根因，不做假数据】
//   驱动侧 3 个候选命令 0x117/0x119/0x11A/0x11B 在"85 个空槽"名单里。
//   实测 0x117 是 HANDLED 但 lastResult=0、输出只有 build 号（0x47BA）后全零，
//   说明两个 Count 都是 0。追踪到 EnumHookInfoOperation 读
//   GT[0x8B7]（=GtDisableHookProtectionAddr1|GtEprocessField150），而该槽由
//   ParseSyscallTableExportDir 填充 —— 该函数在复刻里是空壳，缺 6 个被调用方：
//     ReadWdfLibraryModule(0x140086EA4, 0x12B)
//     FindSyscallTableDescriptor(0x140085E34, 0x27F)
//     BuildExportSectionMapping(0x140086908, 0xB6)
//     CollectSyscallEntries4(0x140086868, 0x9E)
//     CollectTwoSyscallTables(0x140086740, 0x127)
//     CollectSyscallExportEntries(0x140086690, 0xAE)
//   合计约 2000 字节。这条链还依赖一批未初始化的 GT 槽
//   （例如 CollectSyscallExportEntries 里的 GtKeGetCurrentIrql|GtPathBuffer04|0x3100）。
//   所以 Ring0 页三项在链条补齐前无法产出真实数据 —— 界面如实显示"blocked"。
//
// 【Ring3 两项：已实现】
//   用户态可做两件事：
//   1) IAT 检查（FeScanModuleIat）
//      A 类：槽值落在**所有已加载模块之外** → 指向野代码/跳板，可疑。
//      B 类：槽值在模块内，但与该导入名的应然地址不同 →
//            同模块劫持（A.dll!Foo 被改成 A.dll!Bar），地址看着合法但行为已变。
//            B 类需要按导入名解析导出表，默认开启（见 g_Ring3DiagIatDeep 注释）。
//   2) 导出函数 inline hook（FeScanModuleInline）
//      磁盘 PE 字节 vs 内存字节，16 字节窗口比对，PE 重定位目标跳过。
//   展示格式沿用原版的 `%s-->Ring3 Hook`。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

/* ---------------------------------------------------------------- Ring3 Hook */

/* 诊断：Ring3 扫描的模块总数与 inline 实际扫描数（排查卡顿用）。 */
static ULONG g_Ring3DiagModules;
static ULONG g_Ring3DiagInlineScanned;
static int   g_Ring3DiagVerbose;
/* 是否做 B 类（同模块 IAT 劫持）深度校验。
 *
 * 【2026-10-29 性能修复后改为默认开启】
 *   此前逐槽 ReadProcessMemory 读 IMAGE_IMPORT_BY_NAME，ntdll 一个 DLL
 *   就上千次跨进程调用，单进程 60~90 秒跑不完，只能默认关。
 *   现改为：描述符数组整块读 + 全部导入名按 [minRva,maxRva) 一次整块读
 *   + 导出表三张表各一次整块读，跨进程调用数降到每模块十余次，
 *   实测整进程扫描回到亚秒级，因此不再需要开关。
 *   仍保留 XPCH_IAT_NO_DEEP=1 可关掉（遇到异常镜像时排查用）。 */
static int   g_Ring3DiagIatDeep;

/* 取某进程的模块基址范围表（用于判断地址归属）。 */
static BOOL FeLoadModuleRanges(ULONG Pid, FE_HOOK_RANGE **Out, ULONG *OutCount)
{
    HMODULE mods[1024];
    HANDLE hProc;
    DWORD needed = 0;
    ULONG i, n = 0;
    FE_HOOK_RANGE *ranges;

    *Out = NULL;
    *OutCount = 0;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        FALSE, Pid);
    if (!hProc)
        return FALSE;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        CloseHandle(hProc);
        return FALSE;
    }
    n = needed / sizeof(HMODULE);
    if (n == 0 || n > 1024) {
        CloseHandle(hProc);
        return FALSE;
    }
    ranges = (FE_HOOK_RANGE *)calloc(n, sizeof(FE_HOOK_RANGE));
    if (!ranges) {
        CloseHandle(hProc);
        return FALSE;
    }
    for (i = 0; i < n; i++) {
        MODULEINFO mi;
        if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
            ranges[i].Base = (ULONG64)(ULONG_PTR)mi.lpBaseOfDll;
            ranges[i].Size = mi.SizeOfImage;
            GetModuleBaseNameA(hProc, mods[i], ranges[i].Name, sizeof(ranges[i].Name));
        }
    }
    CloseHandle(hProc);
    *Out = ranges;
    *OutCount = n;
    return TRUE;
}

/* 判断地址是否落在任一已加载模块内。返回命中的模块索引，未命中返回 -1。 */
static int FeFindModuleByAddr(const FE_HOOK_RANGE *Ranges, ULONG Count, ULONG64 Addr)
{
    ULONG i;
    for (i = 0; i < Count; i++) {
        if (Addr >= Ranges[i].Base && Addr < Ranges[i].Base + Ranges[i].Size)
            return (int)i;
    }
    return -1;
}

/* 在模块导出表里按名字查地址（按需查找，不预建全表）。
 *
 * 【为什么不做全表缓存】初版尝试把每个模块的全部导出名都读进内存建缓存。
 * 实测在 Services 会话下单个 ReadProcessMemory 就要几十毫秒，
 * ntdll 2490 个导出 × 每槽触发 = 扫一个进程 60 秒以上都跑不完。
 *
 * 改为：只解析"IAT 里实际出现的那些导入名"。一个进程的导入名总数
 * 通常只有几百个，且这里只对"地址落在模块内"的槽调用（A 类越界项
 * 已在前面直接报掉），实际调用次数很低。
 *
 * 优化：一个描述符内的所有槽共用同一个目标 DLL，先生成一份该 DLL 的
 * 「名字→地址」映射再逐一比对，避免重复扫描。
 */
typedef struct _FE_EXP_MAP {
    ULONG64 ModBase;
    ULONG   Count;
    struct { char Name[96]; ULONG64 Addr; } *Items;
} FE_EXP_MAP;

/* 全局按模块缓存：一次扫描内每个目标 DLL 只解析一次。
 *
 * 【为什么必须】单个 ReadProcessMemory 在 Services 会话下要几十毫秒；
 * ntdll 有 2490 个导出名，单次建表就要几十秒。若每个导入描述符都重建，
 * 一个进程几百个描述符完全不可用（实测 60 秒跑不完）。
 * 缓存后整个扫描只对「被导入的 DLL」各建一次，通常 3~8 个。 */
#define FE_EXPMAP_CACHE_MAX 16
static FE_EXP_MAP g_ExpMaps[FE_EXPMAP_CACHE_MAX];
static ULONG      g_ExpMapsUsed;

static void FeExpMapsReset(void)
{
    ULONG i;
    for (i = 0; i < g_ExpMapsUsed; i++)
        free(g_ExpMaps[i].Items);
    ZeroMemory(g_ExpMaps, sizeof(g_ExpMaps));
    g_ExpMapsUsed = 0;
}

static const FE_EXP_MAP *FeExpMapsFind(ULONG64 ModBase)
{
    ULONG i;
    for (i = 0; i < g_ExpMapsUsed; i++)
        if (g_ExpMaps[i].ModBase == ModBase)
            return &g_ExpMaps[i];
    return NULL;
}

static void FeExpMapFree(FE_EXP_MAP *m)
{
    if (m) {
        free(m->Items);
        m->Items = NULL;
        m->Count = 0;
        m->ModBase = 0;
    }
}

/* 建一次映射（每个目标 DLL 每轮扫描只建一次，调用方负责复用）。 */
static void FeExpMapBuild(HANDLE hProc, ULONG64 ModBase, FE_EXP_MAP *m)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY expDir;
    IMAGE_EXPORT_DIRECTORY exp;
    DWORD nNames, nFuncs, i;
    DWORD *names = NULL, *funcs = NULL;
    WORD  *ords = NULL;

    ZeroMemory(m, sizeof(*m));
    m->ModBase = ModBase;
    if (!ModBase)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)ModBase, &dos, sizeof(dos), NULL))
        return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + dos.e_lfanew),
                           &nt, sizeof(nt), NULL))
        return;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return;
    expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + expDir.VirtualAddress),
                           &exp, sizeof(exp), NULL))
        return;
    nNames = exp.NumberOfNames;
    nFuncs = exp.NumberOfFunctions;
    if (g_Ring3DiagVerbose) {
        printf("        [expmap] base=%016I64X nfun=%lu nname=%lu\n",
               (unsigned __int64)ModBase, nFuncs, nNames);
        fflush(stdout);
    }
    if (nNames == 0 || nNames > 0x8000 || nFuncs == 0)
        return;

    names = (DWORD *)calloc(nNames, sizeof(DWORD));
    ords = (WORD *)calloc(nNames, sizeof(WORD));
    funcs = (DWORD *)calloc(nFuncs, sizeof(DWORD));
    m->Items = (void *)calloc(nNames, 104);
    if (!names || !ords || !funcs || !m->Items) {
        free(names); free(ords); free(funcs);
        FeExpMapFree(m);
        return;
    }
    /* 三张表各一次整块读，而不是逐项读 */
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + exp.AddressOfNames),
                           names, nNames * sizeof(DWORD), NULL) ||
        !ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + exp.AddressOfNameOrdinals),
                           ords, nNames * sizeof(WORD), NULL) ||
        !ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + exp.AddressOfFunctions),
                           funcs, nFuncs * sizeof(DWORD), NULL)) {
        free(names); free(ords); free(funcs);
        FeExpMapFree(m);
        return;
    }

    /* 【关键性能优化】名字字符串在 .rdata 里连续分布。逐名 ReadProcessMemory
       会变成几千次跨进程调用（Services 会话下每次可达数十毫秒），
       实测 ntdll 一个模块就要 90 秒以上。
       改为：先算出所有名字 RVA 的最小/最大范围，**一次读回整块**，
       之后全部改成内存内指针运算。上限 4MB 防止异常镜像。 */
    if (nNames > 0) {
        DWORD minRva = 0xFFFFFFFF, maxRva = 0;
        DWORD span;
        BYTE *strBlob = NULL;
        SIZE_T blobGot = 0;

        for (i = 0; i < nNames; i++) {
            if (!names[i]) continue;
            if (names[i] < minRva) minRva = names[i];
            if (names[i] > maxRva) maxRva = names[i];
        }
        if (minRva != 0xFFFFFFFF && maxRva >= minRva) {
            span = (maxRva - minRva) + 128;      /* +128 兜住最后一个长名 */
            if (span > 0x400000)
                span = 0x400000;
            strBlob = (BYTE *)calloc(1, span);
            if (strBlob) {
                /* 短读是可接受的部分成功：blobGot 之后的项按"读不到"跳过 */
                ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModBase + minRva),
                                  strBlob, span, &blobGot);
            }
        }

        for (i = 0; i < nNames && m->Count < 4000; i++) {
            const char *nm = NULL;
            DWORD funcRva;
            WORD ordv = ords[i];

            if (!names[i] || ordv >= nFuncs)
                continue;
            funcRva = funcs[ordv];
            if (funcRva == 0)
                continue;
            if (funcRva >= expDir.VirtualAddress &&
                funcRva < expDir.VirtualAddress + expDir.Size)
                continue;                        /* 转发导出 */

            if (strBlob && names[i] >= minRva &&
                (names[i] - minRva) < blobGot) {
                nm = (const char *)(strBlob + (names[i] - minRva));
                /* 必须在已读范围内遇到 NUL，否则视为不可靠，跳过 */
                if (!memchr(nm, 0, (size_t)(blobGot - (names[i] - minRva))))
                    continue;
            } else {
                continue;
            }
            strncpy_s(m->Items[m->Count].Name, sizeof(m->Items[m->Count].Name),
                      nm, sizeof(m->Items[m->Count].Name) - 1);
            m->Items[m->Count].Addr = ModBase + funcRva;
            m->Count++;
        }
        free(strBlob);
    }
    free(names); free(ords); free(funcs);
}

static ULONG64 FeExpMapLookup(const FE_EXP_MAP *m, const char *FuncName)
{
    ULONG i;
    if (!m || !m->Items || !FuncName || !FuncName[0])
        return 0;
    for (i = 0; i < m->Count; i++)
        if (strcmp(m->Items[i].Name, FuncName) == 0)
            return m->Items[i].Addr;
    return 0;
}

/* 扫描某模块的导入表，检测 IAT 篡改。
 *
 * 两类判据：
 *   A. 目标落在**所有已加载模块之外** —— 经典导入劫持（指向野代码）
 *   B. 目标**在模块内，但不是该导入名的应然地址** —— 同模块 IAT 劫持
 *      （把 A.dll!Foo 改成 A.dll!Bar，返回值/行为不同但地址看起来合法）
 *
 * B 类此前完全漏检。实测复现：把 iatdll!RealTargetAdd 的 IAT 槽改成
 * iatdll!FakeTargetAdd，调用返回 1003 而非 3（劫持真实生效），
 * 但旧判据报 0 条。
 *
 * 应然地址的求法：从 OriginalFirstThunk 取导入名 → 在 IAT 原属模块
 * （descriptor.Name）里查导出表得到地址。
 *
 * 只读**目标进程内存**（ReadProcessMemory），不改任何东西。 */
static void FeScanModuleIat(HANDLE hProc, const FE_HOOK_RANGE *Ranges, ULONG RangeCount,
                            ULONG64 ModuleBase, const char *ModuleName,
                            FE_HOOK_LIST *List, ULONG MaxHooks)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY impDir;
    ULONG64 impDescAddr;
    ULONG i;
    IMAGE_IMPORT_DESCRIPTOR descs[64];
    SIZE_T descGot = 0;
    ULONG descCount;
    char  *dllNameBlob = NULL;
    SIZE_T dllNameGot = 0;
    DWORD  dllNameMin = 0;

    if (List->Count >= MaxHooks)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)ModuleBase, &dos, sizeof(dos), NULL))
        return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModuleBase + dos.e_lfanew),
                           &nt, sizeof(nt), NULL))
        return;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return;

    impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0)
        return;
    impDescAddr = ModuleBase + impDir.VirtualAddress;

    /* 【性能】64 个描述符一次整块读，而不是逐描述符一次跨进程调用。
       Services 会话下每次 ReadProcessMemory 可达数十毫秒，
       60 模块 × 64 描述符 = 3840 次就是几十秒的固定开销。 */
    ZeroMemory(descs, sizeof(descs));
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)impDescAddr,
                           descs, sizeof(descs), &descGot) || descGot < sizeof(IMAGE_IMPORT_DESCRIPTOR))
        return;
    descCount = (ULONG)(descGot / sizeof(IMAGE_IMPORT_DESCRIPTOR));

    /* 【性能】所有 DLL 名也一次读回。名字是 .rdata 里连续分布的短串，
   	   先求最小 RVA 再整块读，把几十次跨进程读压成一次。 */
    {
        DWORD minRva = 0xFFFFFFFF, maxRva = 0;
        ULONG d;
        for (d = 0; d < descCount; d++) {
            if (!descs[d].Name)
                break;
            if (descs[d].Name < minRva) minRva = descs[d].Name;
            if (descs[d].Name > maxRva) maxRva = descs[d].Name;
        }
        if (minRva != 0xFFFFFFFF && maxRva >= minRva && (maxRva - minRva) < 0x10000) {
            SIZE_T span = (SIZE_T)(maxRva - minRva) + 128;
            dllNameBlob = (char *)calloc(1, span);
            if (dllNameBlob) {
                ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModuleBase + minRva),
                                  dllNameBlob, span, &dllNameGot);
                dllNameMin = minRva;
            }
        }
    }

    for (i = 0; i < descCount && List->Count < MaxHooks; i++) {
        IMAGE_IMPORT_DESCRIPTOR desc = descs[i];
        ULONG64 iatAddr;
        ULONG k;

        if (desc.Name == 0 && desc.FirstThunk == 0)
            break;
        if (desc.FirstThunk == 0)
            continue;
        iatAddr = ModuleBase + desc.FirstThunk;
        if (g_Ring3DiagVerbose) {
            printf("      [iat] desc#%lu ft=0x%X oft=0x%X\n",
                   i, desc.FirstThunk, desc.OriginalFirstThunk);
            fflush(stdout);
        }

        /* IAT 整块读取：原先每个 thunk 单独 ReadProcessMemory，
           64 描述符 × 512 thunk × 60 模块 ≈ 200 万次系统调用，
           在 Services 会话下要几十秒。改成一描述符一次读 4KB。 */
        {
            ULONG64 block[512];
            ULONG64 intBlock[512];        /* OriginalFirstThunk 侧（导入名表） */
            SIZE_T got = 0;
            SIZE_T intGot = 0;
            BOOL haveInt = FALSE;
            ULONG64 dllBase = 0;          /* IAT 原属模块的加载基址 */
            char  *impNameBlob = NULL;    /* 本描述符所有导入名的整块缓存 */
            SIZE_T impNameGot = 0;
            DWORD  impNameMin = 0;

            if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)iatAddr,
                                   block, sizeof(block), &got))
                continue;
            /* 短读时把有效长度夹到读到的大小，后面的 block[k] 都是有效项 */
            if (got == 0 || got > sizeof(block))
                continue;

            /* 取导入名表（OriginalFirstThunk）。它和 FirstThunk 一一对应，
               是判定"应然地址"的唯一来源。
               【必须清零】ReadProcessMemory 只覆盖有效项，其余保持栈垃圾；
               垃圾值会通过 byNameRva != 0 的检查，触发大量无效读，
               实测单个描述符因此卡 10 秒以上。 */
            ZeroMemory(intBlock, sizeof(intBlock));
            if (g_Ring3DiagIatDeep && desc.OriginalFirstThunk) {
                SIZE_T wantInt = sizeof(intBlock);
                /* 只读 IAT 实际存在的那一段，避免跨节读失败 */
                if (wantInt > got && got > 0)
                    wantInt = got;
                haveInt = ReadProcessMemory(hProc,
                    (LPCVOID)(ULONG_PTR)(ModuleBase + desc.OriginalFirstThunk),
                    intBlock, wantInt, &intGot) ? TRUE : FALSE;
                if (haveInt && intGot < wantInt) {
                    haveInt = FALSE;    /* 短读：可能跨页，放弃本描述符 */
                    intGot = 0;
                }
                if (haveInt && intGot / sizeof(ULONG64) < got / sizeof(ULONG64))
                    haveInt = FALSE;
            }
            /* 【性能】本描述符全部导入名一次整块读。
               原先每个 IAT 槽单独 ReadProcessMemory 读 IMAGE_IMPORT_BY_NAME，
               ntdll 一个 DLL 就上千次跨进程调用，Services 会话下单次数十毫秒
               → 单进程 60~90 秒。名字串在 .rdata 连续分布，求最小 RVA 后
               整块读回，成本降到每个描述符 1 次。 */
            if (haveInt) {
                DWORD minRva = 0xFFFFFFFF, maxRva = 0;
                ULONG kk, lim = (ULONG)(intGot / sizeof(ULONG64));
                /* 【必须遇 0 终止】INT 是 NULL 结尾数组，后面的字节是
                   .rdata 里无关数据。若继续扫，垃圾值会把 maxRva 撑到
                   几十 MB，触发下面的跨度上限而放弃整块读。 */
                for (kk = 0; kk < lim; kk++) {
                    ULONG64 r = intBlock[kk];
                    if (!r)
                        break;
                    if (r & 0x8000000000000000ULL)
                        continue;                /* 序号导入，无名字 */
                    if (r > 0x10000000)
                        continue;
                    if (r < minRva) minRva = (DWORD)r;
                    if (r > maxRva) maxRva = (DWORD)r;
                }
                if (minRva != 0xFFFFFFFF && maxRva >= minRva &&
                    (maxRva - minRva) < 0x100000) {
                    SIZE_T span = (SIZE_T)(maxRva - minRva) + 256;
                    impNameBlob = (char *)calloc(1, span);
                    if (impNameBlob) {
                        ReadProcessMemory(hProc,
                            (LPCVOID)(ULONG_PTR)(ModuleBase + minRva),
                            impNameBlob, span, &impNameGot);
                        impNameMin = minRva;
                    }
                }
            }
            /* 该 IAT 属于哪个 DLL：descriptor.Name 是模块名（如 "iatdll.dll"）。
               在已加载模块表里按名字找，拿到它的基址；
               并**每个描述符只建一次**该 DLL 的导出映射供本轮复用。 */
            if (haveInt && desc.Name && desc.Name < 0x10000000) {
                const char *dllName = NULL;
                if (dllNameBlob && desc.Name >= dllNameMin &&
                    (desc.Name - dllNameMin) < dllNameGot) {
                    dllName = dllNameBlob + (desc.Name - dllNameMin);
                    if (!memchr(dllName, 0, (size_t)(dllNameGot - (desc.Name - dllNameMin))))
                        dllName = NULL;
                }
                if (dllName && dllName[0]) {
                    ULONG r;
                    for (r = 0; r < RangeCount; r++) {
                        if (_stricmp(Ranges[r].Name, dllName) == 0) {
                            dllBase = Ranges[r].Base;
                            break;
                        }
                    }
                }
            }
            /* B 类（同模块 IAT 劫持）需要按导入名解析导出表。
               初版逐槽跨进程读导入名，单进程要 60~90 秒，只能默认关；
               现在描述符数组、导入名块、导出三表都已整块读，
               每模块只剩十余次跨进程调用，故默认开启。
               XPCH_IAT_NO_DEEP=1 可关闭。A 类（指向模块外）始终启用。 */
            if (g_Ring3DiagIatDeep && haveInt && dllBase &&
                !FeExpMapsFind(dllBase) &&
                g_ExpMapsUsed < FE_EXPMAP_CACHE_MAX) {
                FeExpMapBuild(hProc, dllBase, &g_ExpMaps[g_ExpMapsUsed]);
                g_ExpMapsUsed++;
            }

            for (k = 0; k < got / sizeof(ULONG64) && List->Count < MaxHooks; k++) {
                ULONG64 entry = block[k];
                ULONG64 target;
                int owner;
                FE_HOOK_ENTRY *e;

                if (entry == 0)
                    break;
                if (entry == (ULONG64)-1)
                    continue;                       /* 序数导入占位 */
                /* 只处理"直接地址"形式的 IAT 条目（高位为内核/用户地址） */
                if (entry < 0x10000)
                    continue;
                target = entry;
                owner = FeFindModuleByAddr(Ranges, RangeCount, target);
                if (owner < 0) {
                    /* A 类：落所有模块之外 —— 导入劫持指向野代码 */
                    if (List->Count >= List->Capacity) {
                        ULONG newCap = List->Capacity ? List->Capacity * 2 : 32;
                        FE_HOOK_ENTRY *p = (FE_HOOK_ENTRY *)realloc(
                            List->Items, newCap * sizeof(FE_HOOK_ENTRY));
                        if (!p)
                            return;
                        List->Items = p;
                        List->Capacity = newCap;
                    }
                    e = &List->Items[List->Count++];
                    ZeroMemory(e, sizeof(*e));
                    sprintf_s(e->Owner, sizeof(e->Owner), "%s", ModuleName);
                    e->IatAddress = iatAddr + k * 8;
                    e->Target = target;
                    sprintf_s(e->TargetModule, sizeof(e->TargetModule),
                              "(outside all modules)");
                    continue;
                }

                /* B 类：地址在模块内，但可能被改成了同模块的另一个函数。
                   只有拿到导入名 + 原属模块基址时才判定。 */
                if (g_Ring3DiagIatDeep && haveInt && dllBase &&
                    k < (ULONG)(intGot / sizeof(ULONG64))) {
                    ULONG64 byNameRva = intBlock[k];
                    if (byNameRva && !(byNameRva & 0x8000000000000000ULL) &&
                        byNameRva <= 0x10000000) {
                        const char *impName = NULL;
                        ULONG64 expected;

                        /* 从整块缓存里取名字，不再逐槽跨进程读 */
                        if (impNameBlob && (DWORD)byNameRva >= impNameMin &&
                            ((DWORD)byNameRva - impNameMin) + 2 < impNameGot) {
                            const char *cand = impNameBlob +
                                ((DWORD)byNameRva - impNameMin) + 2;
                            SIZE_T remain = impNameGot -
                                ((DWORD)byNameRva - impNameMin) - 2;
                            if (memchr(cand, 0, remain))
                                impName = cand;
                        }
                        if (impName) {
                            expected = FeExpMapLookup(FeExpMapsFind(dllBase), impName);
                            /* 只有能确定"应然地址"且确实不同才报，
                               查不到（转发导出等）就跳过，避免误报。 */
                            if (expected && expected != target) {
                                if (List->Count >= List->Capacity) {
                                    ULONG newCap = List->Capacity ? List->Capacity * 2 : 32;
                                    FE_HOOK_ENTRY *p = (FE_HOOK_ENTRY *)realloc(
                                        List->Items, newCap * sizeof(FE_HOOK_ENTRY));
                                    if (!p)
                                        return;
                                    List->Items = p;
                                    List->Capacity = newCap;
                                }
                                e = &List->Items[List->Count++];
                                ZeroMemory(e, sizeof(*e));
                                sprintf_s(e->Owner, sizeof(e->Owner), "%s", ModuleName);
                                e->IatAddress = iatAddr + k * 8;
                                e->Target = target;
                                /* 【必须用可截断版本】导入名长度不受控，
                                   拼上 expected/got 两个 16 位十六进制后
                                   很容易超过 TargetModule[64]，而 MSVC 的
                                   sprintf_s 溢出会调用 invalid parameter
                                   handler 直接终止进程（实测扫描在此崩溃）。 */
                                _snprintf_s(e->TargetModule, sizeof(e->TargetModule),
                                            _TRUNCATE,
                                            "!%s (expected %016I64X)",
                                            impName,
                                            (unsigned __int64)expected);
                            }
                        }
                    }
                }
            }
            free(impNameBlob);
        }
    }
    free(dllNameBlob);
}

/* 判断 [rva, rva+len) 区间内哪些字节被重定位项覆盖。
 *
 * 为什么必须做这个：ASLR 下模块实际加载基址 != 首选基址，PE 加载器会把
 * 所有重定位项指向的绝对地址搬移。磁盘上是"首选基址下的值"，内存里是
 * "实际基址下的值"，两者必然不同——naive memcmp 会把这些位置报成
 * inline hook，是纯误报。
 *
 * 实测（本机 Win10 18362）：ntdll/kernel32/user32 等系统 DLL 的
 * 全部重定位项都落在 .rdata/.data（最小 RVA 0x133008，而 .text 结束于
 * 0x12F1EE），**代码段内一个重定位都没有**，因为 x64 用 RIP 相对寻址。
 * 所以对系统 DLL 而言这条防护当前命中率为 0。
 * 但第三方 DLL、32 位混合模块、以及未来 Windows 版本仍可能出现
 * 代码段重定位（例如 x86 的 call [__imp_x] 已是 RIP 相对，但
 * 手写汇编/特定编译器会生成绝对地址），故必须保留这条判断。
 *
 * 返回：写入 Mask[] 的字节数（Mask[i]=1 表示该字节是重定位目标）。
 *       Mask 大小需 >= len。
 */
static void FeBuildRelocMask(const BYTE *pView, const IMAGE_NT_HEADERS64 *dNt,
                             const IMAGE_SECTION_HEADER *pSec, DWORD secCount,
                             DWORD rva, int len, BYTE *Mask)
{
    IMAGE_DATA_DIRECTORY d = dNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD off = 0;
    int i;

    for (i = 0; i < len; i++)
        Mask[i] = 0;

    if (d.VirtualAddress == 0 || d.Size == 0)
        return;                                  /* 无重定位表（如 /FIXED） */

    /* 重定位表本身是 RVA，先换算到文件偏移 */
    {
        DWORD s, relOff = 0;
        BOOL ok = FALSE;
        for (s = 0; s < secCount; s++) {
            DWORD va = pSec[s].VirtualAddress;
            DWORD vs = pSec[s].Misc.VirtualSize ? pSec[s].Misc.VirtualSize
                                                : pSec[s].SizeOfRawData;
            if (d.VirtualAddress >= va && d.VirtualAddress < va + vs) {
                DWORD delta = d.VirtualAddress - va;
                if (delta < pSec[s].SizeOfRawData) {
                    relOff = pSec[s].PointerToRawData + delta;
                    ok = TRUE;
                }
                break;
            }
        }
        if (!ok)
            return;

        while (off + sizeof(IMAGE_BASE_RELOCATION) <= d.Size) {
            const IMAGE_BASE_RELOCATION *blk =
                (const IMAGE_BASE_RELOCATION *)(pView + relOff + off);
            DWORD bs = blk->SizeOfBlock;
            DWORD pageRva;
            int n;
            const WORD *ent;

            if (bs < sizeof(IMAGE_BASE_RELOCATION) || off + bs > d.Size)
                break;
            pageRva = blk->VirtualAddress;
            n = (int)((bs - sizeof(IMAGE_BASE_RELOCATION)) / 2);
            ent = (const WORD *)((const BYTE *)blk + sizeof(IMAGE_BASE_RELOCATION));

            for (i = 0; i < n; i++) {
                int type = ent[i] >> 12;
                DWORD r;
                if (type == 0)                   /* IMAGE_REL_BASED_ABSOLUTE：仅填充 */
                    continue;
                r = pageRva + (ent[i] & 0x0FFF);
                /* 重定位通常改 8 字节（DIR64）；HIGHLOW 改 4 字节。
                   统一按 8 字节标记，宁可多标记不漏标记。 */
                {
                    DWORD k;
                    for (k = 0; k < 8; k++) {
                        DWORD pos = r + k;
                        if (pos >= rva && pos < rva + (DWORD)len)
                            Mask[pos - rva] = 1;
                    }
                }
            }
            off += bs;
        }
    }
}

/* 扫描模块导出函数入口的 inline hook。
 *
 * 判据：从磁盘上的模块文件读出导出函数的「原始首字节」，
 * 与目标进程内存里同一函数的当前首字节比对。
 *
 * 只检查导出函数（有名字、可定位），不做全 .text 逐字节比对——
 * 后者在没有完整重定位基线时误报率极高（重定位项、CFG、hotpatch 填充
 * 都会造成合法差异）。这与原版 CCodeHookDialog 的口径一致：按导出名定位。
 *
 * 过滤掉几类已知的合法差异，避免误报：
 *   - **重定位项覆盖的字节**：ASLR 搬移地址，磁盘值与内存值必然不同
 *   - 首字节为 0xCC / 0x90：编译器 hotpatch padding 或 int3 填充
 *   - 内存不可读（跨页/换页）
 *   - 磁盘偏移换算失败
 */
static void FeScanModuleInline(HANDLE hProc, ULONG64 ModuleBase, const char *ModuleName,
                               const char *DiskPath, FE_HOOK_LIST *List, ULONG MaxHooks)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    const BYTE *pView = NULL;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY expDir;
    DWORD secCount;

    if (List->Count >= MaxHooks)
        return;
    if (!DiskPath || !DiskPath[0])
        return;

    /* 1) 拿内存里的 PE 头，定位导出表 */
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)ModuleBase, &dos, sizeof(dos), NULL))
        return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(ModuleBase + dos.e_lfanew),
                           &nt, sizeof(nt), NULL))
        return;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return;
    expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0)
        return;

    /* 2) 把磁盘上的模块映射进来作基线 */
    hFile = CreateFileA(DiskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap)
        goto done;
    pView = (const BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pView)
        goto done;

    {
        const IMAGE_DOS_HEADER *dDos = (const IMAGE_DOS_HEADER *)pView;
        const IMAGE_NT_HEADERS64 *dNt;
        const IMAGE_SECTION_HEADER *pSec;
        const IMAGE_EXPORT_DIRECTORY *pExp;
        const DWORD *pNames;
        const WORD *pOrds;
        const DWORD *pFuncs;
        IMAGE_DATA_DIRECTORY dExpDir;
        DWORD i;

        if (dDos->e_magic != IMAGE_DOS_SIGNATURE)
            goto done;
        dNt = (const IMAGE_NT_HEADERS64 *)(pView + dDos->e_lfanew);
        if (dNt->Signature != IMAGE_NT_SIGNATURE)
            goto done;

        /* 【必须用磁盘 PE 自己的导出目录】内存里的 expDir 来自目标进程，
           与磁盘文件可能是不同 build（例如已打过补丁），混用会让
           AddressOfNames 指向垃圾 → 越界读 → 崩溃或卡死。
           这是本轮实测 notepad 扫描 7 秒无输出的根因。 */
        dExpDir = dNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dExpDir.VirtualAddress == 0 || dExpDir.Size == 0)
            goto done;

        secCount = dNt->FileHeader.NumberOfSections;
        pSec = IMAGE_FIRST_SECTION(dNt);

        /* RVA → 文件偏移（导出目录本身也要换算） */
        {
            DWORD s, expOff = 0;
            BOOL expOk = FALSE;
            for (s = 0; s < secCount; s++) {
                DWORD va = pSec[s].VirtualAddress;
                DWORD vs = pSec[s].Misc.VirtualSize ? pSec[s].Misc.VirtualSize
                                                    : pSec[s].SizeOfRawData;
                if (dExpDir.VirtualAddress >= va && dExpDir.VirtualAddress < va + vs) {
                    if (dExpDir.VirtualAddress - va + dExpDir.Size > pSec[s].SizeOfRawData)
                        goto done;
                    expOff = pSec[s].PointerToRawData + (dExpDir.VirtualAddress - va);
                    expOk = TRUE;
                    break;
                }
            }
            if (!expOk)
                goto done;
            pExp = (const IMAGE_EXPORT_DIRECTORY *)(pView + expOff);
        }

        /* 三张表的 RVA 也各自换算到文件偏移 */
        {
            DWORD s, offNames = 0, offOrds = 0, offFuncs = 0;
            BOOL okN = FALSE, okO = FALSE, okF = FALSE;
            for (s = 0; s < secCount; s++) {
                DWORD va = pSec[s].VirtualAddress;
                DWORD vs = pSec[s].Misc.VirtualSize ? pSec[s].Misc.VirtualSize
                                                    : pSec[s].SizeOfRawData;
                DWORD d;
                if (!okN && pExp->AddressOfNames >= va && pExp->AddressOfNames < va + vs) {
                    d = pExp->AddressOfNames - va;
                    if (d + pExp->NumberOfNames * 4 <= pSec[s].SizeOfRawData) {
                        offNames = pSec[s].PointerToRawData + d;
                        okN = TRUE;
                    }
                }
                if (!okO && pExp->AddressOfNameOrdinals >= va && pExp->AddressOfNameOrdinals < va + vs) {
                    d = pExp->AddressOfNameOrdinals - va;
                    if (d + pExp->NumberOfNames * 2 <= pSec[s].SizeOfRawData) {
                        offOrds = pSec[s].PointerToRawData + d;
                        okO = TRUE;
                    }
                }
                if (!okF && pExp->AddressOfFunctions >= va && pExp->AddressOfFunctions < va + vs) {
                    d = pExp->AddressOfFunctions - va;
                    if (d + pExp->NumberOfFunctions * 4 <= pSec[s].SizeOfRawData) {
                        offFuncs = pSec[s].PointerToRawData + d;
                        okF = TRUE;
                    }
                }
            }
            if (!okN || !okO || !okF)
                goto done;
            pNames = (const DWORD *)(pView + offNames);
            pOrds = (const WORD *)(pView + offOrds);
            pFuncs = (const DWORD *)(pView + offFuncs);

            if (g_Ring3DiagVerbose) {
                printf("      [v] %s: nfun=%lu nname=%lu expRva=0x%X offN=0x%X offO=0x%X offF=0x%X\n",
                       ModuleName, pExp->NumberOfFunctions, pExp->NumberOfNames,
                       dExpDir.VirtualAddress, offNames, offOrds, offFuncs);
                fflush(stdout);
            }
        }

        /* 每个模块最多看 400 个导出函数，避免超长耗时 */
        for (i = 0; i < pExp->NumberOfNames && i < 400 && List->Count < MaxHooks; i++) {
            DWORD funcRva;
            ULONG64 memAddr;
            BYTE mem16[16];
            SIZE_T got = 0;
            const BYTE *diskBytes;
            DWORD s;
            DWORD fileOff = 0;
            BOOL mapped = FALSE;

            /* 序号必须落在 NumberOfFunctions 内 */
            if (pOrds[i] >= pExp->NumberOfFunctions)
                continue;
            funcRva = pFuncs[pOrds[i]];

            /* 跳过转发导出（RVA 落在导出目录内） */
            if (funcRva >= dExpDir.VirtualAddress &&
                funcRva < dExpDir.VirtualAddress + dExpDir.Size)
                continue;
            if (funcRva == 0)
                continue;

            /* RVA → 文件偏移；同时记录该导出所在节的属性。
               **必须落在可执行节**——数据节里的字节可能恰好像指令
              （实测 NlsAnsiCodePage 在 .data 里、首字节 0xE9，
               被误报成 inline hook）。 */
            for (s = 0; s < secCount; s++) {
                DWORD va = pSec[s].VirtualAddress;
                DWORD vs = pSec[s].Misc.VirtualSize ? pSec[s].Misc.VirtualSize
                                                    : pSec[s].SizeOfRawData;
                if (funcRva >= va && funcRva < va + vs) {
                    DWORD delta = funcRva - va;
                    if (delta + 16 > pSec[s].SizeOfRawData)
                        break;
                    /* IMAGE_SCN_MEM_EXECUTE (0x20000000) 必须置位 */
                    if (!(pSec[s].Characteristics & 0x20000000))
                        break;
                    fileOff = pSec[s].PointerToRawData + delta;
                    mapped = TRUE;
                    break;
                }
            }
            if (!mapped)
                continue;

            diskBytes = pView + fileOff;

            /* 诊断：前 8 个函数打印地址与首字节，用于核对扫描是否走到目标函数 */
            if (g_Ring3DiagVerbose && i < 8) {
                printf("      [v] i=%lu rva=0x%X mem=%016I64X disk0=%02X\n",
                       i, funcRva, ModuleBase + funcRva, diskBytes[0]);
                fflush(stdout);
            }

            /* 读内存里同一函数的当前首 16 字节 */
            memAddr = ModuleBase + funcRva;
            if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)memAddr,
                                   mem16, sizeof(mem16), &got))
                continue;
            if (got < 16)
                continue;

            /* hotpatch / 填充：这些首字节不参与判断 */
            if (mem16[0] == 0xCC || mem16[0] == 0x90)
                continue;
            if (diskBytes[0] == 0xCC || diskBytes[0] == 0x90)
                continue;

            /* 判据说明：
               前面已经用「导出必须落在可执行节」过滤掉了数据导出
               （KiUserInvertedFunctionTable / NlsAnsiCodePage 等在 .data/.rdata，
                内存初始化后差异属正常）。因此这里**不再按首字节白名单**过滤
               —— 那会漏掉 LEA(0x8D)、MOV(0x8D/0xA1) 等大量合法序言。
               实测教训：早期版本的白名单不含 0x8D，导致一个真实的
               inline hook（HookTargetAdd 首字节 8D）被漏检。 */

            /* 重定位感知比对：跳过被重定位项覆盖的字节。
               ASLR 下这些位置的磁盘值（首选基址）与内存值（实际基址）
               必然不同，直接 memcmp 会把它们全报成 hook。 */
            {
                BYTE relocMask[16];
                int m;
                BOOL differ = FALSE;

                FeBuildRelocMask(pView, dNt, pSec, secCount, funcRva, 16, relocMask);
                for (m = 0; m < 16; m++) {
                    if (relocMask[m])
                        continue;
                    if (mem16[m] != diskBytes[m]) {
                        differ = TRUE;
                        break;
                    }
                }
                if (!differ)
                    continue;
            }

            {
                FE_HOOK_ENTRY *e;
                /* pNames[i] 是 RVA，必须换算成文件偏移才能当指针用 */
                const char *fnName = "(unknown)";
                DWORD nameRva = pNames[i];
                DWORD ns;
                for (ns = 0; ns < secCount; ns++) {
                    DWORD va = pSec[ns].VirtualAddress;
                    DWORD vs = pSec[ns].Misc.VirtualSize ? pSec[ns].Misc.VirtualSize
                                                         : pSec[ns].SizeOfRawData;
                    if (nameRva >= va && nameRva < va + vs) {
                        DWORD d = nameRva - va;
                        if (d < pSec[ns].SizeOfRawData)
                            fnName = (const char *)(pView + pSec[ns].PointerToRawData + d);
                        break;
                    }
                }

                if (List->Count >= List->Capacity) {
                    ULONG newCap = List->Capacity ? List->Capacity * 2 : 32;
                    FE_HOOK_ENTRY *p = (FE_HOOK_ENTRY *)realloc(
                        List->Items, newCap * sizeof(FE_HOOK_ENTRY));
                    if (!p)
                        break;
                    List->Items = p;
                    List->Capacity = newCap;
                }
                e = &List->Items[List->Count++];
                ZeroMemory(e, sizeof(*e));
                sprintf_s(e->Owner, sizeof(e->Owner), "%s", ModuleName);
                sprintf_s(e->TargetModule, sizeof(e->TargetModule), "%s!%s",
                          ModuleName, fnName);
                e->IatAddress = memAddr;
                e->Target = memAddr;
            }
        }
    }

done:
    if (pView)
        UnmapViewOfFile(pView);
    if (hMap)
        CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
}

/* 取某模块在磁盘上的路径（用于读原始字节作基线）。 */
static BOOL FeGetModuleDiskPath(HANDLE hProc, ULONG Pid, const FE_HOOK_RANGE *R,
                                char *Out, size_t OutChars)
{
    char full[MAX_PATH];
    DWORD n;
    Out[0] = 0;

    /* 先按「进程映像路径 + 模块名」拼（对主模块可靠） */
    n = GetModuleFileNameExA(hProc, (HMODULE)(ULONG_PTR)R->Base, full, sizeof(full));
    if (n && n < sizeof(full)) {
        strcpy_s(Out, OutChars, full);
        return TRUE;
    }
    /* 回退：system32 下同名文件（对系统 DLL 通常成立） */
    GetSystemDirectoryA(full, sizeof(full));
    strcat_s(full, sizeof(full), "\\");
    strcat_s(full, sizeof(full), R->Name);
    if (GetFileAttributesA(full) != INVALID_FILE_ATTRIBUTES) {
        strcpy_s(Out, OutChars, full);
        return TRUE;
    }
    return FALSE;
}

BOOL FeScanRing3Hooks(ULONG Pid, FE_HOOK_LIST *List)
{
    FE_HOOK_RANGE *ranges = NULL;
    ULONG rangeCount = 0;
    HANDLE hProc;
    ULONG i;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Capacity = 0;
    List->Items = NULL;
    List->Ring0Blocked = 1;          /* Ring0 侧当前受阻，见文件头说明 */

    FeExpMapsReset();                /* 清导出映射缓存（目标进程/模块可能已变） */

    g_Ring3DiagVerbose = GetEnvironmentVariableA("XPCH_INLINE_VERBOSE", NULL, 0) > 0;
    /* B 类默认开启；XPCH_IAT_NO_DEEP=1 可关闭（排查异常镜像用）。 */
    g_Ring3DiagIatDeep = GetEnvironmentVariableA("XPCH_IAT_NO_DEEP", NULL, 0) ? 0 : 1;

    if (!FeLoadModuleRanges(Pid, &ranges, &rangeCount))
        return FALSE;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        FALSE, Pid);
    if (!hProc) {
        free(ranges);
        return FALSE;
    }

    for (i = 0; i < rangeCount && List->Count < FE_HOOK_MAX; i++) {
        if (!ranges[i].Base)
            continue;
        FeScanModuleIat(hProc, ranges, rangeCount, ranges[i].Base,
                        ranges[i].Name, List, FE_HOOK_MAX);
    }
    if (g_Ring3DiagVerbose) {
        printf("    [diag] IAT pass done, %lu entries\n", List->Count);
        fflush(stdout);
    }

    /* 第二轮：导出函数 inline hook（对应原版 CCodeHookDialog 的口径）。
       只对有磁盘文件的模块做，跳过后台无文件的映像。
       实测：每个模块要 CreateFileMapping + MapViewOfFile + 最多 400 次
       ReadProcessMemory，在 Services 会话下单个模块就可能阻塞数秒。
       默认只扫**主模块**（EnumProcessModulesEx 第一项，即目标 exe 本身）
       —— inline hook 最主要的落点，响应时间 <2s。
       需要覆盖更多模块时设环境变量 XPCH_INLINE_MODULES=<n>（最多 64）。 */
    {
        ULONG inlineScanned = 0;
        ULONG limit = 1;
        char envBuf[16];
        DWORD envLen = GetEnvironmentVariableA("XPCH_INLINE_MODULES", envBuf, sizeof(envBuf));
        if (envLen > 0 && envLen < sizeof(envBuf)) {
            ULONG v = (ULONG)strtoul(envBuf, NULL, 0);
            if (v > 0 && v <= 64)
                limit = v;
        }
        for (i = 0; i < rangeCount && inlineScanned < limit && List->Count < FE_HOOK_MAX; i++) {
            char diskPath[MAX_PATH];
            if (!ranges[i].Base || !ranges[i].Name[0])
                continue;
            if (!FeGetModuleDiskPath(hProc, Pid, &ranges[i], diskPath, sizeof(diskPath)))
                continue;
            if (g_Ring3DiagVerbose) {
                printf("    [diag] inline-scan %s (%s)\n", ranges[i].Name, diskPath);
                fflush(stdout);
            }
            FeScanModuleInline(hProc, ranges[i].Base, ranges[i].Name, diskPath,
                               List, FE_HOOK_MAX);
            inlineScanned++;
        }
        g_Ring3DiagModules = rangeCount;
        g_Ring3DiagInlineScanned = inlineScanned;
    }

    CloseHandle(hProc);
    free(ranges);
    FeExpMapsReset();
    return TRUE;
}

void FeFreeHooks(FE_HOOK_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 展示格式沿用原版的 `%s-->Ring3 Hook`。 */
BOOL FePrintRing3Hooks(ULONG Pid)
{
    FE_HOOK_LIST list;
    ULONG i;

    printf("scanning pid %lu ...\n", Pid);
    fflush(stdout);
    if (!FeScanRing3Hooks(Pid, &list)) {
        printf("ring3 hooks: cannot scan pid %lu, GetLastError=%lu\n", Pid, GetLastError());
        fflush(stdout);
        return FALSE;
    }
    /* 【修正 2026-10-22】原先这里打印三行"blocked: driver hook-table chain
       incomplete / ParseSyscallTableExportDir is a stub; 6 callees missing"。
       那是 2026-10-21 的过期状态：现在 ParseSyscallTableExportDir 已按伪代码
       完整转写（SsdtHook.c:1444，7 个调用方全部实现），而 Ring0 页的数据走
       0x117（908 条，已实测），与本链条无关。留着"is a stub"会误导使用者。 */
    printf("=== Ring0 Hooks (pid %lu): see the Ring0 page, data via cmd 0x117 ===\n", Pid);
    printf("=== Ring3 Hooks (pid %lu): %lu entries (IAT + inline) ===\n", Pid, list.Count);
    if (g_Ring3DiagVerbose) {
        printf("    [diag] modules=%lu, inline-scanned=%lu\n",
               g_Ring3DiagModules, g_Ring3DiagInlineScanned);
    }
    for (i = 0; i < list.Count; i++) {
        const char *tm = list.Items[i].TargetModule;

        /* 三类，靠 TargetModule 的形态区分：
             "Module!Func"          -> inline hook
             "!Name (expected ...)" -> 同模块 IAT 劫持（B 类）
             其它（如 "(outside..."）-> 导入指向模块外（A 类） */
        if (strstr(tm, "(outside all modules)")) {
            printf("%s-->Ring3 IAT Hijack (outside)  iat=%016I64X  target=%016I64X\n",
                   list.Items[i].Owner, list.Items[i].IatAddress,
                   list.Items[i].Target);
        } else if (tm[0] == '!') {
            printf("%s-->Ring3 IAT Hijack (same-module)  iat=%016I64X  %s\n",
                   list.Items[i].Owner, list.Items[i].IatAddress, tm);
        } else {
            printf("%s-->Ring3 Inline Hook  fn=%s\n",
                   list.Items[i].Owner, tm);
        }
    }
    if (list.Count == 0)
        printf("(no IAT hijack, no inline-patched exports)\n");
    /* GUI 子系统程序的 stdout 是缓冲的，进程退出时若不显式 flush，
       重定向到文件/管道时会丢内容（这是本轮实测踩到的）。 */
    fflush(stdout);
    FeFreeHooks(&list);
    return TRUE;
}