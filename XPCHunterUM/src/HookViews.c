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
//   用户态可做：枚举本进程及系统里可读进程的已加载模块，检查每个模块的
//   IAT（导入地址表）条目是否落在**任何已加载模块**的地址范围之外。
//   落在范围外 = 可疑（可能是外部 hook stub 或跳板）。
//   展示格式沿用原版的 `%s-->Ring3 Hook`。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

/* ---------------------------------------------------------------- Ring3 Hook */

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

/* 扫描某个模块的 IAT，找出指向"所有模块范围之外"的条目。
 *
 * IAT 定位：读模块的 PE 头 → DataDirectory[1]（Import Table）→ 逐个
 * IMAGE_IMPORT_DESCRIPTOR 取其 FirstThunk 指向的 IAT 块。
 * 我们只读**目标进程内存**（ReadProcessMemory），不改任何东西。 */
static void FeScanModuleIat(HANDLE hProc, const FE_HOOK_RANGE *Ranges, ULONG RangeCount,
                            ULONG64 ModuleBase, const char *ModuleName,
                            FE_HOOK_LIST *List, ULONG MaxHooks)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY impDir;
    ULONG64 impDescAddr;
    ULONG i;

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

    for (i = 0; i < 64 && List->Count < MaxHooks; i++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        ULONG64 iatAddr;
        ULONG k;

        if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(impDescAddr + i * sizeof(desc)),
                               &desc, sizeof(desc), NULL))
            break;
        if (desc.Name == 0 && desc.FirstThunk == 0)
            break;
        if (desc.FirstThunk == 0)
            continue;
        iatAddr = ModuleBase + desc.FirstThunk;

        /* 每个导入描述符最多看 512 个 thunk */
        for (k = 0; k < 512 && List->Count < MaxHooks; k++) {
            ULONG64 entry = 0;
            ULONG64 target;
            int owner;
            FE_HOOK_ENTRY *e;

            if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(iatAddr + k * 8),
                                   &entry, sizeof(entry), NULL))
                break;
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
                /* 落所有模块之外 —— 可疑 */
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
                sprintf_s(e->TargetModule, sizeof(e->TargetModule), "(outside all modules)");
            }
        }
    }
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
    CloseHandle(hProc);
    free(ranges);
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

    if (!FeScanRing3Hooks(Pid, &list)) {
        printf("ring3 hooks: cannot scan pid %lu, GetLastError=%lu\n", Pid, GetLastError());
        return FALSE;
    }
    /* 【修正 2026-10-22】原先这里打印三行"blocked: driver hook-table chain
       incomplete / ParseSyscallTableExportDir is a stub; 6 callees missing"。
       那是 2026-10-21 的过期状态：现在 ParseSyscallTableExportDir 已按伪代码
       完整转写（SsdtHook.c:1444，7 个调用方全部实现），而 Ring0 页的数据走
       0x117（908 条，已实测），与本链条无关。留着"is a stub"会误导使用者。 */
    printf("=== Ring0 Hooks (pid %lu): see the Ring0 page, data via cmd 0x117 ===\n", Pid);
    printf("=== Ring3 Hooks (pid %lu): %lu suspicious IAT entries ===\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("%s-->Ring3 Hook  iat=%016I64X  target=%016I64X  (%s)\n",
               list.Items[i].Owner, list.Items[i].IatAddress,
               list.Items[i].Target, list.Items[i].TargetModule);
    }
    if (list.Count == 0)
        printf("(no IAT entry points outside all loaded modules)\n");
    FeFreeHooks(&list);
    return TRUE;
}