/* ============================================================================
 * XpchSdkSample.c —— XpchSdk 使用示例
 *
 * 演示：打开会话 → 查构建号 → 枚举进程 → 查内核模块 → 查 SSDT 钩子。
 *
 * 编译（在仓库根执行，需先跑 build\build_sdk.bat）：
 *   cl /nologo /Fe:demo.exe XpchSdkSample.c ^
 *      /I..\sdk\inc ..\..\build\bin\Release\sdk_x64\XpchSdk.lib ^
 *      advapi32.lib wintrust.lib crypt32.lib psapi.lib
 * ==========================================================================*/
#include "XpchSdk.h"
#include <stdio.h>

static void PrintStatus(const char *What, XPCH_STATUS St)
{
    WCHAR Txt[256];
    char  Ansi[512];

    /* XpchStatusText 返回宽字符中文；控制台代码页未必是 UTF-8，
       统一转成 ACP 再打印，避免在某些代码页下变乱码。 */
    lstrcpynW(Txt, XpchStatusText(St), 256);
    if (!XpchUtf16ToAnsi(Txt, Ansi, sizeof(Ansi)))
        strcpy_s(Ansi, sizeof(Ansi), "(conversion failed)");
    printf("%-28s : [%d] %s\n", What, (int)St, Ansi);
}

int main(void)
{
    XPCH_SESSION Session;
    XPCH_STATUS St;
    ULONG Build = 0;
    XPCH_PROCESS_INFO *Procs = NULL;
    ULONG ProcCount = 0;
    XPCH_KERNEL_MODULE *KMods = NULL;
    ULONG KModCount = 0;
    XPCH_SSDT_ENTRY *Hooks = NULL;
    ULONG HookCount = 0, Patched = 0;
    ULONG i;

    printf("=== XpchSdk %ws sample ===\n\n", XPCHSDK_VERSION_STRING);

    /* --- 1. 打开会话 --- */
    St = XpchOpen(&Session);
    PrintStatus("XpchOpen", St);
    if (St != XPCH_OK) {
        printf("\nDriver not loaded? Try: sc start XPCHunterDrv\n");
        return 1;
    }

    /* --- 2. 构建号 --- */
    St = XpchGetBuildNumber(&Session, &Build);
    if (St == XPCH_OK)
        printf("%-28s : %lu\n", "Windows build", Build);
    else
        PrintStatus("XpchGetBuildNumber", St);

    /* --- 3. 进程枚举 --- */
    St = XpchEnumProcesses(&Session, &Procs, &ProcCount);
    PrintStatus("XpchEnumProcesses", St);
    if (St == XPCH_OK) {
        printf("  %lu processes, first 8:\n", ProcCount);
        for (i = 0; i < ProcCount && i < 8; i++)
            printf("    PID %-6lu %hs\n", Procs[i].Pid, Procs[i].Name);
        XpchFree(Procs);
    }

    /* --- 4. 内核模块 --- */
    St = XpchEnumKernelModules(&KMods, &KModCount);
    PrintStatus("XpchEnumKernelModules", St);
    if (St == XPCH_OK) {
        printf("  %lu kernel modules, first 5:\n", KModCount);
        for (i = 0; i < KModCount && i < 5; i++)
            printf("    %016I64X  %-24hs %s\n",
                   KMods[i].Base, KMods[i].Name, KMods[i].Path);
        XpchFree(KMods);
    }

    /* --- 5. SSDT 钩子 --- */
    St = XpchEnumSsdtHooks(&Session, &Hooks, &HookCount);
    PrintStatus("XpchEnumSsdtHooks", St);
    if (St == XPCH_OK) {
        for (i = 0; i < HookCount; i++)
            if (Hooks[i].AddressPatched || Hooks[i].BytesPatched)
                Patched++;
        printf("  %lu entries, %lu patched\n", HookCount, Patched);
        if (Patched == 0)
            printf("  (clean, no SSDT hooks)\n");
        else {
            ULONG Shown = 0;
            for (i = 0; i < HookCount && Shown < 10; i++) {
                if (!Hooks[i].AddressPatched && !Hooks[i].BytesPatched)
                    continue;
                printf("    T%lu[%lu] %s  current=%016I64X original=%016I64X\n",
                       Hooks[i].TableIndex, Hooks[i].Index,
                       Hooks[i].BytesPatched ? "PATCHED(inline)" : "PATCHED(addr)",
                       Hooks[i].Current, Hooks[i].Original);
                Shown++;
            }
        }
        XpchFree(Hooks);
    }

    /* --- 6. 读进程内存示例（读自身 PE 头） --- */
    {
        BYTE *Mem = NULL;
        ULONG Read = 0;
        St = XpchReadProcessMemory(&Session, GetCurrentProcessId(),
                                   (ULONG64)(ULONG_PTR)GetModuleHandleW(NULL),
                                   0x40, &Mem, &Read);
        PrintStatus("XpchReadProcessMemory", St);
        if (St == XPCH_OK) {
            printf("  read %lu bytes, first 2 = %02X %02X (expect 4D 5A \"MZ\")\n",
                   Read, Mem[0], Mem[1]);
            XpchFree(Mem);
        }
    }

    XpchClose(&Session);
    printf("\n=== done ===\n");
    return 0;
}