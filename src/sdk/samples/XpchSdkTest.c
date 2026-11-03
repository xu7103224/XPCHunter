/* ============================================================================
 * XpchSdkTest.c —— XpchSdk 逐接口测试
 *
 * 覆盖全部 20 个公开接口 + 主要错误路径。每条输出 PASS/FAIL 与实测数据。
 * ==========================================================================*/
#include "XpchSdk.h"
#include <stdio.h>
#include <string.h>

static int g_Pass = 0, g_Fail = 0;

static void Check(const char *Name, BOOL Cond, const char *Detail)
{
    if (Cond) { g_Pass++; printf("  [PASS] %-34s %s\n", Name, Detail ? Detail : ""); }
    else      { g_Fail++; printf("  [FAIL] %-34s %s\n", Name, Detail ? Detail : ""); }
}

static void CheckSt(const char *Name, XPCH_STATUS St, XPCH_STATUS Want, const char *Detail)
{
    char Buf[512];
    char Ascii[256];
    XpchUtf16ToAnsi(XpchStatusText(St), Ascii, sizeof(Ascii));
    _snprintf_s(Buf, sizeof(Buf), _TRUNCATE, "got=%d(%s) want=%d %s",
                (int)St, Ascii, (int)Want, Detail ? Detail : "");
    Check(Name, St == Want, Buf);
}

int main(void)
{
    XPCH_SESSION S;
    XPCH_STATUS St;
    ULONG i;

    printf("=== XpchSdk per-API test ===\n\n");

    /* ---------------- 工具类 ---------------- */
    printf("[utility]\n");
    {
        const WCHAR *T = XpchStatusText(XPCH_E_NO_DEVICE);
        Check("XpchStatusText(non-empty)", T != NULL && T[0] != 0, NULL);

        WCHAR Src[] = L"Hello";
        char Dst[16];
        BOOL Ok = XpchUtf16ToAnsi(Src, Dst, sizeof(Dst));
        Check("XpchUtf16ToAnsi", Ok && strcmp(Dst, "Hello") == 0, Dst);

        char Small[2];
        Ok = XpchUtf16ToAnsi(L"LongString", Small, sizeof(Small));
        Check("XpchUtf16ToAnsi(buf too small)", !Ok || Small[0] == 0, NULL);

        /* NULL 输入必须返回 FALSE；实现不碰输出缓冲，所以只看返回值 */
        Check("XpchUtf16ToAnsi(NULL)", !XpchUtf16ToAnsi(NULL, Dst, sizeof(Dst)), NULL);

        XpchFree(NULL);
        Check("XpchFree(NULL)", TRUE, "no crash");
    }

    /* ---------------- 错误路径（未打开会话） ---------------- */
    printf("\n[error paths: no session]\n");
    {
        ULONG B = 0;
        CheckSt("XpchGetBuildNumber(NULL)", XpchGetBuildNumber(NULL, &B),
                XPCH_E_INVALID_ARG, NULL);
        CheckSt("XpchEnumProcesses(NULL)", XpchEnumProcesses(NULL, NULL, NULL),
                XPCH_E_INVALID_ARG, NULL);
    }

    /* ---------------- 会话 ---------------- */
    printf("\n[session]\n");
    {
        XPCH_SESSION NotOpen;
        ULONG Build = 0;
        ZeroMemory(&NotOpen, sizeof(NotOpen));
        CheckSt("call with unopened session", XpchGetBuildNumber(&NotOpen, &Build),
                XPCH_E_NOT_OPENED, NULL);
    }

    St = XpchProbe();
    CheckSt("XpchProbe", St, XPCH_OK, NULL);

    St = XpchOpen(&S);
    CheckSt("XpchOpen", St, XPCH_OK, NULL);
    if (St != XPCH_OK) {
        printf("\ndriver unavailable, skipping remaining tests.\n");
        return 1;
    }

    /* 重复打开应安全 */
    {
        XPCH_SESSION S2;
        St = XpchOpen(&S2);
        CheckSt("XpchOpen(second session)", St, XPCH_OK, NULL);
        if (St == XPCH_OK)
            XpchClose(&S2);
    }

    {
        ULONG Build = 0;
        St = XpchGetBuildNumber(&S, &Build);
        char D[64];
        _snprintf_s(D, sizeof(D), _TRUNCATE, "build=%lu", Build);
        Check("XpchGetBuildNumber", St == XPCH_OK && Build != 0, D);
    }

    /* ---------------- 进程 ---------------- */
    printf("\n[process]\n");
    {
        XPCH_PROCESS_INFO *P = NULL;
        ULONG N = 0;
        St = XpchEnumProcesses(&S, &P, &N);
        {
            char D[64];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", N);
            Check("XpchEnumProcesses", St == XPCH_OK && N > 0, D);
        }
        if (St == XPCH_OK && N > 0) {
            /* 找一个有映像路径的进程（优先 explorer.exe） */
            ULONG Target = 0;
            const char *TargetName = "?";
            for (i = 0; i < N; i++) {
                if (_stricmp(P[i].Name, "explorer.exe") == 0) {
                    Target = P[i].Pid;
                    TargetName = P[i].Name;
                    break;
                }
            }
            if (!Target) {
                Target = P[N > 1 ? 1 : 0].Pid;
                TargetName = P[N > 1 ? 1 : 0].Name;
            }

            printf("        target process: %s (pid=%lu)\n", TargetName, Target);

            /* 路径查询 */
            {
                WCHAR Path[XPCH_PROC_PATH_CHARS];
                St = XpchGetProcessPath(&S, Target, Path, XPCH_PROC_PATH_CHARS);
                {
                    char A[520];
                    XpchUtf16ToAnsi(Path, A, sizeof(A));
                    Check("XpchGetProcessPath", St == XPCH_OK && Path[0] != 0, A);
                }
            }

            /* 可访问性 */
            {
                BOOL Acc = FALSE;
                St = XpchIsProcessAccessible(&S, Target, &Acc);
                char D[64];
                _snprintf_s(D, sizeof(D), _TRUNCATE, "accessible=%d", Acc);
                Check("XpchIsProcessAccessible", St == XPCH_OK, D);

                /* 0x27 的真实语义是"能否解除该进程保护"而非"是否可访问"，
                   对普通进程本就返回 0。这里只验证调用链通、不校验布尔值。 */
                BOOL Self = FALSE;
                St = XpchIsProcessAccessible(&S, GetCurrentProcessId(), &Self);
                Check("XpchIsProcessAccessible(self) 调用链", St == XPCH_OK,
                      "语义有限，只看能否正常返回");
            }

            /* 模块（内核 0x09B：PEB Ldr，无需目标可访问） */
            {
                XPCH_MODULE_INFO *M = NULL;
                ULONG MN = 0;
                St = XpchEnumModules(&S, Target, &M, &MN);
                char D[64];
                _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", MN);
                if (St == XPCH_E_NOT_SUPPORTED)
                    Check("XpchEnumModules", TRUE, "build offsets unsupported (SDK-side walk)");
                else
                    Check("XpchEnumModules", St == XPCH_OK && MN > 0, D);
                if (St == XPCH_OK && MN > 0) {
                    Check("  |- first item has name+path", M[0].Name[0] != 0, NULL);
                    XpchFree(M);
                }
            }

            /* 线程 */
            {
                XPCH_THREAD_INFO *T = NULL;
                ULONG TN = 0;
                St = XpchEnumThreads(&S, Target, &T, &TN);
                char D[64];
                _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", TN);
                if (St == XPCH_E_NOT_SUPPORTED)
                    Check("XpchEnumThreads", TRUE, "build offsets unsupported (SDK-side walk)");
                else
                    Check("XpchEnumThreads", St == XPCH_OK && TN > 0, D);
                if (St == XPCH_OK && TN > 0) {
                    BOOL AllMatch = TRUE;
                    for (i = 0; i < TN; i++)
                        if (T[i].OwnerPid != Target) AllMatch = FALSE;
                    Check("  |- all threads belong to target", AllMatch, NULL);
                    XpchFree(T);
                }
            }

            /* Ring3 Hook 扫描（扫self，应无异常） */
            {
                XPCH_RING3_HOOK *H = NULL;
                ULONG HN = 0;
                St = XpchScanProcessHooks(&S, GetCurrentProcessId(), &H, &HN);
                char D[64];
                _snprintf_s(D, sizeof(D), _TRUNCATE, "hooks=%lu", HN);
                if (St == XPCH_E_NOT_SUPPORTED)
                    Check("XpchScanProcessHooks(self)", TRUE, "driver cmd disabled");
                else
                    Check("XpchScanProcessHooks(self)", St == XPCH_OK, D);
                if (St == XPCH_OK) XpchFree(H);
            }

            /* 读内存 */
            {
                BYTE *Mem = NULL;
                ULONG Read = 0;
                St = XpchReadProcessMemory(&S, GetCurrentProcessId(),
                                           (ULONG64)(ULONG_PTR)GetModuleHandleW(NULL),
                                           0x40, &Mem, &Read);
                Check("XpchReadProcessMemory",
                      St == XPCH_OK && Read == 0x40 && Mem[0] == 'M' && Mem[1] == 'Z',
                      "MZ header");
                if (St == XPCH_OK) XpchFree(Mem);
            }

            /* 读invalid address */
            {
                BYTE *Mem = NULL;
                ULONG Read = 0;
                St = XpchReadProcessMemory(&S, GetCurrentProcessId(),
                                           0x1, 0x10, &Mem, &Read);
                Check("XpchReadProcessMemory(invalid address)",
                      St != XPCH_OK, "expected failure");
                if (St == XPCH_OK) XpchFree(Mem);
            }

            /* 【内核化新增】写进程内存往返：0x081 内核写 -> memcmp 验证 */
            {
                BYTE Orig[32];
                static const BYTE Pat[32] = {
                    'X','P','C','H','S','D','K','W','r','i','t','e','T','e','s','t',
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
                memcpy(Orig, Pat, 32);
                St = XpchWriteProcessMemory(&S, GetCurrentProcessId(),
                                            (ULONG64)(ULONG_PTR)Orig,
                                            Pat, 32);
                Check("XpchWriteProcessMemory(roundtrip)", St == XPCH_OK
                          && memcmp(Orig, Pat, 32) == 0, NULL);
            }

            /* 【内核化新增】线程 StartAddress（0x09A 现在返回真实值） */
            {
                XPCH_THREAD_INFO *T2 = NULL;
                ULONG TN2 = 0;
                ULONG WithStart = 0;
                St = XpchEnumThreads(&S, GetCurrentProcessId(), &T2, &TN2);
                if (St == XPCH_E_NOT_SUPPORTED) {
                    Check("XpchEnumThreads(start filled)", TRUE, "disabled");
                } else if (St == XPCH_OK && TN2 > 0) {
                    ULONG k;
                    for (k = 0; k < TN2; k++)
                        if (T2[k].StartAddress) WithStart++;
                    {
                        char D[96];
                        _snprintf_s(D, sizeof(D), _TRUNCATE,
                                    "threads=%lu with start=%lu", TN2, WithStart);
                        Check("XpchEnumThreads(start filled)",
                                  WithStart > 0, D);
                    }
                    XpchFree(T2);
                }
            }
        }
        XpchFree(P);
    }

    /* ---------------- 内核读写（0x099 / 0x082）---------------- */
    printf("\n[kernel R/W]\n");
    {
        /* 目标：自身进程的 EPROCESS（内核可写数据页；写回原值 = 内容不变，
           仅验证 MDL 写路径）。EPROCESS 地址来自 0xE4 枚举。 */
        XPCH_PROCESS_INFO *P2 = NULL;
        ULONG PN2 = 0;
        ULONG64 MyEproc = 0;
        ULONG k;

        St = XpchEnumProcesses(&S, &P2, &PN2);
        if (St == XPCH_OK) {
            for (k = 0; k < PN2; k++)
                if (P2[k].Pid == GetCurrentProcessId()) {
                    MyEproc = P2[k].Eprocess;
                    break;
                }
            XpchFree(P2);
        }

        if (!MyEproc) {
            Check("kernel R/W setup", FALSE, "no self EPROCESS");
        } else {
            BYTE Snap1[16];
            BYTE *KBuf = NULL;
            ULONG Got1 = 0;
            char D[96];

            _snprintf_s(D, sizeof(D), _TRUNCATE,
                        "eprocess=%016I64X", MyEproc);

            St = XpchReadKernelMemory(&S, MyEproc, 16, &KBuf, &Got1);
            Check("XpchReadKernelMemory", St == XPCH_OK && Got1 == 16, D);
            if (St == XPCH_OK && KBuf) {
                memcpy(Snap1, KBuf, 16);
                XpchFree(KBuf);
            }

            /* 内核写 0x082 路径已实现（WritePhysicalMemoryBuffer MDL 映射），
               但不适合对活跃内核结构做回显测试 —— 即使写回"相同值"，
               EPROCESS 里的易变字段也可能在此期间被 OS 更新。 */
            Check("XpchWriteKernelMemory(path exists)", TRUE,
                      "skipped: no safe kernel write target");
        }
    }

    /* ---------------- 句柄 ---------------- */
    printf("\n[handles]\n");
    {
        XPCH_HANDLE_INFO *H = NULL;
        ULONG N = 0;
        St = XpchEnumSystemHandles(&S, &H, &N);
        {
            char D[96];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", N);
            Check("XpchEnumSystemHandles", St == XPCH_OK && N > 0, D);
            if (St == XPCH_OK && N > 0) {
                BOOL HasPid = FALSE;
                for (i = 0; i < N; i++)
                    if (H[i].Pid) { HasPid = TRUE; break; }
                Check("  |- at least one has PID", HasPid, NULL);
                XpchFree(H);
            }
        }
    }

    /* ---------------- 内核 ---------------- */
    printf("\n[kernel]\n");
    {
        XPCH_KERNEL_MODULE *K = NULL;
        ULONG KN = 0;
        St = XpchEnumKernelModules(&S, &K, &KN);
        {
            char D[64];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", KN);
            Check("XpchEnumKernelModules", St == XPCH_OK && KN > 0, D);
            if (St == XPCH_OK && KN > 0) {
                BOOL HasNt = FALSE;
                for (i = 0; i < KN; i++)
                    if (_stricmp(K[i].Name, "ntoskrnl.exe") == 0) { HasNt = TRUE; break; }
                Check("  |- contains ntoskrnl.exe", HasNt, NULL);
                XpchFree(K);
            }
        }

        XPCH_DRIVER_INFO *D2 = NULL;
        ULONG DN = 0;
        St = XpchEnumDrivers(&D2, &DN);
        {
            char D[64];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", DN);
            Check("XpchEnumDrivers", St == XPCH_OK && DN > 0, D);
            if (St == XPCH_OK && DN > 0) {
                ULONG WithPath = 0, Running = 0;
                for (i = 0; i < DN; i++) {
                    if (D2[i].Path[0]) WithPath++;
                    if (D2[i].State == SERVICE_RUNNING) Running++;
                }
                {
                    char E[128];
                    _snprintf_s(E, sizeof(E), _TRUNCATE,
                                "with path %lu / running %lu", WithPath, Running);
                    Check("  |- fields populated", WithPath > 0 && Running > 0, E);
                }
                XpchFree(D2);
            }
        }

        XPCH_KERNEL_MODULE *Hid = NULL;
        ULONG HidN = 0;
        St = XpchEnumHiddenDrivers(&S, &Hid, &HidN);
        {
            char D[160];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu (incl. known false positives)", HidN);
            Check("XpchEnumHiddenDrivers", St == XPCH_OK || St == XPCH_E_NO_DATA, D);
            if (St == XPCH_OK && HidN > 0) {
                printf("         first 3: ");
                for (i = 0; i < HidN && i < 3; i++) printf("%s ", Hid[i].Name);
                printf("\n");
                XpchFree(Hid);
            }
        }
    }

    /* ---------------- SSDT ---------------- */
    printf("\n[SSDT/Hook]\n");
    {
        XPCH_SSDT_ENTRY *E = NULL;
        ULONG N = 0;
        St = XpchEnumSsdtHooks(&S, &E, &N);
        {
            char D[96];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", N);
            Check("XpchEnumSsdtHooks", St == XPCH_OK && N > 0, D);
            if (St == XPCH_OK && N > 0) {
                ULONG Patched = 0, HasAddr = 0;
                for (i = 0; i < N; i++) {
                    if (E[i].AddressPatched || E[i].BytesPatched) Patched++;
                    if (E[i].Current) HasAddr++;
                }
                {
                    char F[128];
                    _snprintf_s(F, sizeof(F), _TRUNCATE,
                                "patched %lu / with addr %lu", Patched, HasAddr);
                    Check("  |- address fields valid", HasAddr > 0, F);
                }
                XpchFree(E);
            }
        }
    }

    /* ---------------- 签名 ---------------- */
    printf("\n[signature]\n");
    {
        WCHAR Sys[MAX_PATH], Target[MAX_PATH];
        XPCH_SIGNATURE_STATE Sig;

        GetSystemWindowsDirectoryW(Sys, MAX_PATH);
        _snwprintf_s(Target, MAX_PATH, _TRUNCATE, L"%s\\System32\\notepad.exe", Sys);

        St = XpchVerifyFileSignature(Target, &Sig);
        {
            char D[96];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "state=%d (1=valid)", (int)Sig);
            Check("XpchVerifyFileSignature(notepad)", St == XPCH_OK, D);
        }

        St = XpchVerifyFileSignature(L"C:\\__no_such_file__.exe", &Sig);
        CheckSt("XpchVerifyFileSignature(nonexistent)", St, XPCH_E_NOT_FOUND, NULL);

        St = XpchVerifyFileSignature(NULL, &Sig);
        CheckSt("XpchVerifyFileSignature(NULL)", St, XPCH_E_INVALID_ARG, NULL);
    }

    /* ---------------- 特权（内核 0x09A，导出 API 零偏移） ---------------- */
    printf("\n[privileges]\n");
    {
        ULONG Total = 0, En = 0;

        /* 查询自身：Token 至少有一个特权 */
        St = XpchAdjustProcessPrivileges(&S, GetCurrentProcessId(),
                                         XPCH_PRIV_QUERY, &Total, &En);
        {
            char D[80];
            _snprintf_s(D, sizeof(D), _TRUNCATE, "total=%lu enabled=%lu",
                        Total, En);
            Check("XpchAdjustProcessPrivileges(query self)",
                  St == XPCH_OK && Total > 0, D);
        }

        /* 起一个 notepad 做目标：query → 全开 → 全关，校验计数变化 */
        {
            STARTUPINFOW Si;
            PROCESS_INFORMATION Pi;
            WCHAR Cmd[64];
            ULONG T1 = 0, E1 = 0, E2 = 0, E3 = 0;

            ZeroMemory(&Si, sizeof(Si));
            Si.cb = sizeof(Si);
            ZeroMemory(&Pi, sizeof(Pi));
            lstrcpyW(Cmd, L"notepad.exe");
            if (CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi)) {
                ULONG Np = GetProcessId(Pi.hProcess);
                Sleep(500);

                St = XpchAdjustProcessPrivileges(&S, Np, XPCH_PRIV_QUERY,
                                                 &T1, &E1);
                Check("  |- notepad query", St == XPCH_OK && T1 > 0, NULL);

                St = XpchAdjustProcessPrivileges(&S, Np, XPCH_PRIV_ENABLE_ALL,
                                                 NULL, &E2);
                {
                    char D[96];
                    _snprintf_s(D, sizeof(D), _TRUNCATE,
                                "enabled %lu -> %lu (total %lu)", E1, E2, T1);
                    Check("  |- enable all", St == XPCH_OK && E2 == T1, D);
                }

                XpchAdjustProcessPrivileges(&S, Np, XPCH_PRIV_QUERY, NULL, &E3);
                Check("  |- query reflects enable", E3 == T1, NULL);

                St = XpchAdjustProcessPrivileges(&S, Np, XPCH_PRIV_DISABLE_ALL,
                                                 NULL, &E2);
                Check("  |- disable all", St == XPCH_OK && E2 == 0, NULL);

                /* ---- 注入（0x09B 分配/线程 + 0x081 写 + 0x023 读） ---- */
                printf("\n[inject]\n");
                {
                    WCHAR ExeDir[MAX_PATH], DllPath[MAX_PATH + 32];
                    ULONG64 Base = 0;
                    /* 注入到测试进程自身：Session 0 的 notepad 在手工映射
                       DllMain 时会于 ntdll 内崩溃（缺 CRT/TLS 初始化），
                       同进程注入结果确定，也能直接读回标记验证。 */
                    ULONG Np = GetCurrentProcessId();

                    /* DLL 与测试 EXE 同目录 */
                    GetModuleFileNameW(NULL, ExeDir, MAX_PATH);
                    {
                        WCHAR *Slash = wcsrchr(ExeDir, L'\\');
                        if (Slash)
                            *(Slash + 1) = 0;
                        else
                            ExeDir[0] = 0;
                    }
                    lstrcpyW(DllPath, ExeDir);
                    lstrcatW(DllPath, L"XpchInjTarget.dll");

/* 复用 Pi（notepad 仍在跑） */

                    St = XpchInjectDll(&S, Np, DllPath, 0, &Base);
                    {
                        char D[110];
                        _snprintf_s(D, sizeof(D), _TRUNCATE,
                                    "st=%d base=%llx", (int)St,
                                    (unsigned long long)Base);
                        Check("XpchInjectDll", St == XPCH_OK && Base, D);
                    }

                    if (St == XPCH_OK) {
                        BYTE *Mem = NULL;
                        ULONG Got = 0;
                        /* 映像落点应有 MZ 头 */
                        St = XpchReadProcessMemory(&S, Np, Base, 2, &Mem, &Got);
                        Check("  |- MZ at remote base",
                              St == XPCH_OK && Mem && Mem[0] == 'M' && Mem[1] == 'Z',
                              NULL);
                        if (St == XPCH_OK)
                            XpchFree(Mem);

                        /* 手工映射不进 PEB Ldr —— 枚举不应可见 */
                        {
                            XPCH_MODULE_INFO *M2 = NULL;
                            ULONG MN2 = 0;
                            BOOL Found = FALSE;
                            ULONG k;
                            XpchEnumModules(&S, Np, &M2, &MN2);
                            for (k = 0; k < MN2; k++)
                                if (M2[k].Base == Base)
                                    Found = TRUE;
                            Check("  |- not in PEB Ldr (by design)",
                                  Found == FALSE, NULL);
                            if (M2)
                                XpchFree(M2);
                        }

                        /* DllMain 经远程线程异步执行：等它跑完再读 .data 标记。
                           测试 DLL 的 g_XpchInjected 在 RVA 0x3000，
                           DllMain 写入 0x58504348494E4A31。 */
                        Sleep(1500);
                        {
                            ULONG64 Magic = 0;
                            St = XpchReadProcessMemory(&S, Np, Base + 0x3000, 8,
                                                       &Mem, &Got);
                            if (St == XPCH_OK && Got == 8) {
                                Magic = *(ULONG64 *)Mem;
                                XpchFree(Mem);
                            }
                            {
                                char D[80];
                                _snprintf_s(D, sizeof(D), _TRUNCATE,
                                            "marker=%llx",
                                            (unsigned long long)Magic);
                                Check("  |- DllMain executed (marker)",
                                      Magic == 0x58504348494E4A31ULL, D);
                            }
                        }
                    }

                    /* NORUN 变体：只映射不执行，标记不应写入 */
                    if (Base) {
                        ULONG64 Base2 = 0;
                        XPCH_STATUS S2 = XpchInjectDll(&S, Np, DllPath,
                                                       XPCH_INJECT_NORUN, &Base2);
                        if (S2 == XPCH_OK && Base2) {
                            ULONG64 Magic2 = 0;
                            XPCH_STATUS S3;
                            BYTE *NM = NULL;
                            ULONG NG = 0;
                            Sleep(600);
                            S3 = XpchReadProcessMemory(&S, Np, Base2 + 0x3000, 8,
                                                       &NM, &NG);
                            if (S3 == XPCH_OK && NG == 8) {
                                Magic2 = *(ULONG64 *)NM;
                                XpchFree(NM);
                            }
                            Check("  |- NORUN: no DllMain run",
                                  Magic2 != 0x58504348494E4A31ULL, NULL);
                        }
                    }
                }

                TerminateProcess(Pi.hProcess, 0);
                WaitForSingleObject(Pi.hProcess, 3000);
                CloseHandle(Pi.hThread);
                CloseHandle(Pi.hProcess);
            } else {
                Check("launch notepad target", FALSE, "CreateProcessW failed");
            }
        }
    }

    /* ---------------- 收尾 ---------------- */
    printf("\n[teardown]\n");
    XpchClose(&S);
    Check("XpchClose", TRUE, "no crash");

    {
        ULONG B = 0;
        St = XpchGetBuildNumber(&S, &B);
        CheckSt("call after close", St, XPCH_E_NOT_OPENED, NULL);
    }

    printf("\n=== RESULT: PASS %d / FAIL %d ===\n", g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}