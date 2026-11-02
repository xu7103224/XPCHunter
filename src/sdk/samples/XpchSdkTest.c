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

            /* 模块 */
            {
                XPCH_MODULE_INFO *M = NULL;
                ULONG MN = 0;
                St = XpchEnumModules(Target, &M, &MN);
                char D[64];
                _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu", MN);
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
        }
        XpchFree(P);
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
        St = XpchEnumKernelModules(&K, &KN);
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
            _snprintf_s(D, sizeof(D), _TRUNCATE, "count=%lu（incl. known false positives）", HidN);
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