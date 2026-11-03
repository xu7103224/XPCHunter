/* ============================================================================
 * XpchInjProbe.c —— 注入链路验证（开发用，不随 SDK 发布）
 *
 * 直接走 XpchInvokeRaw 发 0x09A，并验证注入后 DllMain 是否真的执行：
 * 测试 DLL 的 g_XpchInjected 位于 .data（RVA 0x3000），DllMain 写入
 * 魔数 0x58504348494E4A31；注入后经 0x023 读回即证明执行成功。
 * ==========================================================================*/
#include "../src/XpchSdk_internal.h"
#include <stdio.h>
#include <stdlib.h>

#define MAGIC_WANT  0x58504348494E4A31ULL
#define MARK_RVA    0x3000

static XPCH_SESSION S;

static const char *StName(XPCH_STATUS St)
{
    switch (St) {
    case XPCH_OK:            return "OK";
    case XPCH_E_REJECTED:    return "REJECTED";
    case XPCH_E_IOCTL:       return "IOCTL";
    case XPCH_E_NOT_OPENED:  return "NOT_OPENED";
    default:                 return "OTHER";
    }
}

static void TokenOp(ULONG Pid, ULONG Mode)
{
#pragma pack(push, 1)
    struct { ULONG64 Pid; ULONG Mode; ULONG Pad; } In;
#pragma pack(pop)
    ULONG Out[2] = {0, 0};
    XPCH_STATUS St;

    In.Pid = Pid; In.Mode = Mode; In.Pad = 0;
    St = XpchInvokeRaw(&S, CMD_X_ADJUST_TOKEN, &In, sizeof(In),
                       Out, sizeof(Out));
    printf("  Mode=%lu -> st=%d(%s) privCount=%lu enabled=%lu\n",
           (unsigned long)Mode, (int)St, StName(St),
           (unsigned long)Out[0], (unsigned long)Out[1]);
}

int main(int argc, char **argv)
{
    XPCH_STATUS St;
    ULONG Pid;
    ULONG64 Base = 0;
    ULONG64 Marker = 0;

    if (argc < 2) {
        printf("usage: XpchInjProbe <pid>\n");
        return 1;
    }
    Pid = (ULONG)strtoul(argv[1], NULL, 0);

    St = XpchOpen(&S);
    printf("XpchOpen: %d (%s)\n", (int)St, StName(St));
    if (St != XPCH_OK)
        return 1;

    printf("\n[0x09A: Token priv]\n");
    TokenOp(Pid, 2);
    TokenOp(Pid, 0);
    TokenOp(Pid, 2);
    TokenOp(Pid, 1);
    TokenOp(Pid, 2);

    printf("\n[inject]\n");
    St = XpchInjectDll(&S, Pid, L"C:\\Users\\Public\\XpchInjTarget.dll",
                       0, &Base);
    printf("  XpchInjectDll(RUN) st=%d(%s) base=%llx\n",
           (int)St, StName(St), (unsigned long long)Base);

    if (St == XPCH_OK && Base) {
        BYTE *Mem = NULL;
        ULONG Got = 0;

        /* 远程线程异步执行：必须等 DllMain 跑完再读标记 */
        Sleep(1500);
        printf("  marker RVA 0x%x -> reading ...\n", MARK_RVA);
        St = XpchReadProcessMemory(&S, Pid, Base + MARK_RVA, 8, &Mem, &Got);
        if (St == XPCH_OK && Got == 8) {
            memcpy(&Marker, Mem, 8);
            XpchFree(Mem);
            printf("  marker = 0x%llx  %s\n", (unsigned long long)Marker,
                   Marker == MAGIC_WANT ? "== DLLMAIN RAN" : "(not magic)");
        } else {
            printf("  read marker failed st=%d\n", (int)St);
        }
    }

    printf("\n[threads after inject]\n");
    {
        XPCH_THREAD_INFO *T = NULL; ULONG N = 0;
        St = XpchEnumThreads(&S, Pid, &T, &N);
        printf("  EnumThreads st=%d count=%lu\n", (int)St, N);
        if (St == XPCH_OK) XpchFree(T);
    }

    XpchClose(&S);
    return (Marker == MAGIC_WANT) ? 0 : 2;
}