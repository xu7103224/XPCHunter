// ============================================================================
// xpch_probe - protocol self-test and live integration tool
//
// Stage 1 (offline): verify key derivation, crypto involution, request layout.
// Stage 2 (live)   : open the device, handshake, then exercise commands.
//
// Usage:
//   xpch_probe.exe                     offline self-test only
//   xpch_probe.exe --live              handshake + a few representative cmds
//   xpch_probe.exe --live --open-only  just create the device handle
//   xpch_probe.exe --live --scan       sweep every command in [0x20,0x13A]
//   xpch_probe.exe --live --cmd 0x2A --in <dword> --ina <n> --out <n>
// ============================================================================

#include "XPCHunterUM.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

extern void  XpchCryptBuffer(PUCHAR Buffer, ULONG Size, UCHAR KeyByte);

static int g_Fail = 0;

static void Check(const char *What, int Cond, const char *Detail)
{
    printf("  [%s] %-44s %s\n", Cond ? "PASS" : "FAIL", What, Detail ? Detail : "");
    if (!Cond)
        g_Fail++;
}

static void HexDump(const char *Tag, const UCHAR *p, ULONG n)
{
    ULONG i;
    printf("  %s:", Tag);
    for (i = 0; i < n; i++)
        printf(" %02X", p[i]);
    printf("\n");
}

static FILE *g_Log = NULL;

static void L(const char *fmt, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    fputs(buf, stdout);
    fflush(stdout);
    if (g_Log) { fputs(buf, g_Log); fflush(g_Log); }
}

/*
 * Per-command argument shapes.
 *
 * The handlers are all  char Handler(PVOID In, ULONG InSize, PVOID Out,
 * ULONG OutSize)  and most of them validate both sizes before touching
 * anything. Sending an arbitrary buffer size therefore only exercises the
 * "reject" path, which proves the transport works but not the command.
 *
 * The table below records the shape each command is known to expect, taken
 * from the original handlers (CmdGetModuleCount: out=4; CmdEnumThreads:
 * in=8/out=520; CmdReadProcessMemory: in=8; ...). Commands not listed get a
 * generic 0x1000-byte output buffer and no input, which is enough to show
 * whether the handler is reachable at all.
 */
typedef struct _CMD_SHAPE {
    ULONG Cmd;
    ULONG InSize;
    ULONG OutSize;
} CMD_SHAPE;

static const CMD_SHAPE g_Shapes[] = {
    /* Sizes taken from each handler's own validation (see the C sources):
       every handler starts with `if (OutSize != X || InSize != Y) return 0;`
       so a bare call with a 1-byte buffer only ever exercises the reject path. */
    { 0x20, 8,    0      },  /* CmdReadProcessMemory      in: ULONG64 addr            */
    { 0x22, 0,    4      },  /* CmdQueryProcessInfo       out: DWORD (<=0xA -> SSDT)  */
    { 0x24, 0,    4      },  /* CmdGetModuleCount         out: DWORD build#           */
    { 0x25, 0,    0x1000 },  /* CmdEnumKernelDrivers  -- skipped, see g_SkipCommands */
    { 0x26, 0,    0x240  },  /* CmdEnumHandles             out: >=0x230               */
    { 0x28, 16,   0      },  /* CmdProcessOperation  -- skipped, see g_SkipCommands */
    { 0x2A, 8,    520    },  /* CmdEnumThreads            in: pid, out: WCHAR[260]    */
    { 0x2B, 16,   0      },  /* CmdReadProcessMemoryBlock in: 16 bytes                */
    { 0x30, 16,   0x40   },  /* CmdRegistryProtect  -- skipped, see g_SkipCommands */
    { 0x37, 16,   0x40   },  /* CmdReadProcessMemoryEx    in: 16, out: >=0x38         */
    { 0x3C, 0,    0x1000 },  /* CmdEnumKernelModules                                  */
    { 0x42, 0,    0x40   },  /* CmdQuerySsdtInfo          out: >=0x30                 */
    { 0x54, 0,    0x300  },  /* CmdEnumProcessHandles     out: >=0x258                */
    { 0x56, 0,    0x900  },  /* CmdEnumObjectAllTypes  -- skipped, see g_SkipCommands */
    { 0x7F, 0,    0      },  /* CmdStubAlwaysTrue                                     */
    { 0xAB, 0,    0x1000 },  /* CmdQueryObjectInfo                                    */
    { 0xB0, 0,    0x1000 },  /* CmdEnumSyscallTable2                                  */
    { 0xE1, 0,    0x1E0  },  /* CmdEnumProcessListEx      out: >=0x1E0                */
    { 0xE2, 0,    0x1E0  },  /* CmdEnumProcessListWin7                                */
    { 0xE3, 0,    0x1E0  },  /* CmdEnumProcessListWin8                                */
    { 0xE4, 0,    0x1E0  },  /* CmdEnumProcessListWin10                               */
    { 0xE6, 0,    0x40   },  /* CmdGetSsdtTableInfo       out: >=0x30                 */
    { 0xE8, 0,    0x300  },  /* CmdEnumObjectTypeInfo     out: >=0x240                */
    { 0x10B,0,    0x90   },  /* MiniFilterPreAcquire      out: >=0x90                 */
};

/*
 * 0x115 CmdCallSystemRoutine (original 0x1400776D8) reads
 *     r14 = GT[0x4298]   function pointer
 *     eax = GT[0x27]     InitSdstServiceCount wrote the SSDT service count
 *                        (562 on 18362) into this very slot
 * and, when both are non-zero/!= -1, does
 *     t = KeGetCurrentThread();  saved = ((BYTE*)t)[eax];
 *     ((BYTE*)t)[eax] = 0;  result = r14(1);  ((BYTE*)t)[eax] = saved;
 * i.e. it treats the service count as a _KTHREAD byte offset and clears a
 * byte there. That is exactly what the original does; the front end avoids
 * it because GT[0x4298] is still 0 unless a caller installed a routine.
 *
 * Commands the automatic sweep must not send bare.
 *
 * Every one of these needs state that only the real front end establishes;
 * with that state missing, the handler dereferences an uninitialised value
 * and the guest BSODs or wedges. Each entry names the missing prerequisite
 * so a reader can tell a real defect from a missing-input case.
 */
static const ULONG g_SkipCommands[] = {
    0x25,   /* CmdEnumKernelDrivers
               calls GT[0x4226] (object-type ref fn), GT[0x4271]
               (driver-object list) and GT[0x42A6] through
               EnumProcessInformationWorker. Those slots are filled by
               InitObjectCallbackEntries / object enumeration, which no
               caller has run yet at sweep time. */
    0x28,   /* CmdProcessOperation
               with a 16-byte input it takes the "operate on this process"
               path: it interprets input qword[0] as an EPROCESS and
               qword[1] as a PID, then attaches to / patches it. A zeroed
               input has neither, so it walks into ProcessOperationWithAttach
               with a garbage target. The real front end only sends this
               after picking a live process. */
    0x30,   /* CmdRegistryProtect
               with a 16-byte input it goes straight into the registry
               protect/unprotect path and dereferences the key object at
               input qword[0]. A zeroed input has no key object. */
    0x56,   /* CmdEnumObjectAllTypes
               walks the object-type list from GT slots that only
               InitObjectCallbackEntries fills; without them the list head
               is a stale value and the walk faults. */
    0x115,  /* CmdCallSystemRoutine -- see the long comment below. */
};

static int IsSkipped(ULONG Cmd)
{
    size_t i;
    for (i = 0; i < sizeof(g_SkipCommands) / sizeof(g_SkipCommands[0]); i++)
        if (g_SkipCommands[i] == Cmd)
            return 1;
    return 0;
}

static const CMD_SHAPE *ShapeOf(ULONG Cmd)
{
    size_t i;
    for (i = 0; i < sizeof(g_Shapes) / sizeof(g_Shapes[0]); i++)
        if (g_Shapes[i].Cmd == Cmd)
            return &g_Shapes[i];
    return NULL;
}

/* Send one command using its known shape (or a generic one). */
static BOOL TryCommand(PXPCH_CLIENT Client, ULONG Cmd, ULONG InSizeIn,
                       ULONG OutSizeIn, ULONG InValue, UCHAR *ResultOut)
{
    const CMD_SHAPE *shape = ShapeOf(Cmd);
    ULONG inSize  = shape ? shape->InSize  : InSizeIn;
    ULONG outSize = shape ? shape->OutSize : OutSizeIn;
    ULONG64 inArg = InValue;
    UCHAR *outBuf = NULL;
    BOOL ok;
    UCHAR res = 0;

    /*
     * Commands not in the shape table get a 1-byte output buffer rather
     * than a large scratch one. Reason: a few handlers write their output
     * structure without validating OutSize, so handing them 0x1000 bytes of
     * scratch overflows the kernel stack (observed BSOD 0x139 during a
     * blind sweep). 1 byte is enough to receive the result-code byte the
     * dispatcher writes, and it makes an unvalidated handler fail fast
     * instead of corrupting memory.
     */
    if (!shape)
        outSize = 1;

    if (outSize) {
        outBuf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSize);
        if (!outBuf)
            return FALSE;
    }

    ok = XpchInvoke(Client, Cmd,
                    (inSize && inSize <= sizeof(inArg)) ? &inArg : NULL, inSize,
                    outBuf, outSize, &res);

    if (ResultOut)
        *ResultOut = res;

    if (outBuf)
        HeapFree(GetProcessHeap(), 0, outBuf);
    return ok;
}

int main(int argc, char **argv)
{
    BOOL Live = FALSE;
    BOOL Scan = FALSE;
    BOOL OpenOnly = FALSE;
    BOOL Stats = FALSE;
    ULONG Cmd = 0x24;
    ULONG InValue = 0;
    ULONG ScanLo = XPCH_CMD_MIN;
    ULONG ScanHi = XPCH_CMD_MAX;
    int i;

    fopen_s(&g_Log, "C:\\Users\\Public\\probe_trace.txt", "w");
    L("probe start\n");

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--live") == 0) Live = TRUE;
        else if (_stricmp(argv[i], "--scan") == 0) Scan = TRUE;
        else if (_stricmp(argv[i], "--open-only") == 0) OpenOnly = TRUE;
        else if (_stricmp(argv[i], "--stats") == 0) Stats = TRUE;
        else if (_stricmp(argv[i], "--cmd") == 0 && i + 1 < argc)
            Cmd = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--in") == 0 && i + 1 < argc)
            InValue = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--lo") == 0 && i + 1 < argc)
            ScanLo = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--hi") == 0 && i + 1 < argc)
            ScanHi = (ULONG)strtoul(argv[++i], NULL, 0);
    }
    if (ScanLo < XPCH_CMD_MIN) ScanLo = XPCH_CMD_MIN;
    if (ScanHi > XPCH_CMD_MAX) ScanHi = XPCH_CMD_MAX;

    printf("=== Stage 1: offline self-test ===\n");

    /* 1) parameter derivation: L"View++ByLinxer" must yield
          ioctl=0x05E00158 (= driver GT[0x1E0]) and key=0xCF (= driver GT[0x1E1]) */
    {
        ULONG ioctl = 0;
        UCHAR k = 0;
        char buf[96];
        BOOL ok = XpchDeriveParams(L"View++ByLinxer", &ioctl, &k);
        sprintf_s(buf, sizeof(buf), "ioctl=0x%08X key=0x%02X (expect 0x05E00158 / 0xCF)",
                  ioctl, k);
        Check("derive ioctl + key", ok && ioctl == 0x05E00158u && k == 0xCF, buf);
    }

    /* 2) crypto involution: crypt(crypt(x)) == x */
    {
        UCHAR a[0x30], b[0x30];
        int changed, restored;
        for (i = 0; i < 0x30; i++) a[i] = (UCHAR)(i * 7 + 3);
        memcpy(b, a, sizeof(a));
        XpchCryptBuffer(b, sizeof(b), 0xCF);
        changed = memcmp(a, b, sizeof(a)) != 0;
        XpchCryptBuffer(b, sizeof(b), 0xCF);
        restored = memcmp(a, b, sizeof(a)) == 0;
        Check("crypt changes data", changed, NULL);
        Check("crypt is involutive", restored, NULL);
    }

    /* 3) request layout */
    {
        XPCH_REQUEST req;
        ZeroMemory(&req, sizeof(req));
        req.Magic = XPCH_MAGIC;
        req.Command = Cmd;
        HexDump("plain request first 0x10 bytes", (const UCHAR *)&req, 0x10);
        Check("magic constant", req.Magic == 0x20240810, "0x20240810");
        Check("request size == 0x30", sizeof(XPCH_REQUEST) == 0x30, NULL);
        Check("command in range", Cmd >= XPCH_CMD_MIN && Cmd <= XPCH_CMD_MAX, NULL);
    }

    printf("\n=== Stage 1: %s ===\n", g_Fail ? "FAILURES" : "ALL PASS");

    if (!Live) {
        printf("\n(no --live given, skipping live integration)\n");
        return g_Fail ? 1 : 0;
    }

    printf("\n=== Stage 2: live integration ===\n");
    {
        XPCH_CLIENT client;
        UCHAR res = 0;
        BOOL ok;
        ULONG c;
        int accepted = 0, rejected = 0, skipped = 0;

        if (!XpchOpen(&client)) {
            printf("  open device failed, GetLastError=%lu\n", GetLastError());
            printf("  make sure the driver is loaded: sc start View++ByLinxer\n");
            return 1;
        }
        printf("  device opened, ioctl=0x%08X key=0x%02X\n",
               client.IoControlCode, client.KeyByte);

        if (OpenOnly) {
            XpchClose(&client);
            printf("\n=== done (open-only) ===\n");
            return 0;
        }

        /* --stats: dump the driver-side per-command call counters through the
           diagnostic command 0x13A (an empty slot in the original table, so
           no real front end ever sends it). Use this right after running the
           ORIGINAL PCHunter64.exe against this driver: any command with a
           non-zero count was issued by that front end. */
        if (Stats) {
            enum { N = 283, REC = 16 };
            ULONG *recs = (ULONG *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, N * REC);
            UCHAR sres = 0;
            BOOL sok = FALSE;
            int used = 0;

            if (recs)
                sok = XpchInvoke(&client, 0x13A, NULL, 0, recs, N * REC, &sres);

            printf("  stats dump 0x13A -> %s, result=%u\n",
                   sok ? "OK" : "REJECTED", sres);

            if (sok) {
                for (c = 0; c < N; c++) {
                    ULONG *r = (ULONG *)((BYTE *)recs + c * REC);
                    if (r[1]) {   /* call count */
                        printf("    0x%02X count=%-6lu lastResult=%lu lastPid=%lu\n",
                               r[0], r[1], r[2], r[3]);
                        used++;
                    }
                }
                printf("    %d command(s) invoked since load\n", used);
            }
            if (recs)
                HeapFree(GetProcessHeap(), 0, recs);

            XpchClose(&client);
            printf("\n=== done (stats) ===\n");
            return 0;
        }

        /* Handshake: 0x22 opens the driver-ready flag (GT[0x304]) via
           CheckSsdtHookIntegrity; 0x24 then returns the build number. */
        {
            ULONG build = 0;
            ULONG ssdt = 0;
            UCHAR r22 = 0;
            BOOL ok22;

            ok22 = XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                              NULL, 0, &ssdt, sizeof(ssdt), &r22);
            printf("  handshake 0x22 -> %s, result=%u, ssdt=%lu\n",
                   ok22 ? "OK" : "REJECTED", r22, ssdt);

            ok = XpchInvoke(&client, XPCH_CMD_GET_MODULE_COUNT,
                            NULL, 0, &build, sizeof(build), &res);
            printf("  handshake 0x24 -> %s, result=%u, build=%lu (0x%lX)\n",
                   ok ? "OK" : "REJECTED", res, build, build);
        }

        ok = TryCommand(&client, Cmd, 0, 0x1000, InValue, &res);
        printf("  command 0x%02X -> %s, result=%u, GetLastError=%lu\n",
               Cmd, ok ? "OK" : "REJECTED", res, GetLastError());

        if (Scan) {
            printf("\n  scanning 0x%02X..0x%02X (progress: scan_progress.txt)\n",
                   ScanLo, ScanHi);

            /*
             * Results go to a file that is opened, appended and closed for
             * each command. stdout is block-buffered when redirected, so a
             * BSOD mid-scan would otherwise lose every line already "printed".
             * The same file doubles as the crash beacon: the last line names
             * the command that killed the guest.
             */
            for (c = ScanLo; c <= ScanHi; c++) {
                UCHAR r = 0;
                BOOL r_ok;
                FILE *f = NULL;

                if (IsSkipped(c)) {
                    fopen_s(&f, "C:\\Users\\Public\\scan_progress.txt", "a");
                    if (f) {
                        fprintf(f, "    0x%02X SKIP (see probe.c comment)\n", c);
                        fclose(f);
                    }
                    skipped++;
                    continue;
                }

                fopen_s(&f, "C:\\Users\\Public\\scan_progress.txt", "a");
                if (f) {
                    fprintf(f, "trying 0x%02X\n", c);
                    fclose(f);
                }

                r_ok = TryCommand(&client, c, 0, 0x1000, 0, &r);

                fopen_s(&f, "C:\\Users\\Public\\scan_progress.txt", "a");
                if (f) {
                    fprintf(f, "    0x%02X result=%u %s\n", c, r,
                            r_ok ? "OK" : "REJECTED");
                    fclose(f);
                }
                if (r_ok)
                    accepted++;
                else
                    rejected++;
            }
            printf("    accepted %d, rejected %d, skipped %d\n",
                   accepted, rejected, skipped);
        }

        XpchClose(&client);
    }

    printf("\n=== done ===\n");
    return g_Fail ? 1 : 0;
}