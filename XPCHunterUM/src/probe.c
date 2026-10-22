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
    /* 【2026-10-22】0x22 从 shape 表移除：以 InSize<=0xA 调用它会让驱动执行
       AllocProcessInfoBuffer()，后者 memset 清空命令表的槽 198..224
       （命令 0xE6..0x100），把 0xEF..0xF8 等 20 多个处理器一起抹掉。
       握手已经用合法许可包调用过它，扫描阶段不能再碰。
       0x22, 0, 4 */
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
    { 0xE4, 0,    0x300  },  /* CmdEnumProcessListWin10  out: >=0x298（每条 664 字节） */
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
    /* 0x22 必须跳过：它已由握手用 0x100 合法许可包调用过。若扫描再以
       InSize<=0xA 发一次，驱动会执行 AllocProcessInfoBuffer()，
       其 memset 会清空命令表的槽 198..224（命令 0xE6..0x100），
       把 0xEF..0xF8 等 20 多个处理器一起抹掉 —— 实测已复现。 */
    if (Cmd == 0x22u)
        return 1;
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
    BOOL NoHandshake = FALSE;
    BOOL LicenseOnly = FALSE;
    /* 0x22 握手的入参。默认使用 XpchBuildLicensePacket 生成的
       0x100 字节合法许可包（原版前端走的就是这条路径），
       这样既置位 GT[0x304]，又不会触发 AllocProcessInfoBuffer
       清空命令表 198..224。用 --hs-size 可强制指定其它长度做对照实验。 */
    static UCHAR HsSeed[0x200];
    ULONG HsSeedSize = 0;
    UCHAR HsPacketBuf[0x100];
    PVOID HsPacket = HsSeed;
    ULONG HsPacketSize = 0;
    BOOL Dump = FALSE;
    ULONG DumpSize = 0x10000;
    ULONG Cmd = 0x24;
    ULONG InValue = 0;
    ULONG ScanLo = XPCH_CMD_MIN;
    ULONG ScanHi = XPCH_CMD_MAX;
    BOOL Raw = FALSE;
    ULONG RawSize = 0x4000;
    ULONG RawInSize = 0;
    ULONG RawInValue = 0;
    int i;

    fopen_s(&g_Log, "C:\\Users\\Public\\probe_trace.txt", "w");
    L("probe start\n");

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--live") == 0) Live = TRUE;
        else if (_stricmp(argv[i], "--scan") == 0) Scan = TRUE;
        else if (_stricmp(argv[i], "--open-only") == 0) OpenOnly = TRUE;
        else if (_stricmp(argv[i], "--stats") == 0) Stats = TRUE;
        else if (_stricmp(argv[i], "--dump") == 0) {
            Dump = TRUE;
            if (i + 1 < argc) DumpSize = (ULONG)strtoul(argv[++i], NULL, 0);
        }
        else if (_stricmp(argv[i], "--cmd") == 0 && i + 1 < argc)
            Cmd = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--in") == 0 && i + 1 < argc)
            InValue = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--lo") == 0 && i + 1 < argc)
            ScanLo = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--hi") == 0 && i + 1 < argc)
            ScanHi = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--nohs") == 0) NoHandshake = TRUE;
        else if (_stricmp(argv[i], "--license") == 0) LicenseOnly = TRUE;
        else if (_stricmp(argv[i], "--hs-size") == 0 && i + 1 < argc) {
            HsSeedSize = (ULONG)strtoul(argv[++i], NULL, 0);
            if (HsSeedSize > sizeof(HsSeed)) HsSeedSize = sizeof(HsSeed);
        }
        else if (_stricmp(argv[i], "--raw") == 0 && i + 1 < argc) {
            /* --raw <cmd> [outsize]：发送单条命令并把输出缓冲按 16 字节一行
               十六进制导出，用于离线推断尚未文档化的命令输出布局。 */
            Raw = TRUE;
            Cmd = (ULONG)strtoul(argv[++i], NULL, 0);
            if (i + 1 < argc && argv[i + 1][0] != '-')
                RawSize = (ULONG)strtoul(argv[++i], NULL, 0);
        }
        else if (_stricmp(argv[i], "--rawin") == 0) {
            /* --rawin <insize> <value>：给 --raw 的命令附带入参。
               许多处理器校验 InSize（如 8），没有入参就永远走"入参不合法"分支。 */
            if (i + 2 < argc) {
                RawInSize  = (ULONG)strtoul(argv[++i], NULL, 0);
                RawInValue = (ULONG)strtoul(argv[++i], NULL, 0);
            }
        }
    }
    if (ScanLo < XPCH_CMD_MIN) ScanLo = XPCH_CMD_MIN;
    if (ScanHi > XPCH_CMD_MAX) ScanHi = XPCH_CMD_MAX;

    /* 握手入参：默认合法许可包（0x100）；--hs-size 给了就用裸缓冲做对照。 */
    if (HsSeedSize != 0) {
        HsPacket = HsSeed;
        HsPacketSize = HsSeedSize;
    } else if (XpchBuildLicensePacket(HsPacketBuf)) {
        HsPacket = HsPacketBuf;
        HsPacketSize = sizeof(HsPacketBuf);
    }

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

    /* 2b) AES-128 单块加密：FIPS-197 附录 B 测试向量 */
    {
        static const UCHAR k[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        static const UCHAR p[16] = {
            0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
            0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
        };
        static const UCHAR expect[16] = {
            0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
            0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
        };
        UCHAR out[16];
        XpchAes128EncryptBlock(k, p, out);
        Check("AES-128 FIPS-197 vector", memcmp(out, expect, 16) == 0,
              "3925841d02dc09fbdc118597196a0b32");
    }

    /* 2c) 许可包构造：长度 0x100，且全为合法十六进制字符 */
    {
        UCHAR pkt[0x100];
        int ok = XpchBuildLicensePacket(pkt) ? 1 : 0;
        int i, ishex = 1;
        for (i = 0; i < 0x100; i++) {
            UCHAR c = pkt[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                ishex = 0;
        }
        Check("license packet builds", ok && ishex, "0x100 hex chars");
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

        /* --license: 只发一次 0x100 字节许可包，报告结果字节。
           用来判定驱动是否接受了我们构造的 AES 包（路径 C）。 */
        if (LicenseOnly) {
            UCHAR pkt[0x100];
            UCHAR lr = 0;
            ULONG ls = 0;
            BOOL okp = XpchBuildLicensePacket(pkt);
            BOOL lok = FALSE;

            if (okp)
                lok = XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                                 pkt, sizeof(pkt), &ls, sizeof(ls), &lr);
            printf("  license 0x22 -> %s, result=%u, ssdt=%lu (packet=%s)\n",
                   lok ? "OK" : "REJECTED", lr, ls, okp ? "built" : "FAILED");
            printf("  packet[0..32] = ");
            {
                int q;
                for (q = 0; q < 32; q++) printf("%02X", pkt[q]);
                printf("\n");
            }
            /* 许可包被拒后 GT[0x304] 仍为 0，0x13A 也不可用，
               所以直接借 --license 通道读驱动 env 块里的 AES 诊断：
               先发一次 0x13A（可能被拒），再读返回缓冲的 0x3A4 处。
               若 0x13A 被拒则无输出；因此改为发送后无条件解析。 */
            {
                UCHAR *st = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x3000);
                UCHAR sr = 0;
                if (st) {
                    XpchInvoke(&client, 0x13A, NULL, 0, st, 0x3000, &sr);
                    {
                        const UCHAR *env = st + 283 * 16 + 16;
                        printf("  after-license: 0x13A result=%u"
                               "  aesStage=%lu md5Calc=%08lX md5Expect=%08lX\n",
                               sr, *(const ULONG *)(env + 0x3A4),
                               *(const ULONG *)(env + 0x3A8),
                               *(const ULONG *)(env + 0x3AC));
                    }
                    HeapFree(GetProcessHeap(), 0, st);
                }
            }
            XpchClose(&client);
            printf("\n=== done (license) ===\n");
            return 0;
        }

        /* --dump: send one command with a large output buffer and hex-dump
           whatever the driver wrote. Used to determine a command's real
           output layout empirically instead of guessing from decompiler
           output (the process-list command, for instance, has a nested
           header/entry structure that Hex-Rays renders ambiguously). */
        if (Dump) {
            UCHAR *buf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DumpSize);
            UCHAR dres = 0;
            BOOL dok = FALSE;
            ULONG off;

            XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                       NULL, 0, &(ULONG){0}, 4, NULL);   /* open ready flag */

            if (buf)
                dok = XpchInvoke(&client, Cmd, NULL, 0, buf, DumpSize, &dres);

            printf("  dump 0x%02X outSize=0x%X -> %s, result=%u\n",
                   Cmd, DumpSize, dok ? "OK" : "REJECTED", dres);

            /* 【修正 2026-10-21】很多命令（如 0x49）按设计返回结果字节 0，
               但输出缓冲里有完整数据；--dump 正是用来逆布局的，必须无条件打印。 */
            if (buf) {
                for (off = 0; off < DumpSize; off += 16) {
                    int nz = 0, k;
                    for (k = 0; k < 16; k++) if (buf[off + k]) nz = 1;
                    if (!nz) continue;
                    printf("    %04X:", off);
                    for (k = 0; k < 16; k++) printf(" %02X", buf[off + k]);
                    printf("\n");
                }
            }
            if (buf) HeapFree(GetProcessHeap(), 0, buf);
            XpchClose(&client);
            printf("\n=== done (dump) ===\n");
            return 0;
        }

        /* --stats: dump the driver-side per-command call counters through the
           diagnostic command 0x13A (an empty slot in the original table, so
           no real front end ever sends it). Use this right after running the
           ORIGINAL PCHunter64.exe against this driver: any command with a
           non-zero count was issued by that front end. */
        if (Stats) {
            enum { N = 284, REC = 16 };   /* 283 commands + 1 device-open record */
            enum { ENV = 0x400, STATBUF = 0x3000 };   /* >= driver need, keep slack */
            ULONG *recs;
            UCHAR sres = 0;
            BOOL sok = FALSE;
            int used = 0;
            ULONG ssdt = 0;
            UCHAR r22 = 0;

            /*
             * The dispatcher rejects every command except 0x22 while GT[0x304]
             * (the driver-ready flag) is still 0, so open it first. Without
             * this the 0x13A dump is refused before the handler is reached.
             */
            /* 对照实验用：--nohs 跳过 0x22 握手，可以直接观察
               InitCommandHandlerTable 填好、未被 AllocProcessInfoBuffer
               清空时的命令表原文。 */
            if (!NoHandshake)
                XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                           HsPacket, HsPacketSize, &ssdt, sizeof(ssdt), &r22);

            recs = (ULONG *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, STATBUF);
            if (recs)
                sok = XpchInvoke(&client, 0x13A, NULL, 0, recs, STATBUF, &sres);

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

                {
                    BYTE *env = (BYTE *)recs + N * REC;
                    printf("    --- driver environment ---\n");
                    printf("    build=%-6lu ndisVer=0x%lX processListHead=%p\n",
                           *(ULONG *)(env + 0x00), *(ULONG *)(env + 0x04),
                           (void *)*(ULONG64 *)(env + 0x08));
                    printf("    ndisBase=%p ntoskrnlBase=%p kdSectReady=%lu\n",
                           (void *)*(ULONG64 *)(env + 0x10),
                           (void *)*(ULONG64 *)(env + 0x18),
                           (ULONG)*(ULONG64 *)(env + 0x20));
                    printf("    fltDataSection=%p driverReady=%lu win32kSvc=%p\n",
                           (void *)*(ULONG64 *)(env + 0x28),
                           *(ULONG *)(env + 0x30),
                           (void *)*(ULONG64 *)(env + 0x38));
                    printf("    ndisRead=%lu ndisFileSize=0x%lX\n",
                           *(ULONG *)(env + 0x40), *(ULONG *)(env + 0x44));
                    printf("    openStatus=0x%lX queryStatus=0x%lX\n",
                           *(ULONG *)(env + 0x48), *(ULONG *)(env + 0x4C));
                    printf("    toBuf=%ld rawStatus=0x%lX rawSize=0x%lX\n",
                           (long)*(ULONG *)(env + 0x50),
                           *(ULONG *)(env + 0x54), *(ULONG *)(env + 0x58));
                    /* 0xB0 = GT[0x36C] Win10 进程链表头（命令 0xE4 的数据源，
                       由 ParseNtKernelDataSections 写入）；0xA8 = GT[0x36A] 其门控 */
                    printf("    win10ListHead=%p ndisIMOffset=0x%lX\n",
                           (void *)*(ULONG64 *)(env + 0xB0),
                           (ULONG)*(ULONG *)(env + 0xA8));
                    /* 0x2C0..0x2F8：SSDT/Shadow SSDT（0x8C/0x8E）链条的诊断。
                       OpenFileSection 要求 0x421D/0x421A/0x4223/0x4160 四个槽
                       全部非零，任一个为 0 就整体返回 0。 */
                    printf("    --- 0x8C/0x8E chain ---\n");
                    printf("    RtlInitUnicodeString(0x421D)=%p\n",
                           (void *)*(ULONG64 *)(env + 0x2C0));
                    printf("    IoCreateFile(0x421A)        =%p\n",
                           (void *)*(ULONG64 *)(env + 0x2C8));
                    printf("    CloseHandle(0x4223)         =%p\n",
                           (void *)*(ULONG64 *)(env + 0x2D0));
                    printf("    DriverObjectListHead(0x4160)=%p\n",
                           (void *)*(ULONG64 *)(env + 0x2D8));
                    printf("    ready0x8C(GT[0x1E1])        =%lu\n",
                           (ULONG)*(ULONG64 *)(env + 0x2E0));
                    printf("    ready0x8E(GT[0x2DA])        =%lu\n",
                           (ULONG)*(ULONG64 *)(env + 0x2E8));
                    printf("    openStage                   =0x%lX\n",
                           *(ULONG *)(env + 0x2F0));
                    printf("    openStatus(NTSTATUS)        =0x%lX\n",
                           *(ULONG *)(env + 0x2F4));
                    printf("    openHandle                  =%p\n",
                           (void *)*(ULONG64 *)(env + 0x2F8));
                    printf("    --- 0x046 IDT/IOPort chain ---\n");
                    printf("    ioPortStage=%lu  idtValid=%lu\n",
                           *(ULONG *)(env + 0x300), *(ULONG *)(env + 0x304));
                    printf("    idtGtSlot=%p  idtBase=%p\n",
                           (void *)*(ULONG64 *)(env + 0x308),
                           (void *)*(ULONG64 *)(env + 0x310));
                    printf("    [0x22 license] aesStage=%lu  md5Calc=%08lX  md5Expect=%08lX\n",
                           *(ULONG *)(env + 0x3A4),
                           *(ULONG *)(env + 0x3A8),
                           *(ULONG *)(env + 0x3AC));
                    printf("    [0xF8 kmctx] stage=%lu (0=未进入 1=netio读失败 2=解析中 3=完成)"
                           "  netioFileSize=0x%lX\n",
                           *(ULONG *)(env + 0x3B0),
                           *(ULONG *)(env + 0x3B4));
                    {
                        int off2;
                        /* 只转储环境块本体（0x300）；再往后是分派器诊断表 */
                        printf("    raw env:");
                        for (off2 = 0; off2 < 0x4A0; off2++) {
                            if ((off2 & 15) == 0) printf("\n      %04X:", off2);
                            printf(" %02X", env[off2]);
                        }
                        printf("\n");
                    }

                    /* --- BuildHookTable 分步诊断（2026-10-21）------------------
                       0xA2 的三个前置槽 0x41DB/0x41C3/0x4334 都是
                       GT[0x4158+3k+2]，由 BuildHookTable 的
                       `GtWrite(i+2, RVA + ImageBase)` 写入。它们为 0 说明
                       整张表没填出来；这些计数说明停在哪一步。 */
                    printf("    --- BuildHookTable ---\n");
                    printf("      PeBase=%p PeSize=0x%lX lfanew=0x%lX\n",
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x100),
                           *(ULONG *)(env + 0x110),
                           *(ULONG *)(env + 0x114));
                    printf("      ImageBase=%p ExportCount=%lu IdxEntries=%lu\n",
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x108),
                           *(ULONG *)(env + 0x118), *(ULONG *)(env + 0x11C));
                    printf("      iter=%lu hashZero=%lu hits=%lu writes=%lu\n",
                           *(ULONG *)(env + 0x120), *(ULONG *)(env + 0x124),
                           *(ULONG *)(env + 0x128), *(ULONG *)(env + 0x12C));
                    printf("      idx[0].hash=0x%lX idx[0].rva=0x%lX targetHash=0x%lX\n",
                           *(ULONG *)(env + 0x130), *(ULONG *)(env + 0x134),
                           *(ULONG *)(env + 0x138));
                    printf("      GT[41DB]=0x%lX GT[41C3]=0x%lX GT[4334]=0x%lX\n",
                           *(ULONG *)(env + 0x13C), *(ULONG *)(env + 0x140),
                           *(ULONG *)(env + 0x144));
                    printf("      GT[4159]=0x%lX GT[415A]=0x%lX\n",
                           *(ULONG *)(env + 0x148), *(ULONG *)(env + 0x14C));
                    printf("      GT[29C]=0x%lX GT[29F]=0x%lX GT[27]=0x%lX\n",
                           *(ULONG *)(env + 0x150), *(ULONG *)(env + 0x154),
                           *(ULONG *)(env + 0x158));

                    /* --- 0xA2 终止路径 trace（2026-10-21）----------------
                       stage：1=GT[0x41DB]为0 2=对象类型校验不过
                              3=legacy 路径 4=直接终止已调用
                              5=GT[0x42BC]为0 6=入参校验失败 */
                    printf("    --- 0xA2 terminate trace ---\n");
                    printf("      stage=%lu build=%lu isLegacy=%lu\n",
                           *(ULONG *)(env + 0x160), *(ULONG *)(env + 0x164),
                           *(ULONG *)(env + 0x170));
                    printf("      check1=%lu check2=%lu sdst=%lu\n",
                           *(ULONG *)(env + 0x168), *(ULONG *)(env + 0x16C),
                           *(ULONG *)(env + 0x174));
                    printf("      dupRet=%ld termRet=%lu directRet=0x%lX\n",
                           (long)*(ULONG *)(env + 0x178),
                           *(ULONG *)(env + 0x17C), *(ULONG *)(env + 0x180));
                    printf("      Ep=%p\n",
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x188));
                    printf("      DirectFn=%p (GT[0x42BC]=0x%lX)\n",
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x190),
                           *(ULONG *)(env + 0x1B8));
                    printf("      CheckFn=%p DupFn=%p FreeFn=%p TermFn=%p\n",
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x198),
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x1A0),
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x1A8),
                           (void *)(ULONG_PTR)*(ULONG64 *)(env + 0x1B0));

                    /* --- 分派校准 -------------------------------------------------
                       结果字节 0 既可能是"被分派器拒绝"，也可能是"处理器执行完
                       但设计上返回 0"（例如 0x20 读进程内存、0x28 进程操作）。
                       驱动的诊断表把两者分开：
                         count>0                  → HANDLED（处理器确实执行）
                         count==0 && diag!=0      → REJECTED（分派器原因码）
                         count==0 && diag==0      → NOT-ATTEMPTED（本轮没试过）
                       diag 表位于 env + CMD_ENV_SIZE（见 XPCHunterDrv.h）。 */
                    {
                        /* 2026-10-22: must track XPCHunterDrv.h CMD_ENV_SIZE. */
                        enum { CMD_ENV_SIZE_LOCAL = 0x4A0 };
                        const ULONG *diag = (const ULONG *)(const void *)(env + CMD_ENV_SIZE_LOCAL);
                        const ULONG *rej = diag + 283;
                        ULONG k, handled = 0, rejected = 0, unattempted = 0;

                        for (k = 0; k < 283; k++) {
                            ULONG cnt = *(const ULONG *)(const void *)((const PUCHAR)recs + k * 16 + 4);
                            if (cnt) handled++;
                            else if (diag[k]) rejected++;
                            else unattempted++;
                        }
                        printf("    --- 分派校准 ---\n");
                        printf("    HANDLED=%lu  REJECTED=%lu  NOT-ATTEMPTED=%lu\n",
                               handled, rejected, unattempted);
                        printf("    HANDLED（处理器已执行；result=0 不代表失败）:\n     ");
                        for (k = 0; k < 283; k++) {
                            ULONG cnt = *(const ULONG *)(const void *)((const PUCHAR)recs + k * 16 + 4);
                            if (cnt)
                                printf(" 0x%02lX(%lu,r%lu)", 0x20 + k, cnt,
                                       *(const ULONG *)(const void *)((const PUCHAR)recs + k * 16 + 8));
                        }
                        printf("\n    REJECTED（分派器原因码）:\n     ");
                        for (k = 0; k < 283; k++) {
                            ULONG cnt = *(const ULONG *)(const void *)((const PUCHAR)recs + k * 16 + 4);
                            if (!cnt && diag[k])
                                printf(" 0x%02lX(r%lu)", 0x20 + k, diag[k]);
                        }
                        printf("\n    协议级拒绝计数(reason 1..10):");
                        for (k = 1; k < 11; k++)
                            printf(" %lu=%lu", k, rej[k]);
                        printf("\n");

                        /* 命令表原文快照：判断槽位为 0 是"未写入"还是
                           "被 AllocProcessInfoBuffer 的 memset 清掉"。
                           布局见 XPCHunterDrv.h：
                             CMD_STAT_TOTAL_SIZE | 快照 27*8 | allocProc 计数 4 */
                        {
                            enum {
                                SNAP_OFF = 283 * 16 + 16 + 0x4A0 + 283 * 4 + 11 * 4
                            };
                            const ULONG64 *snap =
                                (const ULONG64 *)(const void *)((const UCHAR *)recs + SNAP_OFF);
                            const ULONG *allocCnt =
                                (const ULONG *)(const void *)((const UCHAR *)recs + SNAP_OFF + 27 * 8);
                            int nz = 0;
                            /* 先用首尾两点确认这个偏移确实落在快照区：
                               驱动把 GT[0x921+198] 写在快照[0]，GT[0x921+224] 在快照[26] */
                            printf("    [debug] SNAP_OFF=%lu snap[0]=%016llX snap[26]=%016llX\n",
                                   (unsigned long)SNAP_OFF,
                                   (unsigned long long)snap[0],
                                   (unsigned long long)snap[26]);
                            printf("    命令表快照 GT[0x921+198..224]（索引 198..224）:\n     ");
                            for (k = 0; k < 27; k++) {
                                if (snap[k]) nz++;
                                printf(" %lu:%s", 198 + k, snap[k] ? "SET" : "0");
                            }
                            printf("\n    非空槽数=%d/27   AllocProcessInfoBuffer 调用次数=%lu\n",
                                   nz, *allocCnt);
                            printf("    [debug] 驱动侧 27 个 QWORD 的导出偏移（相对缓冲首）= %lu\n",
                                   (unsigned long)(283 * 16 + 16 + 0x4A0 + 283 * 4 + 11 * 4));

                            {
                                const ULONG64 *chk =
                                    (const ULONG64 *)(const void *)((const UCHAR *)recs
                                                     + SNAP_OFF + 27 * 8 + 8);
                                printf("    InitCommandHandlerTable 收尾自检:"
                                       " 写出Table[198]=%llX  回读槽198=%llX  回读槽207=%llX\n",
                                       (unsigned long long)chk[0],
                                       (unsigned long long)chk[1],
                                       (unsigned long long)chk[2]);
                                printf("    AllocProcessInfoBuffer GT 标记(0x4F90)=%llu\n",
                                       (unsigned long long)chk[3]);
                                printf("    导出通道自校验: 槽0=%llX  槽281=%llX"
                                       "（都为 0 说明导出通道本身坏了）\n",
                                       (unsigned long long)chk[4],
                                       (unsigned long long)chk[5]);
                            }
                        }
                    }
                }
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
                              HsPacket, HsPacketSize, &ssdt, sizeof(ssdt), &r22);
            printf("  handshake 0x22 (inSize=%lu) -> %s, result=%u, ssdt=%lu\n",
                   HsPacketSize, ok22 ? "OK" : "REJECTED", r22, ssdt);

            ok = XpchInvoke(&client, XPCH_CMD_GET_MODULE_COUNT,
                            NULL, 0, &build, sizeof(build), &res);
            printf("  handshake 0x24 -> %s, result=%u, build=%lu (0x%lX)\n",
                   ok ? "OK" : "REJECTED", res, build, build);
        }

        if (Raw) {
            UCHAR *outBuf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RawSize);
            UCHAR rr = 0;
            BOOL rok;
            ULONG off;

            if (!outBuf) {
                printf("out of memory\n");
                XpchClose(&client);
                return 1;
            }
            /* 直接用 XpchInvoke：TryCommand 会给未知命令强制 1 字节输出，
               这里要的是按调用方指定的大小拿完整输出。
               RawInSize > 0 时先发一段入参（0x4C 等需要 8 字节输入的处理器）。 */
            if (RawInSize)
            {
                UCHAR inBuf[64];
                ULONG n = RawInSize > sizeof(inBuf) ? (ULONG)sizeof(inBuf) : RawInSize;
                ULONG k;
                ZeroMemory(inBuf, sizeof(inBuf));
                for (k = 0; k < n && k < 8; k++)
                    inBuf[k] = (UCHAR)((RawInValue >> (8 * k)) & 0xFF);
                rok = XpchInvoke(&client, Cmd, inBuf, n, outBuf, RawSize, &rr);
            }
            else
            {
                rok = XpchInvoke(&client, Cmd, NULL, 0, outBuf, RawSize, &rr);
            }
            printf("\n=== raw 0x%02X outSize=0x%lX -> %s result=%u ===\n",
                   Cmd, RawSize, rok ? "OK" : "REJECTED", rr);
            for (off = 0; off < RawSize; off += 16) {
                ULONG j;
                printf("  %04lX:", off);
                for (j = 0; j < 16 && off + j < RawSize; j++)
                    printf(" %02X", outBuf[off + j]);
                printf("\n");
            }
            HeapFree(GetProcessHeap(), 0, outBuf);
            XpchClose(&client);
            printf("=== done (raw) ===\n");
            return 0;
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