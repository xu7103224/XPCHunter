// ============================================================================
// xpch_probe - protocol self-test and live integration tool
//
// Stage 1 (offline): verify key derivation, crypto involution, request layout.
// Stage 2 (live)   : open the device, handshake, send commands, print results.
//
// Usage:
//   xpch_probe.exe              offline self-test only
//   xpch_probe.exe --live       also run live integration
//   xpch_probe.exe --live --cmd 0x24
// ============================================================================

#include "XPCHunterUM.h"
#include <stdio.h>
#include <string.h>

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

int main(int argc, char **argv)
{
    BOOL Live = FALSE;
    BOOL Scan = FALSE;
    ULONG Cmd = 0x24;
    int i;

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--live") == 0) Live = TRUE;
        else if (_stricmp(argv[i], "--scan") == 0) Scan = TRUE;
        else if (_stricmp(argv[i], "--cmd") == 0 && i + 1 < argc)
            Cmd = (ULONG)strtoul(argv[++i], NULL, 0);
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
        ULONG out = 0;
        BOOL ok;
        ULONG c;
        int supported = 0, rejected = 0;

        if (!XpchOpen(&client)) {
            printf("  open device failed, GetLastError=%lu\n", GetLastError());
            printf("  make sure the driver is loaded: sc start <service>\n");
            return 1;
        }
        printf("  device opened, key byte = 0x%02X\n", client.KeyByte);

        if (XpchHandshake(&client))
            printf("  handshake OK\n");
        else
            printf("  handshake FAILED, GetLastError=%lu\n", GetLastError());

        ok = XpchInvoke(&client, Cmd, &out, sizeof(out), NULL, 0, NULL);
        printf("  command 0x%02X -> %s, out=0x%X, GetLastError=%lu\n",
               Cmd, ok ? "OK" : "FAILED", out, GetLastError());

        printf("\n  scanning commands 0x20..0x13A:\n");
        for (c = XPCH_CMD_MIN; c <= XPCH_CMD_MAX; c++) {
            ULONG dummy = 0;
            if (XpchInvoke(&client, c, &dummy, sizeof(dummy), NULL, 0, NULL))
                supported++;
            else
                rejected++;
        }
        printf("    accepted %d, rejected %d\n", supported, rejected);

        XpchClose(&client);
    }

    printf("\n=== done ===\n");
    return g_Fail ? 1 : 0;
}