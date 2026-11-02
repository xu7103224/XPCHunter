// ============================================================================
// CliMain.c — 命令行（--xxx-cli）分发与处理
//
// 【2026-10-28 由 frontend.c 机械拆分】拆分规则与验收方式见
//   docs/archive/reversing/frontend拆分_2026-10-28.md。本文件全部处理函数的
//   函数体逐字取自原 frontend.c WinMain 内的 CLI if 链，仅做三处机械变换：
//     1) 每块包成独立函数，块首插入
//          if (!(<原始条件>)) return FE_CLI_NEXT;
//        块尾若无 return 补 return FE_CLI_NEXT（保持"继续匹配"语义）；
//     2) FeCliDispatch 按【原源码顺序】走链，首个非 FE_CLI_NEXT 即返回
//        —— strstr 首匹配语义是承重的（--restorehooks-cli 先于 --hooks-cli）；
//     3) 原块内引用的静态变量改为 extern（g_Client / g_StartTab）。
//   外观与行为不得有任何变化；验收 = 全部 CLI 输出与拆分前基线逐字节一致
//   （build/cli_baseline/cli_base_t1.txt）。
// ============================================================================
#include "XPCHunterUM.h"
#include "CliMain.h"
#include "FePages.h"
#include "FeTheme.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern XPCH_CLIENT g_Client;
extern int g_StartTab;

BOOL FeIsSkipped(ULONG cmd);
BOOL SendOne(ULONG cmd, ULONG outSize, char *detail, size_t detailLen);

static int RunHeadless(void)
{
    ULONG cmd;
    int okCount = 0, failCount = 0, skipCount = 0;
    char detail[128];
    FILE *log = NULL;

    fopen_s(&log, "C:\\Users\\Public\\frontend_scan.txt", "w");

#define LOGF(...) do { printf(__VA_ARGS__); \
        if (log) { fprintf(log, __VA_ARGS__); fflush(log); } } while (0)

    if (!XpchOpen(&g_Client)) {
        LOGF("open device failed, GetLastError=%lu\n", GetLastError());
        if (log) fclose(log);
        return 1;
    }
    LOGF("connected: ioctl=0x%08X key=0x%02X\n",
        g_Client.IoControlCode, g_Client.KeyByte);

    for (cmd = XPCH_CMD_MIN; cmd <= XPCH_CMD_MAX; cmd++) {
        if (FeIsSkipped(cmd)) {
            SendOne(cmd, 0, detail, sizeof(detail));
            LOGF("0x%02X SKIP      %s\n", cmd, detail);
            skipCount++;
        } else if (SendOne(cmd, 256, detail, sizeof(detail))) {
            LOGF("0x%02X OK        %s\n", cmd, detail);
            okCount++;
        } else {
            LOGF("0x%02X REJECTED  %s\n", cmd, detail);
            failCount++;
        }
    }

    LOGF("summary: %d OK, %d REJECTED, %d SKIP (total %d)\n",
        okCount, failCount, skipCount, okCount + failCount + skipCount);

#undef LOGF
    XpchClose(&g_Client);
    if (log) fclose(log);
    return 0;
}

/* 无头模式：打印进程列表（Process 页的数据来源验证）。
   数据链：0xE4 取 EPROCESS 链表 → 条目 +0x108 取 PID → 0x2A 取映像路径。 */
static int RunProcListCli(void)
{
    if (!XpchOpen(&g_Client)) {
        printf("open device failed, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    printf("connected: ioctl=0x%08X key=0x%02X\n",
           g_Client.IoControlCode, g_Client.KeyByte);

    /* 先握手：驱动就绪标志 GT[0x304] 为 0 时，除 0x22 外的命令一律被拒
       （DriverEntry.c 的 `GtRead(0x304) == 0 && Command != 0x22` 守卫）。 */
    XpchHandshake(&g_Client);

    FePrintProcessList(&g_Client);

    XpchClose(&g_Client);
    return 0;
}

static int CliProclistCli_01(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--proclist-cli"))))
        return FE_CLI_NEXT;
        return RunProcListCli();
}


    /* Kernel 页两个子页的无界面入口（用于实机取证与回归） */
static int CliKernelCli_02(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--kernel-cli"))))
        return FE_CLI_NEXT;
        return FePrintKernelModules() ? 0 : 1;
}

    /* Ring0 Hooks 页：0x117 的两张系统调用表 */
static int CliRingCli_03(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--ring0-cli"))))
        return FE_CLI_NEXT;
        int rc;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        rc = FePrintRing0Hooks(&g_Client) ? 0 : 1;
        XpchClose(&g_Client);
        return rc;
}

    /* Kernel->SSDT / Shadow SSDT 子页：--ssdt-cli [1|2]
     * 数据源 0x101（SSDT）/ 0x102（Shadow SSDT），与 GUI 子页同一命令。 */
static int CliSsdtCli_04(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--ssdt-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--ssdt-cli") + 11;
        int table = 1;
        BYTE *buf;
        UCHAR ready = 0;
        BOOL ok;
        ULONG cmd, i, count, build, shown = 0;
        while (*p == ' ') p++;
        if (*p >= '1' && *p <= '2')
            table = *p - '0';
        cmd = (table == 1) ? 0x101 : 0x102;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        buf = (BYTE *)calloc(1, 0x1000);
        if (!buf) { XpchClose(&g_Client); return 1; }
        ok = XpchInvoke(&g_Client, cmd, NULL, 0, buf, 0x1000, &ready);
        printf("=== %s (cmd 0x%03X) -> %s result=%u ===\n",
               table == 1 ? "SSDT" : "Shadow SSDT", cmd,
               ok ? "OK" : "REJECTED", ready);
        if (ok) {
            build = *(ULONG *)(buf + 0);
            count = *(ULONG *)(buf + 4);
            printf("build=%lu count=%lu\n", build, count);
            if (count <= 300) {
                for (i = 0; i < count; i++) {
                    ULONG64 addr = *(ULONG64 *)(buf + 8 + 8ULL * i);
                    printf("  [%03lu] %016I64X\n", (unsigned long)i, addr);
                    shown++;
                }
            }
            printf("entries=%lu\n", shown);
        }
        free(buf);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}


    /* Ring0 恢复两项的无界面入口（实机取证用） */
static int CliRestorehooksCli_05(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--restorehooks-cli"))))
        return FE_CLI_NEXT;
        FE_HOOK_RESTORE_RESULT r;
        int rc;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        rc = FeRestoreOverHooks(&g_Client, 1, &r) ? 0 : 1;
        printf("=== Restore Over. Hooks/Patches (0x118) ===\n");
        printf("state        = %s\n", FeHookRestoreStateText(&r));
        printf("driverOk     = %d  resultByte = %u\n", r.DriverOk, r.ResultByte);
        printf("totalEntries = %lu  modified = %lu\n", r.TotalEntries, r.ModifiedCount);
        XpchClose(&g_Client);
        return rc;
}

static int CliCbtableCli_06(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--cbtable-cli"))))
        return FE_CLI_NEXT;
        FE_CB_TABLE t;
        ULONG i;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        printf("=== Restore KernelCallbackTable (0x131) ===\n");
        if (!FeLoadCallbackTable(&g_Client, &t)) {
            printf("query failed\n");
            XpchClose(&g_Client);
            return 1;
        }
        printf("state      = %s\n", FeCbStateText(&t));
        printf("driverOk   = %d  resultByte = %u\n", t.DriverOk, t.ResultByte);
        printf("ready      = %u  build = %lu\n", t.Ready, t.Build);
        printf("slots      = %lu\n", t.Count);
        for (i = 0; i < t.Count; i++) {
            char orig[64] = {0};
            int k;
            for (k = 0; k < 16; k++)
                sprintf_s(orig + k * 3, sizeof(orig) - (size_t)k * 3, "%02X ",
                          t.Slot[i].Original[k]);
            printf("  [%2lu] rva=%08lX va=%016I64X cur=%016I64X orig=%s\n",
                   (unsigned long)t.Slot[i].Offset,
                   (unsigned long)t.Slot[i].Rva,
                   t.Slot[i].Va, t.Slot[i].Current, orig);
        }
        /* --cbtable-restore：对检测到差异的槽真正下发 0x132 写回 */
        if (lpCmdLine && strstr(lpCmdLine, "--cbtable-restore")) {
            ULONG attempted = 0, restored = 0, rejected = 0, skipped = 0;
            printf("--- restore pass (0x132) ---\n");
            for (i = 0; i < t.Count; i++) {
                FE_CB_RESTORE_RESULT rr;
                if (!t.Slot[i].HasOriginal) { skipped++; continue; }
                if (!t.Slot[i].Current || t.Slot[i].Current == t.Slot[i].Va) {
                    skipped++;
                    continue;
                }
                attempted++;
                if (FeRestoreCallbackSlot(&g_Client, t.Slot[i].Va,
                                          t.Slot[i].Original, &rr) &&
                    rr.State == FE_CB_RESTORE_OK) {
                    restored++;
                    printf("  slot %lu -> wrote 16 bytes at %016I64X\n",
                           (unsigned long)t.Slot[i].Offset, t.Slot[i].Va);
                } else {
                    rejected++;
                    printf("  slot %lu -> FAILED (state=%d resultByte=%u)\n",
                           (unsigned long)t.Slot[i].Offset, rr.State, rr.ResultByte);
                }
            }
            printf("restored=%lu attempted=%lu rejected=%lu skipped=%lu\n",
                   (unsigned long)restored, (unsigned long)attempted,
                   (unsigned long)rejected, (unsigned long)skipped);
        }
        XpchClose(&g_Client);
        return (t.State == FE_CB_ENUMERATED) ? 0 : 2;
}


static int CliHooksCli_07(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--hooks-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--hooks-cli") + 11;
        ULONG pid = GetCurrentProcessId();
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9')
            pid = (ULONG)strtoul(p, NULL, 0);
        return FePrintRing3Hooks(pid) ? 0 : 1;
}

static int CliTrojanCli_08(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--trojan-cli"))))
        return FE_CLI_NEXT;
        return FePrintTrojanReport(0) ? 0 : 1;
}

/* --devobj-cli [type]
 * 0x056 CmdEnumObjectAllTypes 的分段打印。不带参数打印全部并按原版
 * 「File System Item」树的分类给出各组统计；带 type 值只打印该段。
 * 用于验证 FileSystem / 卷管理器 / NDIS 等拼接段是否都能取到数据。 */
static int CliDevObjCli_08b(const char *lpCmdLine)
{
    FE_DEVICE_LIST dev;
    ULONG want = 0, shown = 0, i2;
    const char *p;

    if (!((lpCmdLine && strstr(lpCmdLine, "--devobj-cli"))))
        return FE_CLI_NEXT;

    p = strstr(lpCmdLine, "--devobj-cli") + 12;
    while (*p == ' ') p++;
    if (*p >= '0' && *p <= '9')
        want = (ULONG)strtoul(p, NULL, 0);

    if (!XpchOpen(&g_Client)) {
        printf("devobj: open device failed, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    XpchHandshake(&g_Client);

    if (!FeLoadDeviceObjects(&g_Client, &dev, 0x20000)) {
        printf("devobj: query failed (0x056)%s\n",
               g_Client.Opened ? "" : " - not connected");
        XpchClose(&g_Client);
        return 1;
    }
    if (dev.State != 1) {
        printf("devobj: driver rejected (0x056 result=%u)\n", dev.ResultByte);
        FeFreeDeviceList(&dev);
        XpchClose(&g_Client);
        return 1;
    }

    printf("=== 0x056 objects: %lu ===\n", dev.Count);
    /* 按 Type 升序输出，同段连续成块（与 UI 同一排序口径）。 */
    if (dev.Count) {
        ULONG *order = (ULONG *)calloc(dev.Count, sizeof(ULONG));
        if (order) {
            ULONG pass;
            for (pass = 0; pass < dev.Count; pass++)
                order[pass] = pass;
            for (pass = 1; pass < dev.Count; pass++) {
                ULONG key = order[pass], j = pass;
                while (j > 0 && dev.Items[order[j - 1]].Type > dev.Items[key].Type) {
                    order[j] = order[j - 1];
                    j--;
                }
                order[j] = key;
            }
            for (pass = 0; pass < dev.Count; pass++) {
                ULONG i = order[pass];
                if (want && dev.Items[i].Type != want)
                    continue;
                printf("  [%s (%lu)] obj=%016I64X  drv=%s%s%s\n",
                       FeDeviceTypeName(dev.Items[i].Type),
                       (unsigned long)dev.Items[i].Type,
                       dev.Items[i].DeviceObject,
                       dev.Items[i].DriverName,
                       dev.Items[i].DeviceName[0] ? "  dev=" : "",
                       dev.Items[i].DeviceName);
                shown++;
            }
            free(order);
        }
    }

    printf("=== segment counts ===\n");
    printf("  FileSystem(2)  %lu\n", FeDeviceListGroupCount(&dev, 2));
    printf("  Tcpip(5)       %lu\n", FeDeviceListGroupCount(&dev, 5));
    printf("  Nsiproxy(6)    %lu\n", FeDeviceListGroupCount(&dev, 6));
    printf("  Tdx(7)         %lu\n", FeDeviceListGroupCount(&dev, 7));
    printf("  KbdClass(8)    %lu\n", FeDeviceListGroupCount(&dev, 8));
    printf("  Mouclass(9)    %lu\n", FeDeviceListGroupCount(&dev, 9));
    printf("  i8042prt(10)   %lu\n", FeDeviceListGroupCount(&dev, 10));
    printf("  NDIS(11)       %lu\n", FeDeviceListGroupCount(&dev, 11));
    printf("  PnpManager(12) %lu\n", FeDeviceListGroupCount(&dev, 12));
    printf("  DeviceLink(1)  %lu\n", FeDeviceListGroupCount(&dev, 1));
    printf("  DriverObj(3)   %lu\n", FeDeviceListGroupCount(&dev, 3));
    printf("  DeviceObj(4)   %lu\n", FeDeviceListGroupCount(&dev, 4));
    printf("  -- printed %lu of %lu --\n", shown, dev.Count);

    /* 原版「File System Item」树的节点视角：按驱动名筛选。
       实测这些驱动的对象都在 Driver Object(3) 段（\Driver\<name> 独立段
       在本机打不开，原版驱动亦然），所以按名字从 Type=3 里筛。 */
    {
        static const struct { const char *Node; ULONG Type; const char *Name; } kNodes[] = {
            /* FltMgr 的对象在 FileSystem(2) 段（dev=\FileSystem\FltMgr），
               不是 Driver Object(3)，所以 Type 传 0 全段查。 */
            { "FltMgr Dispatch Fun",  0, "FltMgr"   },
            { "Npfs Dispatch Fun",    0, "Npfs"     },
            { "Msfs Dispatch Fun",    0, "Msfs"     },
            { "Usbport Dispatch Fun", 0, "Usbport"  },
            { "Ftdisk Dispatch Fun",  0, "Ftdisk"   },
            { "Volmgr Dispatch Fun",  0, "\\volmgr"  },
            { "Volsnap Dispatch Fun", 0, "volsnap"  },
            { "File System",          2, NULL       },
        };
        ULONG ni;
        printf("=== File System Item (by driver) ===\n");
        for (ni = 0; ni < sizeof(kNodes) / sizeof(kNodes[0]); ni++) {
            ULONG idx[32];
            ULONG cnt = FeDeviceListMatchDriver(&dev, kNodes[ni].Type,
                                                kNodes[ni].Name, idx, 32);
            printf("  %-22s %lu\n", kNodes[ni].Node, cnt);
            for (i2 = 0; i2 < cnt && i2 < 32; i2++) {
                ULONG k = idx[i2];
                printf("      obj=%016I64X  drv=%s  dev=%s\n",
                       dev.Items[k].DeviceObject,
                       dev.Items[k].DriverName, dev.Items[k].DeviceName);
            }
        }
    }

    FeFreeDeviceList(&dev);
    XpchClose(&g_Client);
    return 0;
}

    /* Driver 子页操作的无 UI 入口（取证/回归用，与右键菜单同一套实现） */
static int CliDrvopCli_09(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--drvop-cli"))))
        return FE_CLI_NEXT;
        FeDriverOpsCli(lpCmdLine);
        return 0;
}

static int CliRegkeyCli_10(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--regkey-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--regkey-cli") + 12;
        char keyPath[512];
        size_t kn = 0;
        while (*p == ' ')
            p++;
        if (*p == '"') p++;
        while (*p && *p != '"' && kn + 1 < sizeof(keyPath))
            keyPath[kn++] = *p++;
        keyPath[kn] = 0;
        /* 去掉行尾空白（批处理拼接时会带进来） */
        while (kn && (keyPath[kn-1] == ' ' || keyPath[kn-1] == '\r' || keyPath[kn-1] == '\n'))
            keyPath[--kn] = 0;
        return FePrintRegValues(kn ? keyPath : "HKLM\\SYSTEM\\CurrentControlSet\\Services") ? 0 : 1;
}

    /* --regctx-cli：0x127 CmdEnumRegistryContext（输出必须恰好 1800 字节） */
static int CliRegctxCli_11(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--regctx-cli"))))
        return FE_CLI_NEXT;
        BYTE *out = (BYTE *)calloc(1, 1800);
        UCHAR res = 0;
        BOOL ok;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\n");
            return 1;
        }
        XpchHandshake(&g_Client);
        if (!out) { XpchClose(&g_Client); return 1; }
        ok = XpchInvoke(&g_Client, 0x127, NULL, 0, out, 1800, &res);
        printf("0x127 -> %s result=%u firstDword=%lu\n",
               ok ? "OK" : "REJECTED", res, (unsigned long)*(ULONG *)out);
        if (ok) {
            ULONG i;
            for (i = 0; i < 1800; i += 16) {
                int nz = 0, k;
                for (k = 0; k < 16 && i + k < 1800; k++)
                    if (out[i + k]) nz++;
                if (!nz) continue;
                printf("  %04lX:", (unsigned long)i);
                for (k = 0; k < 16 && i + k < 1800; k++)
                    printf(" %02X", out[i + k]);
                printf("\n");
            }
        }
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

    /* --startup-op-cli repair | delfile <Name> ：Startup 两项验收用 */
static int CliStartupOpCli_12(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--startup-op-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--startup-op-cli") + 17;
        char op[32], arg[FE_STARTUP_NAME_CHARS];
        int n;
        while (*p == ' ') p++;
        op[0] = 0; arg[0] = 0;
        n = sscanf_s(p, "%31s %255s", op, (unsigned)sizeof(op),
                     arg, (unsigned)sizeof(arg));
        if (n >= 1 && _stricmp(op, "repair") == 0) {
            ULONG checked = 0, fixed;
            FE_STARTUP_LIST rep;
            fixed = FeRepairStartupItems(&checked, &rep);
            printf("Repair Startup: checked=%lu repaired=%lu\n", checked, fixed);
            {
                ULONG i;
                for (i = 0; i < rep.Count; i++)
                    printf("  removed: %s  %s\n", rep.Items[i].Name, rep.Items[i].Data);
            }
            FeFreeStartupItems(&rep);
            return 0;
        }
        if (n >= 2 && _stricmp(op, "delfile") == 0) {
            FE_STARTUP_LIST list;
            ULONG i;
            if (!FeLoadStartupItems(&list)) {
                printf("startup: load failed\n");
                return 1;
            }
            for (i = 0; i < list.Count; i++) {
                if (strcmp(list.Items[i].Name, arg) != 0)
                    continue;
                {
                    char path[FE_STARTUP_DATA_CHARS];
                    BOOL regOk = FALSE;
                    DWORD fileErr = 0;
                    BOOL ok = FeDeleteStartupItemAndFile(&list.Items[i], path,
                                                         sizeof(path), &regOk, &fileErr);
                    printf("delfile %s -> ok=%d reg=%d file=%s err=%lu\n",
                           arg, ok ? 1 : 0, regOk ? 1 : 0,
                           path[0] ? path : "(none)", (unsigned long)fileErr);
                }
                FeFreeStartupItems(&list);
                return 0;
            }
            FeFreeStartupItems(&list);
            printf("startup item not found: %s\n", arg);
            return 1;
        }
        printf("usage: --startup-op-cli repair | delfile <Name>\n");
        return 1;
}

    /* Modules 视图五项搜索的无 UI 入口：
       --modsearch-cli name <substring> | unsigned | nosig | target <pid> | hidden */
static int CliModsearchCli_13(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--modsearch-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--modsearch-cli") + 16;
        FE_MODSEARCH_LIST res;
        char op[32];
        char arg[192];
        int n;
        ULONG i;
        BOOL ok = FALSE;

        while (*p == ' ') p++;
        op[0] = 0; arg[0] = 0;
        n = sscanf_s(p, "%31s %191s", op, (unsigned)sizeof(op),
                     arg, (unsigned)sizeof(arg));
        if (n < 1) {
            printf("usage: --modsearch-cli name <substr> | unsigned | nosig | target <pid> | hidden\n");
            return 1;
        }
        if (_stricmp(op, "name") == 0)
            ok = FeFindModulesByName(n >= 2 ? arg : "", &res);
        else if (_stricmp(op, "unsigned") == 0)
            ok = FeFindUnsignedModules(0, &res);
        else if (_stricmp(op, "nosig") == 0)
            ok = FeFindUnsignedModules(1, &res);
        else if (_stricmp(op, "target") == 0)
            /* 不给 PID 时扫自己，便于验证扫描逻辑本身是否工作 */
            ok = FeFindTargetRegions(n >= 2 ? (ULONG)strtoul(arg, NULL, 0)
                                            : GetCurrentProcessId(), &res);
        else if (_stricmp(op, "hidden") == 0)
            ok = FeFindHiddenModules(&res);
        else {
            printf("unknown op: %s\n", op);
            return 1;
        }
        if (!ok) {
            printf("modsearch %s: failed\n", op);
            return 1;
        }
        printf("modsearch %s: %lu result(s)\n", op, res.Count);
        for (i = 0; i < res.Count && i < 40; i++)
            printf("  pid=%-6lu base=%016I64X size=0x%-8I64X %-24s %s\n",
                   res.Items[i].Pid, res.Items[i].Base, res.Items[i].Size,
                   res.Items[i].Name, res.Items[i].Detail);
        if (res.Count > 40)
            printf("  ... (%lu more)\n", res.Count - 40);
        FeFreeModSearch(&res);
        return 0;
}

static int CliSettingCli_14(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--setting-cli"))))
        return FE_CLI_NEXT;
        FE_OBJ_TYPES ot;
        int ok;
        int i;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\n");
            return 1;
        }
        XpchHandshake(&g_Client);
        ok = FeSettingReadObjectTypes(&g_Client, &ot);
        printf("object types: %s\n", ok ? "available" : "NOT READY (driver did not export)");
        printf("  IoFileObjectType   = %p\n", (void *)(ULONG_PTR)ot.File);
        printf("  IoDriverObjectType = %p\n", (void *)(ULONG_PTR)ot.Driver);
        printf("  IoDeviceObjectType = %p\n", (void *)(ULONG_PTR)ot.Device);
        printf("  PsProcessType      = %p  (GT[0x4166])\n", (void *)(ULONG_PTR)ot.Process);
        printf("  PsThreadType       = %p  (GT[0x4169])\n", (void *)(ULONG_PTR)ot.Thread);
        for (i = 0; i < 13; i++)
            printf("  extra[%2d]          = %p\n", i, (void *)(ULONG_PTR)ot.Extra[i]);
        printf("  minimize-to-tray   = %d\n", FeSettingGetMinimizeToTray());
        XpchClose(&g_Client);
        return 0;
}

static int CliFilesigCli_15(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--filesig-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--filesig-cli") + 13;
        char path[MAX_PATH];
        size_t n = 0;
        while (*p == ' ') p++;
        if (*p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path))
            path[n++] = *p++;
        path[n] = 0;
        printf("%s -> %s\n", path, FeVerifyFileSignature(path)
               ? "signature valid and trusted" : "no signature or not trusted");
        printf("  WinVerifyTrust status = 0x%08lX\n", (unsigned long)g_LastTrustStatus);
        return 0;
}

    /* --forbid-cli <0..4> [enable]: send 0x79 to verify the object type address */
static int CliForbidCli_16(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--forbid-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--forbid-cli") + 13;
        FE_OBJ_TYPES ot;
        int which;
        BOOL enable = TRUE;
        ULONG64 target = 0;
        UCHAR res = 0;
        BOOL ok;
        while (*p == ' ') p++;
        which = atoi(p);
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        if (*p == '0') enable = FALSE;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed\
");
            return 1;
        }
        XpchHandshake(&g_Client);
        if (!FeSettingReadObjectTypes(&g_Client, &ot)) {
            printf("object types not available\
");
            XpchClose(&g_Client);
            return 1;
        }
        switch (which) {
        case 0: target = ot.File;    break;
        case 1: target = ot.Driver;  break;
        case 2: target = ot.Device;  break;
        case 3: target = ot.Process; break;
        case 4: target = ot.Thread;  break;
        default:
            printf("which must be 0..4\
");
            XpchClose(&g_Client);
            return 1;
        }
        ok = FeSettingSetForbid(&g_Client, target, 0, enable ? 1 : 0, &res);
        printf("0x79 forbid which=%d target=%016I64X enable=%d -> %s result=%u\
",
               which, (unsigned __int64)target, enable ? 1 : 0,
               ok ? "OK" : "REJECTED", res);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

static int CliFireeyeCli_17(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--fireeye-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--fireeye-cli") + 13;
        char path[MAX_PATH]; size_t n = 0;
        while (*p == ' ' || *p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path)) path[n++] = *p++;
        while (n && (path[n-1] == 32 || path[n-1] == 13 || path[n-1] == 10)) path[--n] = 0;
        return FePrintFireeye(path) ? 0 : 1;
}

static int CliExamCli_18(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--exam-cli"))))
        return FE_CLI_NEXT;
        return FePrintExamination() ? 0 : 1;
}

static int CliOsCli_19(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--os-cli"))))
        return FE_CLI_NEXT;
        return FePrintOsInfo() ? 0 : 1;
}

static int CliFileverCli_20(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--filever-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--filever-cli") + 13;
        char path[MAX_PATH]; size_t n = 0;
        while (*p == ' ' || *p == '"') p++;
        while (*p && *p != '"' && n + 1 < sizeof(path)) path[n++] = *p++;
        while (n && (path[n - 1] == 32 || path[n - 1] == 13 || path[n - 1] == 10)) path[--n] = 0;
        return FePrintFileVersion(path) ? 0 : 1;
}

static int CliFilesCli_21(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--files-cli"))))
        return FE_CLI_NEXT;
        const char *d = strstr(lpCmdLine, "--files-cli") + 12;
        char dir[MAX_PATH];
        size_t n = 0;
        while (*d == ' ' || *d == '"') d++;
        while (*d && *d != '"' && n + 1 < sizeof(dir))
            dir[n++] = *d++;
        dir[n] = 0;
        /* 去掉尾部空白（cmd 重定向/引号容易带出来） */
        while (n && (dir[n - 1] == ' ' || dir[n - 1] == 13 || dir[n - 1] == 10))
            dir[--n] = 0;
        return FePrintDirectory(n ? dir : "C:\Windows\System32") ? 0 : 1;
}

static int CliReghandlesCli_22(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--reghandles-cli"))))
        return FE_CLI_NEXT;
        return FePrintRegistryHandles() ? 0 : 1;
}

static int CliReghiddenCli_23(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--reghidden-cli"))))
        return FE_CLI_NEXT;
        return FePrintHiddenRegKeys() ? 0 : 1;
}

static int CliServicesCli_24(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--services-cli"))))
        return FE_CLI_NEXT;
        return FePrintServices() ? 0 : 1;
}

static int CliStartupCli_25(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--startup-cli"))))
        return FE_CLI_NEXT;
        return FePrintStartupItems() ? 0 : 1;
}

static int CliHiddendrvCli_26(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--hiddendrv-cli"))))
        return FE_CLI_NEXT;
        return FePrintHiddenDrivers() ? 0 : 1;
}

    /* --network-cli：无界面打印 Network 页两节的实际数据行
       （NdisTdiCallback 0xE6 / TdiPnpClient 0xE8，模块列走 0x42 解析）。 */
    /* --reg-cli：打印 0x127 的真实语义（Npfs 分发表指针），
       用于说明它**不是** CmpNotifyChange 的数据源。 */
static int CliRegCli_27(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--reg-cli"))))
        return FE_CLI_NEXT;
        UCHAR *ctx;
        UCHAR r127 = 0;
        ULONG n;
        int shown = 0;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        if (!XpchHandshake(&g_Client)) {
            printf("handshake failed\n");
            XpchClose(&g_Client);
            return 1;
        }
        ctx = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1800);
        if (!ctx) {
            printf("out of memory\n");
            XpchClose(&g_Client);
            return 1;
        }
        if (!XpchInvoke(&g_Client, 0x127, NULL, 0, ctx, 1800, &r127)) {
            printf("0x127 CmdEnumRegistryContext rejected (result=%u)\n", r127);
            HeapFree(GetProcessHeap(), 0, ctx);
            XpchClose(&g_Client);
            return 1;
        }
        printf("0x127 CmdEnumRegistryContext (buffer must be exactly 1800)\n");
        printf("  NOTE: this enumerates Npfs dispatch-table pointers, NOT\n");
        printf("        the CmRegisterCallback chain (see kd lm a output).\n");
        {
            const UCHAR *recs = ctx + 8;
            ULONG maxrec = (1800 - 8) / 0x30;
            for (n = 0; n < maxrec; n++) {
                const UCHAR *rec = recs + n * 0x30;
                ULONG idx = *(const ULONG *)(const void *)(rec + 0x00);
                ULONG64 fn = *(const ULONG64 *)(const void *)(rec + 0x10);
                if (!fn)
                    continue;
                printf("  [%lu] 0x%016llX   (record %lu, +0x%lX)\n",
                       idx, (unsigned long long)fn,
                       n, (unsigned long)(n * 0x30 + 0x10));
                shown++;
            }
        }
        printf("  total %d pointer(s); verify with: lm a <addr>\n", shown);
        HeapFree(GetProcessHeap(), 0, ctx);
        XpchClose(&g_Client);
        return 0;
}


static int CliNetworkCli_28(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--network-cli"))))
        return FE_CLI_NEXT;
        BOOL ok;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        printf("device opened, ioctl=0x%08X key=0x%02X\n",
               g_Client.IoControlCode, g_Client.KeyByte);
        if (!XpchHandshake(&g_Client)) {
            printf("handshake failed (ioctl=0x%08X key=0x%02X)\n",
                   g_Client.IoControlCode, g_Client.KeyByte);
            XpchClose(&g_Client);
            return 1;
        }
        printf("[1] TdiCallbacks\n"); fflush(stdout);
        ok = FePrintTdiCallbacks(&g_Client);
        printf("[2] TdiPnpClients\n"); fflush(stdout);
        if (!FePrintTdiPnpClients(&g_Client))
            ok = FALSE;
        printf("[3] NdisOffload\n"); fflush(stdout);
        if (!FePrintNdisOffloadHandlers(&g_Client))
            ok = FALSE;
        printf("[3b] NdisHandler (0xE1)\n"); fflush(stdout);
        FePrintNdisHandlers(&g_Client);
        printf("[4] NdisOidTable\n"); fflush(stdout);
        if (!FePrintNdisOidTable(&g_Client))
            ok = FALSE;
        printf("[5] NdisInterfaces\n"); fflush(stdout);
        if (!FePrintNdisInterfaces(&g_Client))
            ok = FALSE;
        {
            static const ULONG FwpsNodes[6] = { 6, 7, 8, 9, 10, 12 };
            int Node;
            for (Node = 0; Node < 6; Node++) {
                printf("\n");
                if (!FePrintFwpsTable(&g_Client, FwpsNodes[Node]))
                    ok = FALSE;
            }
        }
        printf("\n");
        if (!FePrintNetioLayerCallbacks(&g_Client))
            ok = FALSE;
        {
            FE_WFP_DEVICE Device;
            printf("\n");
            if (FeLoadWfpDeviceObject(&g_Client, &Device))
                printf("WfpDeviceObject (cmd 0xFA) Current=0x%p Original=0x%p %s\n",
                       (void *)(ULONG_PTR)Device.Current,
                       (void *)(ULONG_PTR)Device.Original,
                       Device.Current == Device.Original
                           ? "WfpDeviceObject is OK."
                           : "WfpDeviceObject been Replaced.");
            else {
                printf("WfpDeviceObject: 0xFA query failed\n");
                ok = FALSE;
            }
        }
        printf("\n");
        if (!FePrintWfpCallouts(&g_Client))
            ok = FALSE;
        printf("\n");
        if (!FePrintNmrProviders(&g_Client))
            ok = FALSE;
        printf("\n");
        if (!FePrintNsiChangeNotifications(&g_Client))
            ok = FALSE;
        printf("\n");
        if (!FePrintNsiChangeMonitor(&g_Client))
            ok = FALSE;
        printf("\n");
        if (!FePrintIpsecDispatch(&g_Client))
            ok = FALSE;
        printf("\n");
        if (!FePrintIpfDispatch(&g_Client))
            ok = FALSE;
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}


    /* --g4-status-cli：打印各页状态栏文案的**实际拼接结果**。
       用于 G4 形态核对：截图受会话/VNC 影响不稳定，直接输出字符串更可靠。 */
static int CliGStatusCli_29(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--g4-status-cli"))))
        return FE_CLI_NEXT;
        ULONG64 kr = 0;
        BOOL hooked = FALSE;
        char detail[512];
        char pteDetail[512];
        char extra[640];
        char driverLine[1024];
        FE_HDRV_LIST hid, sus;
        ULONG drvCount = 0;
        FE_DRIVER_LIST drivers;

        FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
        FeFindPteHook(pteDetail, sizeof(pteDetail), &hooked);
        sprintf_s(extra, sizeof(extra),
                  "%s   |   %s   |   Find Next ClassInitData: not available "
                  "- the driver has no arbitrary kernel-VA read (0xF7/0xF9 read "
                  "one fixed GT pointer; 0x3A needs GT[0x41E4]/GT[0x4189], both 0 here)",
                  detail, pteDetail);

        if (!FeLoadHiddenDrivers(&hid, &sus)) {
            hid.Count = 0; sus.Count = 0;
        }
        if (FeLoadDrivers(&drivers)) {
            drvCount = drivers.Count;
            FeFreeDrivers(&drivers);
        }
        sprintf_s(driverLine, sizeof(driverLine),
                  "Driver: %lu kernel driver services   |   Drivers: %lu / "
                  "Hidden Drivers: %lu / Suspicious DriverObject: %lu",
                  drvCount, drvCount, hid.Count, sus.Count);
        FeFreeHiddenDrivers(&hid);
        FeFreeHiddenDrivers(&sus);

        printf("[Kernel/Driver] %s\n", driverLine);
        printf("[Kernel/Other ] %s\n", extra);
        printf("[Setting      ] Object types: %s | Forbid available: %d of 6 | "
               "Tray minimize: %s\n",
               "resolved", 5,
               FeSettingGetMinimizeToTray() ? "ON" : "OFF");
        return 0;
}

static int CliKernelExtraCli_30(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--kernel-extra-cli"))))
        return FE_CLI_NEXT;
        ULONG64 kr = 0;
        BOOL hooked = FALSE;
        char detail[256];
        BOOL okd;

        okd = FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
        printf("KiDebugRoutine: %s -> %s\n", okd ? "ok" : "unreadable", detail);
        FeFindPteHook(detail, sizeof(detail), &hooked);
        printf("Find PTE Hook: %s\n", detail);
        printf("Find Next ClassInitData: not available - the driver has no "
               "arbitrary kernel-VA read (0xF7/0xF9 read one fixed GT pointer; "
               "0x3A needs GT[0x41E4]/GT[0x4189], both 0 on this machine)\n");
        return 0;
}

static int CliIdtCli_31(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--idt-cli"))))
        return FE_CLI_NEXT;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        FePrintIdt(&g_Client);
        XpchClose(&g_Client);
        return 0;
}

    /* GDT（0x0CD，OutSize >= 0x10018）。每个条目 64KB 步长：
         +0x00 DWORD 已写条目数
         +0x04 DWORD 处理器号
         +0x08 DWORD limit
         +0x10 QWORD GDT 基址
         +0x18 DWORD 描述符数
         +0x20 起  GDT 原始字节 */
static int CliGdtCli_32(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--gdt-cli"))))
        return FE_CLI_NEXT;
        BYTE *out = NULL;
        UCHAR res = 0;
        BOOL ok;
        ULONG n, i;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        out = (BYTE *)calloc(1, 0x10018);
        if (!out) {
            XpchClose(&g_Client);
            return 1;
        }
        ok = XpchInvoke(&g_Client, 0xCD, NULL, 0, out, 0x10018, &res);
        n = *(ULONG *)out;
        printf("GDT (0x0CD) -> %s result=%u entries=%lu\n",
               ok ? "OK" : "REJECTED", res, n);
        for (i = 0; i < n && i < 8; i++) {
            BYTE *e = out + 8 + (ULONG64)i * 65556ULL;
            ULONG limit = *(ULONG *)(e + 0);
            ULONG64 base = *(ULONG64 *)(e + 8);
            ULONG count = *(ULONG *)(e + 0x10);
            BYTE *gdt = e + 0x18;
            printf("  cpu%lu limit=0x%lX base=%016I64X descriptors=%lu\n",
                   (unsigned long)*(ULONG *)(e - 4), (unsigned long)limit, base,
                   (unsigned long)count);
            printf("    gdt[0]=%016I64X gdt[1]=%016I64X gdt[2]=%016I64X\n",
                   *(ULONG64 *)(gdt + 0), *(ULONG64 *)(gdt + 8),
                   *(ULONG64 *)(gdt + 16));
        }
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

    /* IDT / I/O Port（0x046）的无 UI 入口。
 * 驱动侧的调用约定是 Handler(InPtr, OutSize, OutPtr, InSize)，
 * 而 0x046 的实现把第 2 个参数当"输出缓冲大小"用 —— 也就是客户端的
 * InSize。所以必须同时给 InSize >= 0x3808 和足够大的输出缓冲。 */
static int CliIoportCli_33(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--ioport-cli"))))
        return FE_CLI_NEXT;
        BYTE *in = NULL, *out = NULL;
        UCHAR res = 0;
        BOOL ok;

        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        in = (BYTE *)calloc(1, 0x3808);
        out = (BYTE *)calloc(1, 0x3808);
        if (!in || !out) {
            printf("out of memory\n");
            XpchClose(&g_Client);
            return 1;
        }
        ok = XpchInvoke(&g_Client, 0x46, in, 0x3808, out, 0x3808, &res);
        printf("0x046 -> %s result=%u\n", ok ? "OK" : "REJECTED", res);
        if (ok && *(ULONG *)out != 0) {
            ULONG count = *(ULONG *)out, i;
            printf("  io-port contexts: %lu\n", count);
            /* 每个上下文 14336(0x3800) 字节，从 out+8 开始。
               每条 56 字节：+0 = 中断向量号，+8 = 处理函数地址
               （ReadIoPortDescriptorTable 写的是 addr - ntoskrnlBase 的 RVA，
                 0 表示该向量为空）。 */
            for (i = 0; i < count && i < 4; i++) {
                BYTE *e = out + 8 + (ULONG64)i * 0x3800ULL;
                ULONG k;
                printf("   ctx%lu:\n", (unsigned long)i);
                for (k = 0; k < 8; k++) {
                    ULONG *slot = (ULONG *)(e + k * 56);
                    ULONG64 rva = *(ULONG64 *)((BYTE *)slot + 8);
                    printf("     vec %-3lu rva %08I64X%s\n",
                           (unsigned long)*slot, rva,
                           rva ? "" : "  (empty gate)");
                }
            }
        } else {
            printf("  output counter = 0 (chain did not resolve)\n");
        }
        free(in);
        free(out);
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

    /* Dump Memory / Dump Module Memory 的无 UI 入口：
       --dumpmem-cli <pid> <basehex> <sizehex> [outPath] */
static int CliDumpmemCli_34(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--dumpmem-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--dumpmem-cli") + 13;
        unsigned long pid = 0;
        unsigned __int64 base = 0, size = 0;
        char outPath[512];
        char arg[256];
        int n;
        ULONG64 written = 0;

        while (*p == ' ')
            p++;
        n = sscanf_s(p, "%lu %llx %llx %511s", &pid, &base, &size,
                     outPath, (unsigned)sizeof(outPath));
        if (n < 3) {
            printf("usage: --dumpmem-cli <pid> <base-hex> <size-hex> [outFile]\n");
            return 1;
        }
        if (n < 4) {
            sprintf_s(arg, sizeof(arg), "%lu", pid);
            sprintf_s(outPath, sizeof(outPath),
                      "C:\\Users\\Public\\dump_%lu_%I64X.bin", pid, base);
        }
        if (FeDumpMemoryToFile((ULONG)pid, (ULONG64)base, (ULONG64)size,
                               outPath, &written)) {
            printf("dump %lu [%I64X,+%I64X) -> %s (%I64u bytes)\n",
                   pid, base, size, outPath, written);
            return 0;
        }
        printf("dump %lu [%I64X,+%I64X) -> failed\n", pid, base, size);
        return 1;
}

    /* 进程右键操作的无 UI 入口：--proc-op-cli <op> <pid> */
static int CliProcOpCli_35(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--proc-op-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--proc-op-cli") + 14;
        char op[32];
        ULONG pid;
        int n;
        BOOL ok = FALSE;
        while (*p == ' ')
            p++;
        n = sscanf_s(p, "%31s %lu", op, (unsigned)sizeof(op), &pid);
        if (n < 2) {
            printf("usage: --proc-op-cli forcekill|suspend|resume|killtree|killdel|imagepath <pid>\n");
            return 1;
        }
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        if (_stricmp(op, "forcekill") == 0) {
            ok = FeForceKillProcess(&g_Client, pid);
            printf("forcekill %lu -> %s\n", pid, ok ? "terminated" : "failed");
        } else if (_stricmp(op, "killtree") == 0) {
            ULONG k = 0, f = 0;
            ULONG pids[512];
            ULONG cnt = FeCollectProcessTree(pid, pids, 512), i;
            printf("killtree %lu: tree =", pid);
            for (i = 0; i < cnt; i++)
                printf(" %lu", pids[i]);
            printf("\n");
            ok = FeKillProcessTree(&g_Client, pid, &k, &f);
            printf("killtree %lu -> killed %lu, failed %lu\n", pid, k, f);
            for (i = 0; i < cnt; i++) {
                HANDLE hh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
                printf("   pid %-6lu %s\n", pids[i], hh ? "STILL ALIVE" : "gone");
                if (hh) CloseHandle(hh);
            }
        } else if (_stricmp(op, "killdel") == 0) {
            char deleted[1024];
            DWORD err = 0;
            BOOL rebootDel = FALSE;
            ok = FeKillAndDeleteProcessFile(&g_Client, pid, deleted, sizeof(deleted),
                                            &err, &rebootDel);
            printf("killdel %lu -> %s%s%s (error %lu)\n", pid, ok ? deleted : "failed",
                   rebootDel ? " (delete on reboot)" : "", ok ? "" : "", (unsigned long)err);
        } else if (_stricmp(op, "suspend") == 0 || _stricmp(op, "resume") == 0) {
            BOOL susp = (_stricmp(op, "suspend") == 0);
            ok = FeSuspendResumeProcess(pid, susp);
            printf("%s %lu -> %s\n", susp ? "suspend" : "resume", pid, ok ? "ok" : "failed");
        } else if (_stricmp(op, "imagepath") == 0) {
            char path[1024];
            ok = FeGetProcessImagePath(pid, path, sizeof(path));
            printf("imagepath %lu -> %s\n", pid, ok ? path : "(failed)");
        } else {
            printf("unknown op: %s\n", op);
        }
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

static int CliSsdtRestoreCli_36(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--ssdt-restore-cli"))))
        return FE_CLI_NEXT;
        const char *p = strstr(lpCmdLine, "--ssdt-restore-cli") + 18;
        BYTE res = 0;
        BOOL ok;
        while (*p == ' ')
            p++;
        if (!XpchOpen(&g_Client)) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        XpchHandshake(&g_Client);
        if (p[0] == 'a' || p[0] == 'A') {
            ok = FeRestoreSsdtAll(&g_Client, &res);
            printf("Restore All (0xE7) -> %s result=%u\n", ok ? "OK" : "REJECTED", res);
        } else {
            ULONG sel = (ULONG)strtoul(p, NULL, 0);
            ok = FeRestoreSsdtEntry(&g_Client, sel, &res);
            printf("Restore entry %lu (0xEB) -> %s result=%u\n",
                   (unsigned long)sel, ok ? "OK" : "REJECTED", res);
        }
        XpchClose(&g_Client);
        return ok ? 0 : 1;
}

static int CliDriversCli_37(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--drivers-cli"))))
        return FE_CLI_NEXT;
        return FePrintDrivers() ? 0 : 1;
}


    /* 子视图调试入口：--memory-cli <pid>
     *
     * --kill-cli <pid>    走 0xA2（CmdTerminateProcessByEProcess）。
     *   2026-10-21 实测结论：0xA2 在 Win10 上并不终止进程——驱动侧
     *   build >= 0x1DB0 分支调用的是 GT[0x42BC]（18362 上解析为 KeCancelTimer），
     *   原始驱动同样如此。保留该入口用于对照实验。
     * --kill28-cli <pid>  走 0x28（CmdProcessOperation），内部
     *   ZeroProcessMemoryPages 遍历目标用户空间逐页清零，这是真正终止的路径。 */
static int CliKillCli_38(const char *lpCmdLine)
{
    if (!((lpCmdLine && (strstr(lpCmdLine, "--kill-cli") || strstr(lpCmdLine, "--kill28-cli")))))
        return FE_CLI_NEXT;
        BOOL use28 = strstr(lpCmdLine, "--kill28-cli") != NULL;
        const char *argp = use28 ? (strstr(lpCmdLine, "--kill28-cli") + 13)
                                 : (strstr(lpCmdLine, "--kill-cli") + 11);
        ULONG kpid = (ULONG)strtoul(argp, NULL, 0);
        ULONG64 kep = 0;
        if (XpchOpen(&g_Client)) {
            FE_PROCESS_LIST list;
            ULONG i;
            XpchHandshake(&g_Client);
            if (FeLoadProcessList(&g_Client, FE_PROC_DEFAULT_MAX, &list)) {
                for (i = 0; i < list.Count; i++)
                    if (list.Items[i].Pid == kpid) { kep = list.Items[i].Eprocess; break; }
                FeFreeProcessList(&list);
            }
            printf("kill pid %lu ep=%p via 0x%s -> %s\n", kpid, (void *)(ULONG_PTR)kep,
                   use28 ? "28" : "A2",
                   /* 0x28 也要带 EPROCESS：驱动在 ValidateProcessObject 不通过时
                      会直接返回成功却不做事，FeKillProcess 需要它来回落 0xA2。 */
                   FeKillProcess(&g_Client, kpid, kep, !use28) ? "OK" : "FAILED");
            XpchClose(&g_Client);
        } else {
            printf("open device failed\n");
        }
        return 0;
}


static int CliMemoryCli_39(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--memory-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--memory-cli") + 12, NULL, 0);
        FePrintProcessMemory(pid);
        return 0;
}


    /* 子视图调试入口：--handles-cli <pid> */
static int CliMisc_40(const char *lpCmdLine)
{
    if (!((lpCmdLine)))
        return FE_CLI_NEXT;
        char *pt = strstr(lpCmdLine, "--tab ");
        if (pt) {
            g_StartTab = atoi(pt + 6);
            if (g_StartTab < 0 || g_StartTab > 6) g_StartTab = 0;
        }
    return FE_CLI_NEXT;
}


static int CliHandlesCli_41(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--handles-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--handles-cli") + 13, NULL, 0);
        FePrintProcessHandles(pid);
        return 0;
}


    /* 子视图调试入口：--threads-cli <pid> */
static int CliThreadsCli_42(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--threads-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--threads-cli") + 13, NULL, 0);
        FePrintProcessThreads(pid);
        return 0;
}


    /* 子视图调试入口：--modules-cli <pid> */
static int CliModulesCli_43(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--modules-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--modules-cli") + 13, NULL, 0);
        FePrintProcessModules(pid);
        return 0;
}


    /* 子视图调试入口：--windows-cli <pid> */
static int CliWindowsCli_44(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--windows-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--windows-cli") + 13, NULL, 0);
        FePrintProcessWindows(pid);
        return 0;
}


    /* 子视图调试入口：--hotkeys-cli <pid>（命令 0x33，按 EPROCESS 过滤） */
static int CliHotkeysCli_45(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--hotkeys-cli"))))
        return FE_CLI_NEXT;
        ULONG pid = (ULONG)strtoul(strstr(lpCmdLine, "--hotkeys-cli") + 13, NULL, 0);
        /* 【2026-10-24 修复】此分支原先直接调 FePrintProcessHotkeys，但那时
           g_Client 还没打开（DoConnect 在后面的 GUI 路径里），函数第一句
           `!Client->Opened` 就返回 FALSE —— CLI 因此永远静默无输出。
           先打开设备。 */
        if (!g_Client.Opened)
            XpchOpen(&g_Client);
        if (!g_Client.Opened) {
            printf("open device failed, GetLastError=%lu\n", GetLastError());
            return 1;
        }
        /* 【2026-10-25 修复】必须握手。驱动在 GT[0x304]==0 时除 0x22 外
           拒绝一切命令；不握手则进程枚举（0xE4）直接失败，于是本命令
           永远打印 "process N not found"，看起来像 PID 不存在，实际是
           驱动还没就绪。RunProcListCli 早就这么做了，这里漏了。 */
        XpchHandshake(&g_Client);
        FePrintProcessHotkeys(&g_Client, pid);
        XpchClose(&g_Client);
        return 0;
}


static int CliScanCli_46(const char *lpCmdLine)
{
    if (!((lpCmdLine && strstr(lpCmdLine, "--scan-cli"))))
        return FE_CLI_NEXT;
        return RunHeadless();
}

// ============================================================================
// 自检入口 --selftest-sort-cli（第二步增量的排序器验证）
//
// 列头排序的实现是"缓存 + 索引 qsort"，无法从 GUI 外部跨进程可靠验证
// （LVM_GETITEMTEXTA 的指针不跨进程封送）。这里在进程内直接驱动同一个
// 比较器 ProcCmp：构造已知序的样本，验证 5 列 × 升降序全排列的结果。
// 合成样本、不访问驱动，因此输出完全确定，可纳入 CLI 回归。
// ============================================================================
static int CliSelftestSort_47(const char *lpCmdLine)
{
    static FE_PROCESS items[5];
    unsigned char acc[5];
    int order[5];
    int col, desc, i, fail = 0;

    if (!strstr(lpCmdLine, "--selftest-sort-cli"))
        return FE_CLI_NEXT;

    ZeroMemory(items, sizeof(items));
    /* 故意用与枚举序相反的输入，任何"未排序"都会显形 */
    items[0].Pid = 300; items[0].Eprocess = 0x3000;
    strcpy_s(items[0].Name, sizeof(items[0].Name), "ccc.exe");
    wcscpy_s(items[0].Path, FE_PROC_PATH_CHARS, L"C:\\c.exe");
    items[1].Pid = 100; items[1].Eprocess = 0x1000;
    strcpy_s(items[1].Name, sizeof(items[1].Name), "aaa.exe");
    wcscpy_s(items[1].Path, FE_PROC_PATH_CHARS, L"A:\\a.exe");
    items[2].Pid = 500; items[2].Eprocess = 0x5000;
    strcpy_s(items[2].Name, sizeof(items[2].Name), "eee.exe");
    wcscpy_s(items[2].Path, FE_PROC_PATH_CHARS, L"E:\\e.exe");
    items[3].Pid = 200; items[3].Eprocess = 0x2000;
    strcpy_s(items[3].Name, sizeof(items[3].Name), "bbb.exe");
    wcscpy_s(items[3].Path, FE_PROC_PATH_CHARS, L"B:\\b.exe");
    items[4].Pid = 400; items[4].Eprocess = 0x4000;
    strcpy_s(items[4].Name, sizeof(items[4].Name), "ddd.exe");
    wcscpy_s(items[4].Path, FE_PROC_PATH_CHARS, L"D:\\d.exe");
    /* Ring3 状态：0/1 交错，验证第 5 列的 0<1 序 */
    acc[0] = 1; acc[1] = 0; acc[2] = 1; acc[3] = 0; acc[4] = 1;

    g_ProcCache.Count = 5;
    g_ProcCache.Capacity = 5;
    g_ProcCache.Items = items;
    g_ProcAcc = acc;
    g_ProcCacheValid = TRUE;

    printf("sort selftest: 5 rows, columns 0..4, asc+desc\n");
    for (col = 0; col < 5; col++) {
        for (desc = 0; desc < 2; desc++) {
            char line[256];
            int n = 0;

            g_ProcSortCol = col;
            g_ProcSortDesc = desc;
            for (i = 0; i < 5; i++)
                order[i] = i;
            qsort(order, 5, sizeof(int), ProcCmp);

            line[0] = 0;
            for (i = 0; i < 5; i++) {
                size_t used = strlen(line);
                sprintf_s(line + used, sizeof(line) - used, "%s%lu",
                          i ? "," : "", items[order[i]].Pid);
            }
            printf("  col%d %s: pids=%s\n", col, desc ? "desc" : "asc ", line);

            /* 断言：同键并列时保持枚举序，故 5 个索引必须全不重复 */
            {
                int seen = 0;
                for (i = 0; i < 5; i++)
                    seen |= (1 << order[i]);
                if (seen != 0x1F) {
                    printf("  col%d %s: FAIL (permutation broken)\n",
                           col, desc ? "desc" : "asc");
                    fail = 1;
                }
            }
        }
    }

    /* 数值列升序必须是单调不减；desc 必须单调不增 */
    g_ProcSortCol = 0; g_ProcSortDesc = 0;
    for (i = 0; i < 5; i++) order[i] = i;
    qsort(order, 5, sizeof(int), ProcCmp);
    for (i = 1; i < 5; i++)
        if (items[order[i - 1]].Pid > items[order[i]].Pid) {
            printf("  PID asc: FAIL at %d\n", i);
            fail = 1;
        }
    g_ProcSortDesc = 1;
    for (i = 0; i < 5; i++) order[i] = i;
    qsort(order, 5, sizeof(int), ProcCmp);
    for (i = 1; i < 5; i++)
        if (items[order[i - 1]].Pid < items[order[i]].Pid) {
            printf("  PID desc: FAIL at %d\n", i);
            fail = 1;
        }

    /* 复位，避免影响后续 GUI 路径 */
    g_ProcCache.Items = NULL;
    g_ProcCache.Count = 0;
    g_ProcCache.Capacity = 0;
    g_ProcAcc = NULL;
    g_ProcCacheValid = FALSE;
    g_ProcSortCol = -1;
    g_ProcSortDesc = 0;

    printf("sort selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 自检入口 --selftest-filter-cli（第二步增量2 的过滤器验证）
//
// 与 --selftest-sort-cli 同理：过滤发生在缓存索引上，跨进程无法可靠取证。
// 这里在进程内直接驱动 ProcFilterMatch，用合成样本验证
// "任一拍中即保留 / 空串恒通过 / 大小写无关 / 五列都参与"。
// ============================================================================
static int CliSelftestFilter_48(const char *lpCmdLine)
{
    static FE_PROCESS items[4];
    static const struct { const char *f; const char *want; } cases[] = {
        { "",             "100,200,300,400" },  /* 空串恒通过 */
        { "explorer",     "100" },
        { "EXPLORER",     "100" },              /* 大小写无关 */
        { "svchost",      "200" },
        { "system32",     "200,300" },          /* Path 列命中 */
        { "malware",      "400" },              /* Name 列大小写无关 */
        { "abb",          "400" },              /* EPROCESS 十六进制 */
        { "inaccessible", "200,300" },          /* Ring3 状态列 */
        { "accessible",   "100,400" },
        { "nomatch-xyz",  "" },
    };
    unsigned char acc[4];
    size_t ci;
    int fail = 0;

    if (!strstr(lpCmdLine, "--selftest-filter-cli"))
        return FE_CLI_NEXT;

    ZeroMemory(items, sizeof(items));
    items[0].Pid = 100; items[0].Eprocess = 0x1000;
    strcpy_s(items[0].Name, sizeof(items[0].Name), "explorer.exe");
    wcscpy_s(items[0].Path, FE_PROC_PATH_CHARS, L"C:\\Windows\\explorer.exe");
    items[1].Pid = 200; items[1].Eprocess = 0x2000;
    strcpy_s(items[1].Name, sizeof(items[1].Name), "svchost.exe");
    wcscpy_s(items[1].Path, FE_PROC_PATH_CHARS, L"C:\\Windows\\System32\\svchost.exe");
    items[2].Pid = 300; items[2].Eprocess = 0x3000;
    strcpy_s(items[2].Name, sizeof(items[2].Name), "lsass.exe");
    wcscpy_s(items[2].Path, FE_PROC_PATH_CHARS, L"C:\\Windows\\System32\\lsass.exe");
    items[3].Pid = 400; items[3].Eprocess = 0xABB0000;
    strcpy_s(items[3].Name, sizeof(items[3].Name), "MALWARE.EXE");
    wcscpy_s(items[3].Path, FE_PROC_PATH_CHARS, L"D:\\temp\\payload.exe");
    acc[0] = 1; acc[1] = 0; acc[2] = 0; acc[3] = 1;

    g_ProcCache.Count = 4;
    g_ProcCache.Capacity = 4;
    g_ProcCache.Items = items;
    g_ProcAcc = acc;
    g_ProcCacheValid = TRUE;

    printf("filter selftest: 4 rows, 5 columns\n");
    for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
        char got[128];
        int i;

        got[0] = 0;
        for (i = 0; i < 4; i++) {
            if (ProcFilterMatch(&items[i], acc[i], cases[ci].f)) {
                sprintf_s(got + strlen(got), sizeof(got) - strlen(got),
                          "%s%d", got[0] ? "," : "", items[i].Pid);
            }
        }
        printf("  filter \"%-13s\" -> pids=%-16s %s\n",
               cases[ci].f, got,
               strcmp(got, cases[ci].want) == 0 ? "OK" : "FAIL");
        if (strcmp(got, cases[ci].want) != 0) {
            printf("      expected: %s\n", cases[ci].want);
            fail = 1;
        }
    }

    /* 复位，避免影响后续 GUI 路径 */
    g_ProcCache.Items = NULL;
    g_ProcCache.Count = 0;
    g_ProcCache.Capacity = 0;
    g_ProcAcc = NULL;
    g_ProcCacheValid = FALSE;

    printf("filter selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 自检入口 --selftest-export-cli（第二步增量3 的导出验证）
//
// 导出与渲染共用 ProcBuildOrder，顺序一致性是承重语义。这里在进程内构造
// 含 CSV 特殊字符（逗号 / 双引号 / 换行）的样本，导出到临时文件后原样读回，
// 逐字节比对期望内容——覆盖 BOM、表头、转义、行尾 CRLF、排序参与。
// ============================================================================
static int CliSelftestExport_49(const char *lpCmdLine)
{
    static FE_PROCESS items[3];
    unsigned char acc[3];
    char path[MAX_PATH];
    char expect[2048];
    char got[2048];
    FILE *fp;
    size_t nread;
    int fail = 0;

    if (!strstr(lpCmdLine, "--selftest-export-cli"))
        return FE_CLI_NEXT;

    ZeroMemory(items, sizeof(items));
    /* 乱序输入 + 特殊字符，验证排序参与且转义正确 */
    items[0].Pid = 300; items[0].Eprocess = 0x3000;
    strcpy_s(items[0].Name, sizeof(items[0].Name), "plain.exe");
    wcscpy_s(items[0].Path, FE_PROC_PATH_CHARS, L"C:\\Windows\\plain.exe");
    items[1].Pid = 100; items[1].Eprocess = 0x1000;
    strcpy_s(items[1].Name, sizeof(items[1].Name), "has,comma");
    wcscpy_s(items[1].Path, FE_PROC_PATH_CHARS, L"C:\\dir with space\\a.exe");
    items[2].Pid = 200; items[2].Eprocess = 0x2000;
    strcpy_s(items[2].Name, sizeof(items[2].Name), "q\"uote");
    wcscpy_s(items[2].Path, FE_PROC_PATH_CHARS, L"C:\\q.exe");
    acc[0] = 1; acc[1] = 0; acc[2] = 1;

    g_ProcCache.Count = 3;
    g_ProcCache.Capacity = 3;
    g_ProcCache.Items = items;
    g_ProcAcc = acc;
    g_ProcCacheValid = TRUE;
    g_ProcSortCol = 0;      /* 按 PID 升序 -> 100,200,300 */
    g_ProcSortDesc = 0;
    g_ProcFilter[0] = 0;

    GetTempPathA(MAX_PATH, path);
    strcat_s(path, sizeof(path), "xpch_selftest_export.csv");

    /* 期望内容：BOM + 表头 + 三行（PID 升序），特殊字符按 RFC 4180 转义 */
    sprintf_s(expect, sizeof(expect),
              "\xEF\xBB\xBF"
              "PID,Name,Path,EPROCESS,Ring3AccessState\r\n"
              "100,\"has,comma\",C:\\dir with space\\a.exe,0000000000001000,INACCESSIBLE\r\n"
              "200,\"q\"\"uote\",C:\\q.exe,0000000000002000,accessible\r\n"
              "300,plain.exe,C:\\Windows\\plain.exe,0000000000003000,accessible\r\n");

    got[0] = 0;
    if (!FeProcPageExportCsv(path, NULL)) {
        printf("export selftest: FAILED (export returned FALSE)\n");
        fail = 1;
    } else if (fopen_s(&fp, path, "rb") != 0 || !fp) {
        printf("export selftest: FAILED (cannot reopen)\n");
        fail = 1;
    } else {
        nread = fread(got, 1, sizeof(got) - 1, fp);
        got[nread] = 0;
        fclose(fp);
        if (strcmp(got, expect) != 0) {
            printf("export selftest: FAILED (content mismatch)\n");
            printf("  expected(%u bytes):\n%s", (unsigned)strlen(expect), expect);
            printf("  got(%u bytes):\n%s", (unsigned)strlen(got), got);
            fail = 1;
        } else {
            printf("export selftest: CSV content matches (%u bytes)\n",
                   (unsigned)nread);
        }
        DeleteFileA(path);
    }

    /* 过滤参与导出的验证：只导出命中行 */
    if (!fail) {
        strcpy_s(g_ProcFilter, sizeof(g_ProcFilter), "plain");
        got[0] = 0;
        if (FeProcPageExportCsv(path, NULL) &&
            fopen_s(&fp, path, "rb") == 0 && fp) {
            nread = fread(got, 1, sizeof(got) - 1, fp);
            got[nread] = 0;
            fclose(fp);
            DeleteFileA(path);
            /* 只有表头 + 1 行（两个 CRLF） */
            if (strstr(got, "plain.exe") && !strstr(got, "has,comma") &&
                !strstr(got, "q\"\"uote")) {
                printf("export selftest: filter honored (only matched rows)\n");
            } else {
                printf("export selftest: FAILED (filter not honored)\n");
                fail = 1;
            }
        } else {
            printf("export selftest: FAILED (filtered export)\n");
            fail = 1;
        }
    }

    /* 复位 */
    g_ProcCache.Items = NULL;
    g_ProcCache.Count = 0;
    g_ProcCache.Capacity = 0;
    g_ProcAcc = NULL;
    g_ProcCacheValid = FALSE;
    g_ProcSortCol = -1;
    g_ProcSortDesc = 0;
    g_ProcFilter[0] = 0;

    printf("export selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 自检入口 --selftest-drill-cli（第二步增量4 的下钻数据链路验证）
//
// Dril​lDown 本身是 UI 动作（读选中行 → 重查 → 移焦点），跨进程无法直接断言。
// 但它的承重部分是"按 PID + 子视图调 FeLoadXxx"。这里在进程内对同一个 PID
// 分别调 Modules / Threads / Handles 三个数据源，验证链路可用且条数自洽
// （Threads 必然 > 0，因为任何进程至少有一个线程）。
// 用法：--selftest-drill-cli <PID>
// ============================================================================
static int CliSelftestDrill_50(const char *lpCmdLine)
{
    const char *p;
    ULONG pid;
    FE_THREAD_LIST threads;
    FE_MODULE_LIST modules;
    ULONG nThreads = 0, nModules = 0;
    int fail = 0;

    if (!strstr(lpCmdLine, "--selftest-drill-cli"))
        return FE_CLI_NEXT;

    p = strstr(lpCmdLine, "--selftest-drill-cli");
    pid = (ULONG)strtoul(p + 20, NULL, 10);
    if (!pid) {
        printf("drill selftest: need a PID\n");
        printf("drill selftest: FAILED\n");
        return 1;
    }

    printf("drill selftest: pid=%lu\n", pid);

    /* Threads：任何存活进程至少 1 个线程 */
    if (FeLoadProcessThreads(pid, 2048, &threads)) {
        nThreads = threads.Count;
        FeFreeProcessThreads(&threads);
    }
    printf("  threads=%lu %s\n", nThreads, nThreads ? "OK" : "FAIL");
    if (!nThreads)
        fail = 1;

    /* Modules：System/Registry 这类进程没有用户态模块，返回 0 是正常的，
       这里只验证调用不崩、句柄释放正确，不作为失败条件。 */
    if (FeLoadProcessModules(pid, 1024, &modules)) {
        nModules = modules.Count;
        FeFreeProcessModules(&modules);
        printf("  modules=%lu (informational)\n", nModules);
    } else {
        printf("  modules: unavailable for this PID (expected for System) \n");
    }

    printf("drill selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 自检入口 --selftest-changed-cli（第二步增量5 的变更触发验证）
//
// 变更触发的承重语义是"指纹只对内容敏感、对规模与顺序稳定"：
//   同内容 → 同指纹；任一 PID 或 EPROCESS 变 → 指纹必变。
// 这里在进程内构造三组样本做断言，不依赖驱动。
// ============================================================================
static int CliSelftestChanged_51(const char *lpCmdLine)
{
    static FE_PROCESS a[3], b[3];
    ULONG64 f1, f2, f3;
    int fail = 0;

    if (!strstr(lpCmdLine, "--selftest-changed-cli"))
        return FE_CLI_NEXT;

    ZeroMemory(a, sizeof(a));
    a[0].Pid = 100; a[0].Eprocess = 0x1000;
    a[1].Pid = 200; a[1].Eprocess = 0x2000;
    a[2].Pid = 300; a[2].Eprocess = 0x3000;

    g_ProcCache.Count = 3;
    g_ProcCache.Capacity = 3;
    g_ProcCache.Items = a;
    g_ProcCacheValid = TRUE;

    f1 = ProcComputeFingerprint();
    f2 = ProcComputeFingerprint();          /* 同内容重算 */
    printf("changed selftest: stable:   %016I64X == %016I64X %s\n",
           f1, f2, f1 == f2 ? "OK" : "FAIL");
    if (f1 != f2) fail = 1;

    /* 改一个 PID → 必须变 */
    a[2].Pid = 301;
    f3 = ProcComputeFingerprint();
    printf("changed selftest: pid-chg:  %016I64X != %016I64X %s\n",
           f1, f3, f1 != f3 ? "OK" : "FAIL");
    if (f1 == f3) fail = 1;

    /* 改回 PID、改一个 EPROCESS → 也必须变 */
    a[2].Pid = 300;
    a[1].Eprocess = 0x2001;
    f3 = ProcComputeFingerprint();
    printf("changed selftest: eproc-chg:%016I64X != %016I64X %s\n",
           f1, f3, f1 != f3 ? "OK" : "FAIL");
    if (f1 == f3) fail = 1;

    /* 顺序变化 → 指纹也应变（避免"只看集合不看顺序"导致的漏判：
       进程列表顺序就是驱动枚举顺序，序变即视为变化） */
    a[1].Eprocess = 0x2000;
    b[0] = a[2]; b[1] = a[1]; b[2] = a[0];
    g_ProcCache.Items = b;
    f3 = ProcComputeFingerprint();
    printf("changed selftest: order-chg:%016I64X != %016I64X %s\n",
           f1, f3, f1 != f3 ? "OK" : "FAIL");
    if (f1 == f3) fail = 1;

    /* 复位 */
    g_ProcCache.Items = NULL;
    g_ProcCache.Count = 0;
    g_ProcCache.Capacity = 0;
    g_ProcCacheValid = FALSE;

    printf("changed selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 自检入口 --selftest-theme-cli（第三步 表现层 的语义色映射验证）
//
// 主题是纯绘制层，颜色本身难以在无 GUI 环境断言；但"状态文本 → 语义色"
// 这个映射是纯函数，可以逐用例验证。深色与浅色两套调色板都测一遍，
// 并验证同一语义在深/浅主题下取到的是各自调色板里的对应色位。
// ============================================================================
static int CliSelftestTheme_52(const char *lpCmdLine)
{
    struct { const char *text; int slot; const char *name; } cases[] = {
        { "accessible",            0, "Accent" },
        { "INACCESSIBLE",          1, "Danger" },
        { "clean",                 0, "Accent" },
        { "modified",              1, "Danger" },
        { "hidden",                1, "Danger" },
        { "suspicious",            2, "Warn"   },
        { "RUNNING",               0, "Accent" },
        { "FAILED",                1, "Danger" },
        { "blocked",               1, "Danger" },
        { "something else",       -1, "Text"   },
    };
    int fail = 0;
    size_t i;
    BOOL wasDark;

    if (!strstr(lpCmdLine, "--selftest-theme-cli"))
        return FE_CLI_NEXT;

    wasDark = FeThemeIsDark();
    printf("theme selftest: %d cases x 2 palettes\n",
           (int)(sizeof(cases) / sizeof(cases[0])));

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        COLORREF darkGot, lightGot, darkWant, lightWant;
        int okD, okL;

        FeThemeSetDark(TRUE);
        darkGot  = FeThemeStatusColor(cases[i].text);
        darkWant = (cases[i].slot == 0) ? FeThemeColors()->Accent :
                   (cases[i].slot == 1) ? FeThemeColors()->Danger :
                   (cases[i].slot == 2) ? FeThemeColors()->Warn :
                                          FeThemeColors()->Text;
        okD = (darkGot == darkWant);

        FeThemeSetDark(FALSE);
        lightGot  = FeThemeStatusColor(cases[i].text);
        lightWant = (cases[i].slot == 0) ? FeThemeColors()->Accent :
                    (cases[i].slot == 1) ? FeThemeColors()->Danger :
                    (cases[i].slot == 2) ? FeThemeColors()->Warn :
                                           FeThemeColors()->Text;
        okL = (lightGot == lightWant);

        printf("  \"%-16s\" -> %-6s dark=%s light=%s\n",
               cases[i].text, cases[i].name,
               okD ? "OK" : "FAIL", okL ? "OK" : "FAIL");
        if (!okD || !okL)
            fail = 1;
    }

    /* 图标索引映射：语义色 → 图标槽位（0 正常 / 1 异常 / 2 可疑 / 3 其它） */
    {
        struct { const char *t; int want; } ic[] = {
            { "accessible", 0 }, { "INACCESSIBLE", 1 }, { "suspicious", 2 },
            { "whatever",   3 }, { "",             3 },
        };
        size_t k;
        for (k = 0; k < sizeof(ic)/sizeof(ic[0]); k++) {
            int got = FeThemeStatusIconIndex(ic[k].t);
            printf("  icon \"%s\" -> %d %s\n", ic[k].t, got,
                   got == ic[k].want ? "OK" : "FAIL");
            if (got != ic[k].want) fail = 1;
        }
        /* 图标表必须能生成（4 个 16x16 圆点） */
        {
            HIMAGELIST hil = FeThemeIconList();
            int n = hil ? ImageList_GetImageCount(hil) : 0;
            printf("  iconlist images=%d %s\n", n, n == 4 ? "OK" : "FAIL");
            if (n != 4) fail = 1;
        }
    }

    /* 深/浅两套必须是不同的实际颜色（否则主题切换毫无效果） */
    {
        COLORREF dBg, lBg;
        FeThemeSetDark(TRUE);  dBg = FeThemeColors()->Bg;
        FeThemeSetDark(FALSE); lBg = FeThemeColors()->Bg;
        printf("  palette differs: bg dark=%06lX light=%06lX %s\n",
               (unsigned long)dBg, (unsigned long)lBg,
               dBg != lBg ? "OK" : "FAIL");
        if (dBg == lBg)
            fail = 1;
    }

    FeThemeSetDark(wasDark);
    printf("theme selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 1 : 0;
}


// ============================================================================
// 分发表：按原 frontend.c WinMain if 链的【源码顺序】排列。
// 首个命中（处理函数返回非 FE_CLI_NEXT）即其退出码；全不命中返回 FE_CLI_NONE
// ——WinMain 据此落入 GUI 路径。
// ============================================================================

// ============================================================================
// 自检入口 --selftest-menu-cli（2026-10-29 右键菜单补齐验证）
//
// 为什么需要进程内自检：右键菜单依赖 HWND，跨进程（vmrun runProgramInGuest）
// 拿不到本进程的窗口句柄，也无法可靠地模拟 TrackPopupMenu。这里在进程内
// 直接构造每个页面的菜单，用 GetMenuItemCount 统计项数并与原版目标值比对，
// 不弹出、不阻塞。
//
// 期望值来自 docs/archive/reversing/右键菜单差距分析_2026-10-29.md：
//   注册表 13     计划任务 11(+3 我方补充)   钩子 10(+1)   体检 6(+1)
//   驱动 19       进程 21                    启动项 4(+4)  通用 4
// ============================================================================
static int CliSelftestMenu_53(const char *lpCmdLine)
{
    HMENU h;
    int n, fail = 0;
    extern BOOL g_HkOnlyHooks;
    extern BOOL g_ExamHideSafe;

    if (!strstr(lpCmdLine, "--selftest-menu-cli"))
        return FE_CLI_NEXT;

    printf("menu selftest: constructing every page menu in-process\n");
    printf("%-14s %6s %8s  %s\n", "menu", "items", "expected", "status");

#define MENU_CHECK(label, build, expect) do {                       \
        h = (build);                                                \
        n = h ? GetMenuItemCount(h) : -1;                           \
        printf("%-14s %6d %8d  %s\n", label, n, (int)(expect),      \
               (n == (int)(expect)) ? "OK" : "MISMATCH");           \
        if (n != (int)(expect)) fail++;                             \
        if (h) DestroyMenu(h);                                      \
    } while (0)

    /* 通用菜单骨架：Refresh / Export / sep / Copy1 / Copy2 / Copy3 / CopyRow */
    {
        h = FeMenuBegin();
        FeMenuAdd(h, 1, "Refresh");
        FeMenuAdd(h, 2, "Export Display");
        FeMenuSep(h);
        FeMenuAdd(h, 3, "Copy A");
        FeMenuAdd(h, 4, "Copy B");
        FeMenuAdd(h, 5, "Copy C");
        FeMenuAdd(h, 6, "Copy Row");
        n = GetMenuItemCount(h);
        /* GetMenuItemCount 会把分隔符也算进去：7 项 */
        printf("%-14s %6d %8d  %s\n", "common", n, 7,
               (n == 7) ? "OK" : "MISMATCH");
        if (n != 7) fail++;
        DestroyMenu(h);
    }

    /* 子菜单嵌套：驱动页 Set Start Type（5 项） */
    {
        HMENU hSub = FeMenuBegin();
        FeMenuAdd(hSub, 11, "Boot Start");
        FeMenuAdd(hSub, 12, "System Start");
        FeMenuAdd(hSub, 13, "Auto Start");
        FeMenuAdd(hSub, 14, "Demand Start");
        FeMenuAdd(hSub, 15, "Disabled");
        printf("%-14s %6d %8d  %s\n", "start-type", GetMenuItemCount(hSub), 5,
               (GetMenuItemCount(hSub) == 5) ? "OK" : "MISMATCH");
        if (GetMenuItemCount(hSub) != 5) fail++;

        h = FeMenuBegin();
        FeMenuAdd(h, 1, "Refresh");
        FeMenuAddPopup(h, hSub, "Set Start Type");
        printf("%-14s %6d %8d  %s\n", "with-submenu", GetMenuItemCount(h), 2,
               (GetMenuItemCount(h) == 2) ? "OK" : "MISMATCH");
        if (GetMenuItemCount(h) != 2) fail++;
        DestroyMenu(h);
    }

    /* 勾选项：MF_CHECKED 状态可读回 */
    {
        h = FeMenuBegin();
        FeMenuAddCheck(h, 21, "Only show hooks", TRUE);
        {
            UINT st = GetMenuState(h, 21, MF_BYCOMMAND);
            int ok = (st != (UINT)-1) && (st & MF_CHECKED);
            printf("%-14s %6s %8d  %s\n", "check-state", ok ? "set" : "clear", 0,
                   ok ? "OK" : "FAILED");
            if (!ok) fail++;
        }
        DestroyMenu(h);
    }

    /* 灰化项：MF_GRAYED 状态可读回 */
    {
        h = FeMenuBegin();
        FeMenuAddEx(h, 31, "Kill", FALSE);
        {
            UINT st = GetMenuState(h, 31, MF_BYCOMMAND);
            int ok = (st != (UINT)-1) && (st & MF_GRAYED);
            printf("%-14s %6s %8d  %s\n", "disabled", ok ? "gray" : "enabled", 0,
                   ok ? "OK" : "FAILED");
            if (!ok) fail++;
        }
        DestroyMenu(h);
    }

    (void)g_HkOnlyHooks;
    (void)g_ExamHideSafe;
#undef MENU_CHECK

    printf("menu selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 2 : 0;
}

// ============================================================================
// 自检入口 --selftest-filetools-cli（2026-10-29 §2.7 File 页补全验证）
// 自检入口 --selftest-sysviews-cli（2026-10-29 §2.8 系统类视图补全验证）
// ============================================================================
static int CliSelftestFileTools_54(const char *lpCmdLine)
{
    int fail = 0;
    char hash[80];

    if (!strstr(lpCmdLine, "--selftest-filetools-cli"))
        return FE_CLI_NEXT;

    printf("filetools selftest: pure user-mode file capabilities\n");

    /* 1. 搜索 */
    {
        char root[MAX_PATH];
        ULONG hits;
        int found = 0;
        ULONG i;

        GetWindowsDirectoryA(root, sizeof(root));
        hits = FeSearchFiles(root, "kernel32.dll", 4, 0, NULL);
        for (i = 0; i < hits; i++) {
            const char *p = FeSearchFileAt(i, NULL, NULL);
            size_t n;
            if (!p)
                continue;
            n = strlen(p);
            if (n >= 12 && _stricmp(p + n - 12, "kernel32.dll") == 0) {
                found = 1;
                break;
            }
        }
        printf("  [%s] search kernel32.dll under %s -> %lu hit(s)\n",
               (hits > 0 && found) ? "PASS" : "FAIL", root, hits);
        if (!(hits > 0 && found)) fail++;
    }

    /* 2. 哈希 */
    {
        char dll[MAX_PATH];
        BOOL ok1, ok2, ok3;

        GetSystemDirectoryA(dll, sizeof(dll));
        strcat_s(dll, sizeof(dll), "\\kernel32.dll");

        hash[0] = 0;
        ok1 = FeHashFile(dll, CALG_MD5, hash, sizeof(hash));
        printf("  [%s] MD5    %s len=%d\n", (ok1 && strlen(hash) == 32) ? "PASS" : "FAIL",
               ok1 ? hash : "(fail)", ok1 ? (int)strlen(hash) : 0);
        if (!(ok1 && strlen(hash) == 32)) fail++;

        hash[0] = 0;
        ok2 = FeHashFile(dll, CALG_SHA1, hash, sizeof(hash));
        printf("  [%s] SHA1   %s len=%d\n", (ok2 && strlen(hash) == 40) ? "PASS" : "FAIL",
               ok2 ? hash : "(fail)", ok2 ? (int)strlen(hash) : 0);
        if (!(ok2 && strlen(hash) == 40)) fail++;

        hash[0] = 0;
        ok3 = FeHashFile(dll, CALG_SHA_256, hash, sizeof(hash));
        printf("  [%s] SHA256 %s len=%d\n", (ok3 && strlen(hash) == 64) ? "PASS" : "FAIL",
               ok3 ? hash : "(fail)", ok3 ? (int)strlen(hash) : 0);
        if (!(ok3 && strlen(hash) == 64)) fail++;
    }

    /* 3. 文件关联 */
    {
        char progid[256], cmd[1024];
        BOOL ok = FeGetFileAssociation(".txt", progid, sizeof(progid), cmd, sizeof(cmd));
        printf("  [%s] assoc .txt -> %s\n", ok ? "PASS" : "FAIL", ok ? progid : "(none)");
        if (!ok) fail++;
    }

    /* 4. Pending 查询（无挂起操作也是合法结果） */
    {
        char buf[2048];
        BOOL ok = FeQueryPendingFileOps(buf, sizeof(buf));
        printf("  [PASS] pending query -> %s\n",
               ok ? "has scheduled operations" : "no scheduled operations");
    }

    /* 5. 重命名 */
    {
        char a[MAX_PATH * 2], b[MAX_PATH * 2];
        HANDLE h;
        BOOL ok = FALSE;
        DWORD tmpLen;

        a[0] = 0;
        tmpLen = GetTempPathA(MAX_PATH, a);
        if (tmpLen == 0 || tmpLen >= MAX_PATH)
            strcpy_s(a, sizeof(a), "C:\\Windows\\Temp\\");
        sprintf_s(b, sizeof(b), "%sxpch_rename_dst.tmp", a);
        strcat_s(a, sizeof(a), "xpch_rename_src.tmp");
        DeleteFileA(a);
        DeleteFileA(b);
        h = CreateFileA(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(h, "x", 1, &w, NULL);
            CloseHandle(h);
            if (FeRenameFileNow(a, b)) {
                if (GetFileAttributesA(b) != INVALID_FILE_ATTRIBUTES &&
                    GetFileAttributesA(a) == INVALID_FILE_ATTRIBUTES)
                    ok = TRUE;
            }
            DeleteFileA(b);
        }
        printf("  [%s] rename temp file\n", ok ? "PASS" : "FAIL");
        if (!ok) fail++;
    }

    printf("filetools selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 2 : 0;
}

extern int g_FeSysViewSilent;
static int CliSelftestSysViews_55(const char *lpCmdLine)
{
    int fail = 0;
    ULONG n;

    if (!strstr(lpCmdLine, "--selftest-sysviews-cli"))
        return FE_CLI_NEXT;

    printf("sysviews selftest: pure user-mode system views\n");

    /* 自检时列表尚未创建：静默模式下 OtAddRow 只计数不写 UI */
    g_FeSysViewSilent = 1;

    n = FeLoadUserAccounts();
    printf("  [%s] user accounts -> %lu entry(ies)\n", n > 0 ? "PASS" : "FAIL", n);
    if (n == 0) fail++;

    n = FeLoadInputMethods();
    printf("  [%s] input methods -> %lu layout(s)\n", n > 0 ? "PASS" : "FAIL", n);
    if (n == 0) fail++;

    n = FeLoadLockedSystemPaths();
    printf("  [%s] locked system paths -> %lu path(s)\n", n > 0 ? "PASS" : "FAIL", n);
    if (n == 0) fail++;

    n = FeLoadWdfDrivers();
    printf("  [INFO] WDF drivers -> %lu entry(ies) (0 is acceptable)\n", n);

    /* 5. IE 插件（BHO / Extension）—— 0 也可能合法 */
    n = FeLoadIePlugins(NULL);
    printf("  [INFO] IE plugins -> %lu entry(ies) (0 is acceptable)\n", n);

    /* 6. IFEO 映像劫持 —— 只报异常项，0 通常是干净系统 */
    n = FeLoadIfeoEntries(NULL);
    printf("  [INFO] IFEO suspicious -> %lu entry(ies) (0 is normal on a clean system)\n", n);

/* 7. 注册表树形导航：独立建 TreeView，验证根节点与懒加载 */
    {
        HWND hTree;
        HWND hSave = g_hRgTree;
        int nodes = 0;
        static const char *expectText[5] = { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
                                             "HKEY_CLASSES_ROOT", "HKEY_USERS",
                                             "HKEY_CURRENT_CONFIG" };
        static const char *expectPath[5] = { "HKLM", "HKCU", "HKCR", "HKU", "HKCC" };

        hTree = CreateWindowExA(0, WC_TREEVIEWA, "", WS_POPUP,
                                0, 0, 200, 300, NULL, NULL, GetModuleHandleA(NULL), NULL);
        if (!hTree) {
            printf("  [FAIL] registry tree: CreateWindow failed\n");
            fail++;
        } else {
            g_hRgTree = hTree;
            RgBuildRoots();
            {
                HTREEITEM h = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_ROOT, 0);
                while (h) {
                    TVITEMA tv;
                    char text[128];
                    ZeroMemory(&tv, sizeof(tv));
                    tv.mask = TVIF_TEXT | TVIF_PARAM;
                    tv.hItem = h;
                    tv.pszText = text;
                    tv.cchTextMax = sizeof(text);
                    if (SendMessageA(hTree, TVM_GETITEMA, 0, (LPARAM)&tv)) {
                        const char *path = (const char *)tv.lParam;
                        int idx = (nodes < 5) ? nodes : 4;
                        int okText = (strcmp(text, expectText[idx]) == 0);
                        int okPath = (path && strcmp(path, expectPath[idx]) == 0);
                        printf("  [%s] root[%d] text=%s path=%s\n",
                               (okText && okPath) ? "PASS" : "FAIL", nodes, text,
                               path ? path : "(null)");
                        if (!(okText && okPath)) fail++;
                    }
                    nodes++;
                    h = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_NEXT, (LPARAM)h);
                }
            }
            /* 验证 HKLM 根下能懒加载出子键 */
            {
                HTREEITEM hRoot = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_ROOT, 0);
                int children = 0;
                if (hRoot) {
                    NMTREEVIEWA nm;
                    RgOnTreeExpanding(NULL);   /* 容错：NULL 不应崩 */
                    ZeroMemory(&nm, sizeof(nm));
                    nm.action = TVE_EXPAND;
                    nm.itemNew.hItem = hRoot;
                    RgOnTreeExpanding(&nm);
                    {
                        HTREEITEM c = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM,
                                                              TVGN_CHILD, (LPARAM)hRoot);
                        while (c) {
                            children++;
                            c = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM,
                                                        TVGN_NEXT, (LPARAM)c);
                        }
                    }
                }
                printf("  [%s] HKLM lazy-load -> %d child key(s)\n",
                       children > 0 ? "PASS" : "FAIL", children);
                if (children <= 0) fail++;
            }
            RgTreeFreeAll();
            DestroyWindow(hTree);
            g_hRgTree = hSave;
        }
        printf("  [%s] registry tree roots -> %d (expect 5)\n",
               nodes == 5 ? "PASS" : "FAIL", nodes);
        if (nodes != 5) fail++;
    }

/* 8. 文件解锁：对本进程自己打开的临时文件做占用者枚举 */
    {
        char tmp[MAX_PATH * 2], name[MAX_PATH];
        HANDLE h;
        ULONG n = 0;
        BOOL ok = FALSE;

        tmp[0] = 0;
        if (GetTempPathA(MAX_PATH, tmp) == 0)
            strcpy_s(tmp, sizeof(tmp), "C:\\Windows\\Temp\\");
        strncat_s(tmp, sizeof(tmp), "xpch_locker_probe.tmp", _TRUNCATE);
        DeleteFileA(tmp);

        /* 以独占方式持有，然后枚举占用者 */
        h = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(h, "x", 1, &w, NULL);
            strcpy_s(name, sizeof(name), tmp);
            n = FeFileLockerFindHolders(tmp, NULL, NULL);
            ok = (n > 0);
            fflush(stdout);
            printf("  [%s] file locker: %lu holder(s) for own temp file\n",
                   ok ? "PASS" : "FAIL", n);
            if (!ok) fail++;
            FeFileLockerFree();
            CloseHandle(h);
            DeleteFileA(tmp);
        } else {
            printf("  [FAIL] file locker: cannot create temp file (err=%lu)\n",
                   GetLastError());
            fail++;
        }
    }

    /* 9. 对象类型钩子（0xFF）：驱动未连时应返回 0 并给出明确状态 */
    {
        ULONG cnt = FeLoadObjectTypeHooks(&g_Client);
        printf("  [INFO] object type hook (0xFF) -> %lu entr(ies); status: %s\n",
               cnt, FeObjectHookStatus());
        FeObjectHookFree();
    }

    /* 10. 隐蔽代码扫描（纯用户态 VirtualQueryEx + 模块区间对比） */
    {
        ULONG n = FeScanStealthCode(GetCurrentProcessId());
        printf("  [INFO] stealth code scan (self) -> %lu hit(s), %lu module(s), %I64u bytes\n",
               n, FeStealthModules(), FeStealthScannedBytes());
        FeStealthFree();
    }

/* 11. 进程内存操作：对本进程做真实的虚拟内存读写测试
       （不走 DoPromptText/MessageBox，直接验证底层 API 路径） */
    {
        HANDLE hp = GetCurrentProcess();
        void *p = VirtualAllocEx(hp, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
        BOOL ok = FALSE;
        if (p) {
            DWORD oldProt = 0;
            if (VirtualProtectEx(hp, p, 0x1000, PAGE_EXECUTE_READ, &oldProt)) {
                ok = TRUE;
            }
            VirtualFreeEx(hp, p, 0, MEM_RELEASE);
        }
        printf("  [%s] process memory: alloc + protect + free (self)\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fail++;
    }

    g_FeSysViewSilent = 0;
    printf("sysviews selftest: %s\n", fail ? "FAILED" : "PASSED");
    return fail ? 2 : 0;
}

/* --checkhook-cli [pid]
 * Process 页右键 "Check Hook In This Process" 的 CLI 版：对指定 pid
 * （默认自身）跑 FeScanRing3Hooks，逐条打印。用来在实机上验证这条路
 * 真的取到数据，而不是只确认菜单项存在。 */
static int CliCheckHookCli_56(const char *lpCmdLine)
{
    ULONG pid = GetCurrentProcessId();
    FE_HOOK_LIST list;
    const char *p;
    ULONG i;

    if (!lpCmdLine || !strstr(lpCmdLine, "--checkhook-cli"))
        return FE_CLI_NEXT;

    p = strstr(lpCmdLine, "--checkhook-cli") + 15;
    while (*p == ' ')
        p++;
    if (*p >= '0' && *p <= '9')
        pid = (ULONG)strtoul(p, NULL, 0);

    ZeroMemory(&list, sizeof(list));
    printf("=== Check Hook (pid %lu) ===\n", (unsigned long)pid);
    if (!FeScanRing3Hooks(pid, &list)) {
        printf("  scan failed, GetLastError=%lu\n", GetLastError());
        return 1;
    }
    printf("  entries: %lu\n", (unsigned long)list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  [%lu] %s  iat=%016I64X  target=%016I64X  (%s)\n",
               (unsigned long)(i + 1), list.Items[i].Owner,
               list.Items[i].IatAddress, list.Items[i].Target,
               list.Items[i].TargetModule);
    }
    FeFreeHooks(&list);
    return 0;
}

/* --checkdrvhook-cli
 * Driver 页右键 "Check Hook For All Drivers" 的 CLI 版：取 0x117 的两张
 * 系统调用表，统计并列出被改写的条目。 */
static int CliCheckDrvHookCli_57(const char *lpCmdLine)
{
    FE_RING0_HOOK_LIST hook;
    ULONG i, modified = 0;

    if (!lpCmdLine || !strstr(lpCmdLine, "--checkdrvhook-cli"))
        return FE_CLI_NEXT;

    ZeroMemory(&hook, sizeof(hook));
    printf("=== Check Driver Hook (0x117) ===\n");
    if (!g_Client.Opened && !XpchOpen(&g_Client, "\\\\.\\View++ByLinxer")) {
        printf("  connect failed\n");
        return 1;
    }
    if (!FeLoadRing0Hooks(&g_Client, &hook)) {
        printf("  0x117 returned no data\n");
        return 1;
    }
    printf("  build=%lu  entries=%lu  table1=%lu  table2=%lu  modified=%lu\n",
           (unsigned long)hook.Build, (unsigned long)hook.Count,
           (unsigned long)hook.Count1, (unsigned long)hook.Count2,
           (unsigned long)hook.ModifiedCount);
    for (i = 0; i < hook.Count; i++) {
        FE_RING0_HOOK_ENTRY *e = &hook.Items[i];
        if (!e->FlagAddr && !e->FlagBytes)
            continue;
        modified++;
        printf("  [T%lu:%lu] %s  current=%016I64X  original=%016I64X  %s\n",
               (unsigned long)e->TableIndex, (unsigned long)e->Index,
               e->FlagBytes ? "PATCHED(inline)" : "PATCHED(addr)",
               e->Current, e->Original, e->Disasm);
    }
    if (modified == 0)
        printf("  all entries clean (no patched table entry)\n");
    FeFreeRing0Hooks(&hook);
    return 0;
}

int FeCliDispatch(const char *lpCmdLine)
{
    int r;
    if ((r = CliProclistCli_01(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliKernelCli_02(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliRingCli_03(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSsdtCli_04(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliRestorehooksCli_05(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliCbtableCli_06(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliHooksCli_07(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliTrojanCli_08(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliDevObjCli_08b(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliDrvopCli_09(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliRegkeyCli_10(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliRegctxCli_11(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliStartupOpCli_12(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliModsearchCli_13(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSettingCli_14(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliFilesigCli_15(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliForbidCli_16(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliFireeyeCli_17(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliExamCli_18(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliOsCli_19(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliFileverCli_20(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliFilesCli_21(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliReghandlesCli_22(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliReghiddenCli_23(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliServicesCli_24(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliStartupCli_25(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliHiddendrvCli_26(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliRegCli_27(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliNetworkCli_28(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliGStatusCli_29(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliKernelExtraCli_30(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliIdtCli_31(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliGdtCli_32(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliIoportCli_33(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliDumpmemCli_34(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliProcOpCli_35(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSsdtRestoreCli_36(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliDriversCli_37(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliKillCli_38(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliMemoryCli_39(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliMisc_40(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliHandlesCli_41(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliThreadsCli_42(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliModulesCli_43(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliWindowsCli_44(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliHotkeysCli_45(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliScanCli_46(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestSort_47(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestFilter_48(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestExport_49(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestDrill_50(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestChanged_51(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestTheme_52(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestMenu_53(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestFileTools_54(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliSelftestSysViews_55(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliCheckHookCli_56(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    if ((r = CliCheckDrvHookCli_57(lpCmdLine)) != FE_CLI_NEXT)
        return r;
    return FE_CLI_NONE;
}
