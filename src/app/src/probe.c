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
#include <io.h>
#include <fcntl.h>
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

/* A/B 采集时额外跳过的命令。
 *
 * 与 g_SkipCommands 的区别：那一组的理由是"缺前置状态会崩"；
 * 这一组是**操作类命令** —— 它们会创建/打开对象、装卸驱动、改内核内存、
 * 装 hook。自动化盲目调用会：
 *   · 在系统里留下垃圾对象 / 半装好的 hook（污染后续所有命令的结果）；
 *   · 用零入参走到 ObOpenObjectByPointer / ObpCaptureObjectCreateInformation
 *     这类路径，对 NULL 解引用 → 实测 BSOD 0x50；
 *   · 某些直接改 EPROCESS / 内核页，把 guest 弄坏。
 *
 * 原版前端只在用户主动点击、且带着真实对象句柄时才发这些命令。
 * 因此它们**不做自动化 A/B 比对**，改为逐条反汇编核对实现。
 * 这个边界必须写清楚，不能装作"全量比对过"。 */
static const ULONG g_AbDangerous[] = {
    0x28,   /* CmdProcessOperation              改目标进程内存           */
    0x2B,   /* CmdReadProcessMemoryBlock        需真实 EPROCESS          */
    0x2D,   /* CmdModuleOperation               模块注/卸                */
    0x2F,   /* CmdRegistryOperation             改注册表键               */
    0x30,   /* CmdRegistryProtect               需真实键对象             */
    0x34,   /* CmdObjectOperation               改对象                   */
    0x38,   /* CmdDeviceIoControl               转发到其它设备           */
    0x39,   /* CmdVirtualMemoryOp              改进程虚拟内存           */
    0x3A,   /* CmdProcessMonitor               注册进程监控             */
    0x3D,   /* CmdThreadOperation               改线程                   */
    0x3E,   /* CmdThreadMonitor                 注册线程监控             */
    0x3F,   /* CmdKernelObjectMonitor           注册内核对象监控         */
    0x40,   /* CmdHandleMonitor                 注册句柄监控             */
    0x44,   /* CmdDriverLoadUnload              装卸驱动                 */
    0x45,   /* CmdReadPhysicalMemory            读物理内存               */
    0x46,   /* CmdIoPortOperation               IN/OUT 端口（已实测可通过，但会动硬件）*/
    0x48,   /* CmdProcessMemoryOperation        改进程内存               */
    0x49,   /* CmdEnumProcessModules            需真实进程               */
    0x4A,   /* CmdKernelMemoryOpDispatch        内核内存写               */
    0x4B,   /* CmdProcessMemoryOpDispatch       进程内存写               */
    0x4C,   /* CmdMemoryQueryOp                 内存查询（需上下文）     */
    0x4F,   /* CmdDriverProtectOp               改驱动保护               */
    0x51,   /* InitRegFilter                    注册注册表过滤           */
    0x52,   /* InitRegNotify                    注册注册表通知           */
    0x53,   /* InitRegCallback                  注册注册表回调           */
    0x55,   /* CmdQueryProcessInfoEx            需真实进程               */
    0x57,   /* CmdObjectOperationDispatch       对象操作分发             */
    0x58,   /* CmdDeviceIoControlEx             转发                     */
    0x59,   /* CmdFsctlOperation                转发                     */
    0x5A,   /* CmdReadProcessMemoryStr          需真实进程               */
    0x5B,   /* CmdWriteProcessMemoryEx          写进程内存               */
    0x5C,   /* CmdDeviceIoControlSimple         转发                     */
    0x5D,   /* CmdDeviceIoControlWithBuffer     转发                     */
    0x5E,   /* CmdDeviceIoControlWithString     转发                     */
    0x5F,   /* CmdOpenSectionObject             创建/打开对象 → 0x50     */
    0x60,   /* CmdCreateFile                    创建文件                 */
    0x61,   /* CmdEnumHandlesByPid              需真实进程               */
    0x62,   /* CmdCreateFileWithPath            创建文件                 */
    0x63,   /* CmdCloseHandle                   关句柄（会关错东西）     */
    0x64,   /* CmdQueryFileInfo                 需真实文件对象           */
    0x65,   /* CmdOpenFileHandle                打开文件                 */
    0x66,   /* CmdReadFileSize                  需真实文件对象           */
    0x67,   /* CmdWriteFile                     写文件                   */
    0x68,   /* CmdReadFile                      读文件                   */
    0x69,   /* CmdReadDirectory                 遍历目录                 */
    0x6A,   /* CmdEnumDirectory                 遍历目录                 */
    0x6B,   /* EnableObjectCallback             注册对象回调             */
    0x6C,   /* CmdRenameFile                    改文件名                 */
    0x6D,   /* CmdCopyFile                      复制文件                 */
    0x6E,   /* CmdOpenFileForEnum               打开文件                 */
    0x6F,   /* CmdDeleteFile                    删文件                   */
    0x70,   /* CmdSetFileAttributes             改文件属性               */
    0x72,   /* PowerCallbackUnregister          注销回调                 */
    0x73,   /* ShutdownCallbackUnregister       注销回调                 */
    0x74,   /* PowerCallbackRoutine             注册电源回调             */
    0x75,   /* RegNotifyCallback                注册注册表通知           */
    0x76,   /* DisableThreadProtect             改线程保护               */
    0x77,   /* EnableThreadProtect              改线程保护               */
    0x78,   /* CmdQuerySystemInfoEx             实机证实：OutSize=8192 时
               BSOD 0x50（nt!ObpCaptureObjectCreateInformation+0x141，
               arg1=0xfffff80300000000）。**原版驱动同样崩，崩溃位置与
               参数完全一致** —— 不是复刻偏差，是这条命令在缺少前置状态
               （GT 里的对象/系统信息上下文）时用零入参走到对象创建路径。
               前端只在真实调用场景下用它。禁止盲目调用。               */
    0x79,   /* CmdCallbackControl               改回调                   */
    0x7A,   /* CmdReadCpuMsr                    读 MSR                   */
    0x7C,   /* CmdReadCpuBaseAddr               读 CPU 基址              */
    0x83,   /* MiniFilterGenerateFileName       需真实文件上下文         */
    0x84,   /* RegisterFormatNameCallback       注册回调                 */
    0x86,   /* MiniFilterFormatFileNameWithContext 需真实上下文          */
    0x87,   /* RegisterFormatPathCallback       注册回调                 */
    0x88,   /* MiniFilterFormatFileNameWithPathEx 需真实上下文          */
    0x89,   /* CmdEnumHookInfo                  见下（实测可通过但只读） */
    0x8F,   /* MiniFilterCommPortSend           发通信端口               */
    0x90,   /* MiniFilterCommPortRecv           收通信端口               */
    0x91,   /* MiniFilterCommPortReply          回通信端口               */
    0x9C,   /* MiniFilterCommPortConnect        连通信端口               */
    0x9D,   /* MiniFilterCommPortDisconnect     断通信端口               */
    0x9E,   /* MiniFilterCommPortCleanup        清理通信端口             */
    0xA0,   /* CmdCloseProcessHandle            关进程句柄               */
    0xA1,   /* CmdEnumObjectHandles             需真实进程               */
    0xA2,   /* CmdTerminateProcessByEProcess    终止进程                 */
    0xAD,   /* CmdInstallSystemHook             装 hook                  */
    0xAF,   /* CmdInstallShadowHook             装 hook                  */
    0xB1, 0xB3, 0xB5, 0xB7, 0xB9, 0xBB, 0xBD, 0xC1,  /* InstallSyscallHook2..9 */
    0xC2,   /* CmdEnumGdiObjects                实机：OutSize=8192 时
               BSOD 0x50，与 0x78 同址（原版同样崩）。需要 win32k 会话
               上下文，盲扫必然走到对象创建路径。禁止盲目调用。       */
    0xC4,   /* CmdFixProcessEProcess            改 EPROCESS              */
    0xC7, 0xC8,  /* CmdSetCallbackFlagTrue/False 改回调标志              */
    0xC9,   /* MiniFilterContextCleanup         清理上下文               */
    0xCA, 0xCC,  /* CmdDiskReadSector / SectorReadWrite 直接读写磁盘扇区 */
    0xCB,   /* CmdDiskOperationDispatch         转发                     */
    0xCE,   /* CmdForEachCpuClearGdtBit         改 GDT                   */
    0xCF,   /* RegisterFilterUnloadCallback     注册回调                 */
    0xD1,   /* MiniFilterNotifyRoutineEx2       注册通知                 */
    0xD2, 0xD3,  /* Enable/DisableProcessProtect 改进程保护              */
    0xD6,   /* CmdWriteKernelObjectField        写内核对象               */
    0xD7,   /* ProcessCallbackRoutine           注册进程回调             */
    0xD8,   /* InitProcessCallback              注册进程回调             */
    0xDF,   /* CmdOpenFilterVolumeFile          打开卷文件 → 对象创建    */
    0xE0,   /* CmdRemoveFilterContextNode       改过滤上下文             */
    0xE7,   /* CmdRestoreSsdtTable              改 SSDT                  */
    0xEB,   /* CmdSetSsdtEntry                  改 SSDT                  */
    0xEC,   /* CmdReadExportDirectory           实机：给足 2MB 仍崩 0x3B
               （原版同样崩）。它需要 InitKernelDataSectionTable 已把
               GT 里的导出目录上下文填好；盲扫时那条链没跑，于是
               解引用空指针。与 0x78/0xC2 同类：缺前置状态。
               前端只有在 Kernel 页打开时才用，不能自动化盲调。      */
    0xED,   /* CmdUpdateExportEntry             改导出表                 */
    0xEE,   /* CmdRestoreExportTable            改导出表                 */
    0xEF,   /* CmdInitSsdtTable                 初始化 SSDT 表           */
    0xF1, 0xF2,  /* CmdInitFwpsDispatchTables(2) 改 WFP 分发表           */
    0xF5,   /* InvokeRegisteredCallbackWithUserData 调用注册回调       */
    0xF8,   /* CmdInitKernelMemoryContext       改内核内存上下文       */
    0xF9,   /* CmdReadKernelMemoryRange         读内核内存               */
    0xFA,   /* CmdReadKernelMemoryRangeSize     读内核内存               */
    0xFB,   /* CmdWriteKernelMemoryRange        写内核内存               */
    0xFD,   /* CmdCallKernelMemoryFunction      调内核函数               */
    0x101,  /* CmdReadSsdtEntryTable            读 SSDT 条目             */
    0x102,  /* CmdReadSsdtEntryTableEx          读 Shadow SSDT           */
    0x103,  /* CmdDispatchSsdtByVersion         分发表                  */
    0x104,  /* CmdFixSsdtEntryAddress           改 SSDT                  */
    0x105,  /* CmdEnumSsdtEntryTable            枚举 SSDT                */
    0x107,  /* CmdWriteMsrValue                 写 MSR                   */
    0x109,  /* CmdSetProcessorField             改处理器字段             */
    0x10A,  /* InitFileSystemCallback           注册文件系统回调         */
    0x10C, 0x10D, 0x10E, 0x10F, 0x110,  /* MiniFilterPre* 需真实上下文 */
    0x111,  /* InitMiniFilterDriver             注册 minifilter          */
    0x113,  /* InitFileSystemFilter             注册文件系统过滤         */
    0x114,  /* FileSystemFilterCallback         回调处理                 */
    0x115,  /* CmdCallSystemRoutine             调任意内核函数           */
    0x116,  /* CmdResetDriverState              重置驱动状态             */
    0x118,  /* CmdCheckBytePattern              见下                     */
    0x11C,  /* InitObjectCallback               注册对象回调             */
    0x11E, 0x120, 0x126, 0x128, 0x12A, 0x12E, 0x130, 0x132, 0x134,  /* Set*Context */
    0x12C,  /* CmdInstallUSBPortSyscallHook     装 hook                  */
    0x135, 0x136,  /* Disable/EnableObjectProtect 改对象保护               */
    0x137, 0x138,  /* KernelNotifyRoutine(Ex) 注册内核通知                 */
    0x139,  /* CmdRestoreDriverDispatch         改驱动分发表             */
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
    for (i = 0; i < sizeof(g_AbDangerous) / sizeof(g_AbDangerous[0]); i++)
        if (g_AbDangerous[i] == Cmd)
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
    BOOL XDump = FALSE;
    BOOL SddtInfo = FALSE;
    ULONG XDumpOff = 0;
    ULONG XDumpCount = 0;
    UCHAR InHexBuf[64];
    ULONG InHexLen = 0;
    BOOL CbTable = FALSE;
    BOOL CbTableRestore = FALSE;
    BOOL Matrix = FALSE;
    BOOL AbCollect = FALSE;
    ULONG AbLo = 0, AbHi = 0, AbOnlyCount = 0;
    ULONG64 AbInValue = 0;
    const char *AbOut = "C:\Users\Public\ab.txt";
    ULONG MatrixLo = 0, MatrixHi = 0;
    const char *MatrixOut = "C:\Users\Public\matrix_out.txt";
    BOOL DumpKmem = FALSE;
    int i;

    fopen_s(&g_Log, "C:\\Users\\Public\\probe_trace.txt", "w");
    L("probe start\n");
    {
        int q;
        L("argv[%d]:", argc);
        for (q = 0; q < argc; q++) L(" [%s]", argv[q]);
        L("\n");
    }

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
        else if (_stricmp(argv[i], "--cbtable") == 0) CbTable = TRUE;
        else if (_stricmp(argv[i], "--cbtable-restore") == 0) {
            CbTable = TRUE;
            CbTableRestore = TRUE;
        }
        else if (_stricmp(argv[i], "--dump-kmem") == 0) DumpKmem = TRUE;
        else if (_stricmp(argv[i], "--ab") == 0) AbCollect = TRUE;
        else if (_stricmp(argv[i], "--ab-lo") == 0 && i + 1 < argc)
            AbLo = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--ab-hi") == 0 && i + 1 < argc)
            AbHi = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--ab-count") == 0 && i + 1 < argc)
            AbOnlyCount = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--ab-in") == 0 && i + 1 < argc)
            AbInValue = (ULONG64)_strtoui64(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--ab-out") == 0 && i + 1 < argc)
            AbOut = argv[++i];
        else if (_stricmp(argv[i], "--matrix") == 0) Matrix = TRUE;
        else if (_stricmp(argv[i], "--matrix-lo") == 0 && i + 1 < argc)
            MatrixLo = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--matrix-hi") == 0 && i + 1 < argc)
            MatrixHi = (ULONG)strtoul(argv[++i], NULL, 0);
        else if (_stricmp(argv[i], "--matrix-out") == 0 && i + 1 < argc)
            MatrixOut = argv[++i];
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
        else if (_stricmp(argv[i], "--inhex") == 0 && i + 1 < argc) {
            /* --inhex <hexstring>：逐字节入参，供 0x132（48 字节结构化输入）等
               需要任意字节布局的命令做端到端验证。 */
            const char *h = argv[++i];
            InHexLen = 0;
            while (h[0] && h[1] && InHexLen < sizeof(InHexBuf)) {
                char two[3];
                two[0] = h[0]; two[1] = h[1]; two[2] = 0;
                InHexBuf[InHexLen++] = (UCHAR)strtoul(two, NULL, 16);
                h += 2;
            }
        }
        else if (_stricmp(argv[i], "--ssdtinfo") == 0) SddtInfo = TRUE;
        else if (_stricmp(argv[i], "--xdump") == 0 && i + 4 < argc) {
            /* --xdump <cmd> <outsize> <offset> <count>
               只导出输出缓冲中 [offset, offset+count) 的 qword 列表。
               0xE1 CmdEnumProcessListEx 要求 4MB 输出缓冲，整块按 16 字节
               打印会有 26 万行；用本开关只取关心的区间（NDIS handler 表
               在 +0x58 起的 48 个指针）。 */
            XDump = TRUE;
            Cmd = (ULONG)strtoul(argv[++i], NULL, 0);
            RawSize = (ULONG)strtoul(argv[++i], NULL, 0);
            XDumpOff = (ULONG)strtoul(argv[++i], NULL, 0);
            XDumpCount = (ULONG)strtoul(argv[++i], NULL, 0);
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

            if (okp) {
                ULONG LsBuf = 0;   /* OutSize 必须正好 4（路径 C 条件） */
                lok = XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                                 pkt, sizeof(pkt), &LsBuf, sizeof(LsBuf), &lr);
                ls = LsBuf;
            }
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

            /* 【2026-10-26 最终修正】分发器（DriverEntry.c:542-545,605）映射：
                   OutSize = [buf+0x20] = 请求的 InSize
                   CtxSize = [buf+0x24] = 请求的 OutSize
                   Handler(rcx=CtxPtr, edx=OutSize, r8=ExtraPtr, r9=CtxSize)
               CmdQueryProcessInfo(ProcessId, BufferSize, OutBuf, OutputSize)：
                   BufferSize ← 请求的 InSize
                   OutputSize ← 请求的 OutSize
               走路径 A（InSize<=0xA）会置 GT[0x304]=1 但清空命令表
               198..224；走路径 C（InSize=0x100 合法包 + OutSize==4）
               由 QuerySsdHookByProcessInfo → DecryptAesHexString 成功后
               调 CheckSsdtHookIntegrity，同样置 GT[0x304]=1 且不清表。
               所以正确组合是 **InSize=0x100 许可包 + OutSize=4**。 */
            {
                UCHAR ReadyPkt[0x100];
                ULONG ReadyOut = 0;
                if (XpchBuildLicensePacket(ReadyPkt))
                    XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                               ReadyPkt, sizeof(ReadyPkt),
                               &ReadyOut, sizeof(ReadyOut), NULL);
            }

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
            ULONG SsdtBuf = 0;   /* OutSize 必须正好 4（路径 C 条件） */
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
                           HsPacket, HsPacketSize,
                           &SsdtBuf, sizeof(SsdtBuf), &r22);
            ssdt = SsdtBuf;

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
            ULONG SsdtBuf = 0;   /* OutSize 必须正好 4（路径 C 条件） */
            UCHAR r22 = 0;
            BOOL ok22;

            ok22 = XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                              HsPacket, HsPacketSize,
                           &SsdtBuf, sizeof(SsdtBuf), &r22);
            ssdt = SsdtBuf;
            printf("  handshake 0x22 (inSize=%lu) -> %s, result=%u, ssdt=%lu\n",
                   HsPacketSize, ok22 ? "OK" : "REJECTED", r22, ssdt);

            ok = XpchInvoke(&client, XPCH_CMD_GET_MODULE_COUNT,
                            NULL, 0, &build, sizeof(build), &res);
            printf("  handshake 0x24 -> %s, result=%u, build=%lu (0x%lX)\n",
                   ok ? "OK" : "REJECTED", res, build, build);
        }

        /* --cbtable：按原版输出布局解析 0x131 的 28 条回调表，并（可选）
           --cbtable-restore 对检测到差异的槽真正下发 0x132 写回。
           布局依据见 KernelHookViews.c FeLoadCallbackTable 的注释。 */
        if (CbTable) {
            enum { CB_SIZE = 1352, CB_BASE = 8, CB_STRIDE = 0x30, CB_N = 28 };
            UCHAR *cb = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CB_SIZE);
            UCHAR rcb = 0;
            BOOL cok;
            ULONG pass, attempted = 0, restored = 0, rejected = 0, skipped = 0;

            if (!cb) { printf("out of memory\n"); XpchClose(&client); return 1; }
            cok = XpchInvoke(&client, 0x131, NULL, 0, cb, CB_SIZE, &rcb);
            printf("\n=== 0x131 callback table -> %s result=%u ===\n",
                   cok ? "OK" : "REJECTED", rcb);
            printf("ready      = %u\n", cb[0]);
            printf("build      = %lu\n", *(ULONG *)(cb + 8));
            if (cok && cb[0] == 1) {
                for (pass = 0; pass < CB_N; pass++) {
                    UCHAR *e = cb + CB_BASE + pass * CB_STRIDE;
                    ULONG idx = *(ULONG *)(e + 0x00);
                    ULONG rva = *(ULONG *)(e + 0x04);
                    ULONG64 va = *(ULONG64 *)(e + 0x08);
                    ULONG64 cur = *(ULONG64 *)(e + 0x10);
                    ULONG64 head = 0;
                    char orig[64] = {0};
                    int k;
                    memcpy(&head, e + 0x1A, sizeof(head));
                    (void)head;
                    for (k = 0; k < 16; k++)
                        sprintf_s(orig + k * 3, sizeof(orig) - (size_t)k * 3, "%02X ",
                                  e[0x1A + k]);
                    printf("  [%2lu] rva=%08lX va=%016I64X cur=%016I64X orig=%s\n",
                           (unsigned long)idx, (unsigned long)rva, va, cur, orig);
                    /* 【判据】orig 是目标地址上的原始机器码快照，cur 是系统当前
                       调用的回调函数指针 —— 两者不是同类数据，不能直接比较。
                       能被输出缓冲判定的「回调被替换」只有一种：cur 指向的地址
                       与快照所属地址 va 不一致，即回调指针被重定向。
                       至于「va 处代码被就地改写成跳板」（本驱动 InstallCallback-
                       ContextHookEntry 的做法），需要读内核内存才能判定，输出里
                       没有该字段，前端无法单凭 0x131 得出结论 —— 因此这里只做
                       指针重定向这一项可判定的检查，不做任何猜测。 */
                    if (!cur || !va || cur == va) { skipped++; continue; }
                    attempted++;
                    if (CbTableRestore) {
                        /* 【2026-10-23 修正】恢复「被替换的回调」走的是原版
                           InstallCallbackContextHookEntry（0x140036284）那条路：
                             in+0x00 = 槽索引（<= 0x1B）
                             in+0x08 = 要写回的原始函数地址（本表条目的 va）
                             in+0x18 = 1  → 触发指针写回
                           驱动执行 WritePhysicalMemoryQword(
                               GetCallbackContextBase() + 112 + 8*index, in[8])
                           即把回调上下文里那一项指针改回原始函数。
                           此前用的 in+0x19=1 是「在目标地址上打 16 字节补丁」，
                           属于另一条语义（恢复内联补丁），不是本项。 */
                        UCHAR in[48];
                        UCHAR rr = 0;
                        BOOL rok;
                        ZeroMemory(in, sizeof(in));
                        *(ULONG *)(in + 0) = idx;
                        *(ULONG64 *)(in + 8) = va;
                        in[24] = 1;                 /* 指针写回路径 */
                        rok = XpchInvoke(&client, 0x132, in, (ULONG)sizeof(in),
                                         NULL, 0, &rr);
                        if (rok && rr == 1) {
                            restored++;
                            printf("       -> restored: slot %lu pointer <- %016I64X\n",
                                   (unsigned long)idx, va);
                        } else {
                            rejected++;
                            printf("       -> FAILED (ok=%d result=%u)\n", rok, rr);
                        }
                    }
                }
                printf("  slots=%lu  redirected=%lu  original=%lu\n",
                       (unsigned long)CB_N, (unsigned long)attempted,
                       (unsigned long)skipped);
                if (CbTableRestore)
                    printf("  restored=%lu attempted=%lu rejected=%lu\n",
                           (unsigned long)restored, (unsigned long)attempted,
                           (unsigned long)rejected);
                else if (attempted)
                    printf("  (dry run; add --cbtable-restore to actually write back)\n");
            }
            HeapFree(GetProcessHeap(), 0, cb);
            XpchClose(&client);
            printf("=== done (cbtable) ===\n");
            return 0;
        }

        /* --matrix：全命令 I/O 差分矩阵。
           按 g_Shapes 里每个命令自己的真实入参/出参形状调用一次，
           把「结果字节 + 前 N 字节输出（hex）」写进文件。
           同一份输出在原版驱动与我方驱动上各跑一次并逐字节 diff，
           就能定位哪些命令的行为与原版不一致。
           不在此做任何判断，只负责忠实采样。 */
        if (Matrix) {
            FILE *mf = NULL;
            ULONG c;
            ULONG nsent = 0, nrej = 0;
            fopen_s(&mf, MatrixOut, "w");
            if (!mf) {
                printf("cannot open %s\n", MatrixOut);
                XpchClose(&client);
                return 1;
            }
            fprintf(mf, "# cmd insize outsize result hex\n");
            for (c = MatrixLo ? MatrixLo : ScanLo;
                 c <= (MatrixHi ? MatrixHi : ScanHi); c++) {
                const CMD_SHAPE *sh = ShapeOf(c);
                ULONG outSz = sh ? sh->OutSize : 0;
                ULONG inSz = sh ? sh->InSize : 0;
                UCHAR *ob = NULL;
                UCHAR rr = 0;
                BOOL ok;
                ULONG oi;

                if (IsSkipped(c))
                    continue;
                if (outSz > 0x4000) outSz = 0x4000;
                ob = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSz ? outSz : 8);
                if (!ob) continue;

                if (inSz) {
                    UCHAR inbuf[64];
                    ZeroMemory(inbuf, sizeof(inbuf));
                    ok = XpchInvoke(&client, c, inbuf,
                                    inSz > sizeof(inbuf) ? (ULONG)sizeof(inbuf) : inSz,
                                    ob, outSz, &rr);
                } else {
                    ok = XpchInvoke(&client, c, NULL, 0, ob, outSz, &rr);
                }
                if (ok) nsent++; else nrej++;

                fprintf(mf, "0x%03lX %5lu %6lu %3u %s",
                        (unsigned long)c, (unsigned long)inSz,
                        (unsigned long)outSz, (unsigned)rr, ok ? "OK " : "REJ");
                /* 只记录非零区间的起点，避免整块 0 也写出来占空间 */
                for (oi = 0; oi < outSz; oi += 16) {
                    int allz = 1, j;
                    for (j = 0; j < 16 && oi + j < outSz; j++)
                        if (ob[oi + j]) { allz = 0; break; }
                    if (allz) continue;
                    fprintf(mf, " %04lX:", (unsigned long)oi);
                    for (j = 0; j < 16 && oi + j < outSz; j++)
                        fprintf(mf, "%02X", ob[oi + j]);
                }
                fprintf(mf, "\n");
                fflush(mf);
                HeapFree(GetProcessHeap(), 0, ob);
            }
            fprintf(mf, "# sent=%lu rejected=%lu\n",
                    (unsigned long)nsent, (unsigned long)nrej);
            fclose(mf);
            printf("matrix written to %s (sent=%lu rejected=%lu)\n",
                   MatrixOut, (unsigned long)nsent, (unsigned long)nrej);
            XpchClose(&client);
            return 0;
        }

        /* --dump-kmem [addr]：内核内存转储。
           本驱动没有「任意内核 VA 读」原语（0xF7/0xF9 只读它们各自那个
           固定 GT 指针；0x3A 的主路径依赖 GT[0x41E4]=MmGetPhysicalAddress、
           回退依赖 GT[0x4189]，实测两槽都是 0），所以无法按用户给的任意
           地址读。能如实提供的只有 0x131 已经跑通的那份真实数据：
           28 个内核回调目标的 (RVA, VA, 当前函数指针, 磁盘原始 16 字节)。
           这里把它按转储格式打出来 —— 全部来自驱动实测，不编造任何字节。 */
        if (DumpKmem) {
            enum { CB_SIZE = 1352, CB_BASE = 8, CB_STRIDE = 0x30, CB_N = 28 };
            UCHAR *cb = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CB_SIZE);
            UCHAR rcb = 0;
            BOOL cok;
            ULONG k, dumped = 0;

            if (!cb) { printf("out of memory\n"); XpchClose(&client); return 1; }
            cok = XpchInvoke(&client, 0x131, NULL, 0, cb, CB_SIZE, &rcb);
            printf("\n=== Dump Kernel Memory ===\n");
            if (!(cok && cb[0] == 1)) {
                printf("not available: cmd 0x131 returned result=%u (callback table "
                       "not initialised)\n", rcb);
                printf("note: this driver has no arbitrary kernel-VA read primitive. "
                       "0xF7/0xF9 read one fixed GT pointer each; 0x3A needs "
                       "GT[0x41E4]/GT[0x4189] which are both 0 on this machine.\n");
                HeapFree(GetProcessHeap(), 0, cb);
                XpchClose(&client);
                printf("=== done (dump-kmem) ===\n");
                return 0;
            }
            printf("%-4s %-10s %-18s %-18s %s\n",
                   "slot", "RVA", "VA", "current", "on-disk first 16 bytes");
            for (k = 0; k < CB_N; k++) {
                UCHAR *e = cb + CB_BASE + k * CB_STRIDE;
                ULONG idx = *(ULONG *)(e + 0x00);
                ULONG rva = *(ULONG *)(e + 0x04);
                ULONG64 va = *(ULONG64 *)(e + 0x08);
                ULONG64 cur = *(ULONG64 *)(e + 0x10);
                char hex[64] = {0};
                int b;
                if (!va) continue;
                for (b = 0; b < 16; b++)
                    sprintf_s(hex + b * 3, sizeof(hex) - (size_t)b * 3, "%02X ",
                              e[0x1A + b]);
                printf("[%2lu] %08lX   %016I64X   %016I64X   %s\n",
                       (unsigned long)idx, (unsigned long)rva, va, cur, hex);
                dumped++;
            }
            printf("dumped %lu kernel callback targets (16 bytes each, read by the "
                   "driver from the on-disk ntoskrnl image)\n", (unsigned long)dumped);
            HeapFree(GetProcessHeap(), 0, cb);
            XpchClose(&client);
            printf("=== done (dump-kmem) ===\n");
            return 0;
        }

        if (XDump) {
            UCHAR *outBuf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RawSize);
            UCHAR rr = 0;
            BOOL rok;

            if (!outBuf) {
                printf("out of memory\n");
                XpchClose(&client);
                return 1;
            }
            rok = XpchInvoke(&client, Cmd, NULL, 0, outBuf, RawSize, &rr);
            printf("=== xdump 0x%02X outSize=0x%lX off=0x%lX count=%lu -> %s result=%u ===\n",
                   Cmd, RawSize, XDumpOff, XDumpCount, rok ? "OK" : "REJECTED", rr);
            if (rok) {
                ULONG k;
                for (k = 0; k < XDumpCount; k++) {
                    ULONG o = XDumpOff + k * 8;
                    ULONG64 v;
                    if (o + 8 > RawSize)
                        break;
                    v = *(const ULONG64 *)(const void *)(outBuf + o);
                    printf("  [%02lu] +0x%05lX = 0x%016llX\n",
                           k, o, (unsigned long long)v);
                }
            }
            HeapFree(GetProcessHeap(), 0, outBuf);
            XpchClose(&client);
            printf("=== done (xdump) ===\n");
            return 0;
        }

        if (SddtInfo) {
            /* 0x42 CmdQuerySsdtInfo：入参必须 24 字节
                 +0  BYTE Flags
                 +4  (pad)
                 +8  PVOID OutputBuffer（用户态）
                 +16 ULONG BufferSize
               驱动会 memset(OutputBuffer,0,BufferSize) 后调 CmdEnumDriverObjects。
               这条路径此前在 EnumerateDriverFiles 里对 NULL 解引用崩掉
               （BSOD 0x3B），用本模式做回归。 */
            enum { SI_SIZE = 0x40000 };
            UCHAR Arg[24];
            UCHAR *Out = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SI_SIZE);
            UCHAR rr = 0;
            BOOL rok;

            if (!Out) {
                printf("out of memory\n");
                XpchClose(&client);
                return 1;
            }
            ZeroMemory(Arg, sizeof(Arg));
            Arg[0] = 0;                             /* Flags */
            *(ULONG64 *)(void *)(Arg + 8) = (ULONG64)(ULONG_PTR)Out;
            *(ULONG *)(void *)(Arg + 16) = SI_SIZE;

            rok = XpchInvoke(&client, 0x42, Arg, sizeof(Arg), NULL, 0, &rr);
            printf("=== 0x42 CmdQuerySsdtInfo -> %s result=%u ===\n",
                   rok ? "OK" : "REJECTED", rr);
            if (rok) {
                printf("  entry count @+0 = %lu\n",
                       *(const ULONG *)(const void *)Out);
                {
                    ULONG k;
                    for (k = 0; k < 6; k++)
                        printf("  [%lu] +0x%03lX = 0x%016llX\n", k,
                               (unsigned long)(k * 8),
                               (unsigned long long)
                               *(const ULONG64 *)(const void *)(Out + k * 8));
                }
            }
            HeapFree(GetProcessHeap(), 0, Out);
            XpchClose(&client);
            printf("=== done (ssdtinfo) ===\n");
            return 0;
        }

        if (AbCollect) {
            /* ── A/B 全量采集 ──────────────────────────────────────────
               目的：把每条命令的**完整输入与输出**原样落盘，供两条驱动
               （原版 / 我方）各跑一次后做逐字节比对。

               与 --matrix 的关键差别：
                 · 输出缓冲按"该命令真实期望尺寸"给足，而不是 1 字节；
                 · 分配时在实际尺寸之后额外留 256KB guard 区，
                   只把真实尺寸传给驱动 —— 那些不校验 OutSize 的处理器
                   即使越界写也只落进 guard，不会破坏堆（此前用 0x1000
                   盲扫曾打爆内核栈导致 BSOD 0x139）；
                 · 记录完整 hex（最多 4MB）、返回码、GetLastError；
                 · 每条调用前把"正在调用哪条"写进 last.txt 并刷盘，
                   万一 BSOD 能精确定位到命令号。

               输出格式（每行一条，便于 diff）：
                 CMD 0xNNN INSZ=n OUTSZ=n RES=n OK|REJ ERR=n HDRLEN=n
                 IN  <hex>
                 OUT <hex>                                        */
            enum { AB_GUARD = 0x40000, AB_MAXOUT = 0x400000, AB_MAXIN = 256 };
            FILE *abf = NULL;
            FILE *abl = NULL;
            ULONG c;
            ULONG nok = 0, nrej = 0, nrec = 0;

            fopen_s(&abf, AbOut, "w");
            if (!abf) {
                printf("cannot open %s\n", AbOut);
                XpchClose(&client);
                return 1;
            }
            fprintf(abf, "# A/B collect  cmd insz outsz res status lasterr hdrlen\n");
            /* 【2026-10-25 修正】此前这里直接发 0x24 就开扫，从未做 0x22 握手。
               分发器 0x140082532 在 GT[0x304]==0 时只放行 0x22
               （`cmp ebx,22h / jnz loc_1400825CB`），所以整轮扫描 126 条全是
               REJ —— 那次采集结果不可用，不是驱动不对。
               这里先走与 XpchHandshake 相同的路径 C（0x100 字节合法许可包）。 */
            if (!NoHandshake) {
                ULONG abSsdt = 0; UCHAR ar = 0;
                ULONG AbSsdtBuf = 0;   /* OutSize 必须正好 4（路径 C 条件） */
                BOOL aok;
                aok = XpchInvoke(&client, XPCH_CMD_QUERY_PROCESS_INFO,
                                 HsPacket, HsPacketSize,
                                 &AbSsdtBuf, sizeof(AbSsdtBuf), &ar);
                abSsdt = AbSsdtBuf;
                fprintf(abf, "# handshake 0x22 insz=%lu %s res=%u ssdt=%lu\n",
                        (unsigned long)HsPacketSize, aok ? "OK" : "REJ",
                        (unsigned)ar, (unsigned long)abSsdt);
                printf("  [ab] handshake 0x22 insz=%lu -> %s res=%u ssdt=%lu\n",
                       (unsigned long)HsPacketSize, aok ? "OK" : "REJECTED",
                       (unsigned)ar, (unsigned long)abSsdt);
            }
            {
                ULONG abBuild = 0; UCHAR br = 0;
                if (XpchInvoke(&client, XPCH_CMD_GET_MODULE_COUNT,
                               NULL, 0, &abBuild, sizeof(abBuild), &br))
                    fprintf(abf, "# build=%lu\n", (unsigned long)abBuild);
                else
                    fprintf(abf, "# build=UNAVAILABLE(0x24 rej res=%u)\n",
                            (unsigned)br);
            }

            for (c = AbLo ? AbLo : XPCH_CMD_MIN;
                 c <= (AbHi ? AbHi : XPCH_CMD_MAX); c++) {
                ULONG outSz, inSz;
                UCHAR *raw = NULL, *outp = NULL;
                UCHAR inbuf[AB_MAXIN];
                UCHAR rr = 0;
                BOOL ok;
                DWORD gerr;
                ULONG k;

                if (IsSkipped(c))
                    continue;
                if (AbOnlyCount && nrec >= AbOnlyCount)
                    break;

                /* 每条命令的期望尺寸：优先用形状表，未知则给 0x2000
                   （足够覆盖绝大多数固定结构，又不会大到无谓占用）。 */
                {
                    const CMD_SHAPE *sh = ShapeOf(c);
                    outSz = sh ? sh->OutSize : 0x2000;
                    inSz  = sh ? sh->InSize  : 0;
                }
                if (outSz > AB_MAXOUT) outSz = AB_MAXOUT;

                /* last-attempt 标记：崩了就靠它定位。
                   必须真正落到磁盘 —— 用 CreateFile 写 + FlushFileBuffers，
                   不能只靠 CRT 的 fflush（它只刷到 OS 缓存，BSOD 时丢失）。 */
                {
                    HANDLE hL = CreateFileW(L"C:\\Users\\Public\\ab_last.txt",
                                            GENERIC_WRITE, 0, NULL,
                                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hL != INVALID_HANDLE_VALUE) {
                        char lb[96];
                        int ln = _snprintf_s(lb, sizeof(lb), _TRUNCATE,
                                             "0x%03lX insz=%lu outsz=%lu\r\n",
                                             (unsigned long)c, (unsigned long)inSz,
                                             (unsigned long)outSz);
                        DWORD wrote = 0;
                        if (ln > 0)
                            WriteFile(hL, lb, (DWORD)ln, &wrote, NULL);
                        FlushFileBuffers(hL);
                        CloseHandle(hL);
                    }
                }

                /* 主输出也立刻落盘，避免崩溃时丢掉已完成的历史记录 */
                fflush(abf);
                { HANDLE hF = (HANDLE)_get_osfhandle(_fileno(abf));
                  if (hF != INVALID_HANDLE_VALUE) FlushFileBuffers(hF); }

                if (outSz) {
                    raw = (UCHAR *)HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             (SIZE_T)outSz + AB_GUARD);
                    if (!raw) continue;
                    outp = raw;
                }

                ZeroMemory(inbuf, sizeof(inbuf));
                if (inSz) {
                    for (k = 0; k < inSz && k < AB_MAXIN && k < 8; k++)
                        inbuf[k] = (UCHAR)((AbInValue >> (8 * k)) & 0xFF);
                }

                ok = XpchInvoke(&client, c,
                                inSz ? inbuf : NULL,
                                inSz > AB_MAXIN ? AB_MAXIN : inSz,
                                outp, outSz, &rr);
                gerr = GetLastError();
                if (ok) nok++; else nrej++;
                nrec++;

                fprintf(abf, "CMD 0x%03lX INSZ=%lu OUTSZ=%lu RES=%u %s ERR=%lu HDRLEN=%lu\n",
                        (unsigned long)c, (unsigned long)inSz,
                        (unsigned long)outSz, (unsigned)rr,
                        ok ? "OK" : "REJ", (unsigned long)gerr,
                        (unsigned long)(outSz ? (nrec ? 0 : 0) : 0));

                /* 输入：全部字节 */
                if (inSz) {
                    fprintf(abf, "IN  ");
                    for (k = 0; k < inSz && k < AB_MAXIN; k++)
                        fprintf(abf, "%02X", inbuf[k]);
                    fprintf(abf, "\n");
                } else {
                    fprintf(abf, "IN  -\n");
                }

                /* 输出：只有返回 OK 才记录（REJ 时缓冲未被写，记了也没意义）；
                   同时裁掉尾部全零，避免 4MB 全 0 撑爆文件。 */
                if (ok && outSz) {
                    ULONG tail = outSz;
                    while (tail && raw[tail - 1] == 0) tail--;
                    fprintf(abf, "OUT ");
                    for (k = 0; k < tail; k++)
                        fprintf(abf, "%02X", raw[k]);
                    if (!tail) fprintf(abf, "-");
                    fprintf(abf, "\n");
                } else {
                    fprintf(abf, "OUT -\n");
                }
                fflush(abf);

                if (raw) HeapFree(GetProcessHeap(), 0, raw);
            }

            fprintf(abf, "# records=%lu ok=%lu rej=%lu\n",
                    (unsigned long)nrec, (unsigned long)nok, (unsigned long)nrej);
            fclose(abf);
            printf("A/B collect -> %s  (records=%lu ok=%lu rej=%lu)\n",
                   AbOut, (unsigned long)nrec, (unsigned long)nok,
                   (unsigned long)nrej);
            XpchClose(&client);
            return 0;
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
               --inhex 给了逐字节入参（用于 0x132 这类 48 字节结构化输入）；
               RawInSize > 0 时先发一段入参（0x4C 等需要 8 字节输入的处理器）。 */
            if (InHexLen)
            {
                rok = XpchInvoke(&client, Cmd, InHexBuf, InHexLen, outBuf, RawSize, &rr);
            }
            else if (RawInSize)
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