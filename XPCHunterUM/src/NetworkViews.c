// ============================================================================
// NetworkViews.c — Network 页（原版 Network Callback 树）数据层
//
// 只做两节（原版树中已完整解码的部分），数据全部来自驱动命令：
//
//   NdisTdiCallback  ← 0xE6
//     原版客户端 sub_1400ABA60 → sub_140025470（发 0xE6，OutSize=48）
//     驱动侧 CmdGetSsdtTableInfo（SSDT.c:2469 / 原 0x140067DBC）返回 6 个 QWORD：
//       [2] = GT2058  TDI 原始地址 1        [3] = GT2059  TDI 原始地址 2
//       [4] = *GT884  数据节区当前值 1      [5] = *GT885  数据节区当前值 2
//     前两个 QWORD 是驱动清 0 的占位，客户端本地补名称：
//       row0 = "TdiRegisterDeviceObject"   row1 = "TdiPnPHandler"
//     每行：当前值 != 原始值 → "Hook"，否则显示 "-"。
//
//   TdiPnpClient     ← 0xE8
//     原版客户端 sub_1400ADE50 → sub_140025570（发 0xE8，OutSize=4MB）
//     驱动侧 EnumObjectTypeInfoOperation（Operation.c:1223 / 原 0x14007EDC8）：
//       header：total@+0、count@+4
//       记录：步长 568，type@+8、对象@+16、名称@+24（UTF-16，最多 256 字符），
//             +536 Binding、+544 UnBind（仅 type==1）、+552 AddAddress、
//             +560 DelAddress、+568 PnPPower（仅 type!=1）
//     客户端为每个非 0 handler 加一行，字段名依次取自 off_1406D03E8：
//       BindingHandler / UnBindHandler / AddAddressHandler /
//       DelAddressHandler / PnPPowerHandler
//
//   符号解析 ← 0x42（selector=0）
//     原版客户端 sub_14001F8B0：count@+0，记录@+8，步长 0x228，
//     基址@+24、大小@+32、名称@+36（UTF-16）。见 header 注释。
// ============================================================================
#include "XPCHunterUM.h"
#include "xpc_oid_names.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FE_SYMBOL_BUFFER_SIZE 0x400000u
#define FE_SYMBOL_RECORD_SIZE 0x228u
#define FE_SYMBOL_RECORD_COUNT_MAX \
    ((FE_SYMBOL_BUFFER_SIZE - 8u) / FE_SYMBOL_RECORD_SIZE)
#define FE_SYMBOL_BASE_OFFSET   24u
#define FE_SYMBOL_SIZE_OFFSET   32u
#define FE_SYMBOL_NAME_OFFSET   36u

#define FE_PNP_BUFFER_SIZE  0x400000u
#define FE_PNP_RECORD_SIZE  0x238u
#define FE_PNP_HEADER_SIZE  576u
#define FE_PNP_MAX_COUNT \
    ((FE_PNP_BUFFER_SIZE - FE_PNP_HEADER_SIZE) / FE_PNP_RECORD_SIZE + 1u)
#define FE_PNP_TYPE_OFFSET     8u
#define FE_PNP_OBJECT_OFFSET   16u
#define FE_PNP_NAME_OFFSET     24u
#define FE_PNP_NAME_BYTES      512u
#define FE_PNP_BINDING_OFFSET  536u
#define FE_PNP_UNBIND_OFFSET   544u
#define FE_PNP_ADDADDR_OFFSET  552u
#define FE_PNP_DELADDR_OFFSET  560u
#define FE_PNP_PNPPOWER_OFFSET 568u

static void NvWideToAnsi(const WCHAR *Wide, size_t WideChars,
                         char *Ansi, size_t AnsiChars)
{
    int n;

    if (!Ansi || !AnsiChars)
        return;
    Ansi[0] = 0;
    if (!Wide || !WideChars)
        return;
    n = WideCharToMultiByte(CP_ACP, 0, Wide, (int)WideChars,
                            Ansi, (int)AnsiChars - 1, NULL, NULL);
    if (n <= 0)
        Ansi[0] = 0;
}

// ---------------------------------------------------------------------------
// 0x42：驱动/模块符号表
// ---------------------------------------------------------------------------
BOOL FeOpenSymbolTable(XPCH_CLIENT *Client, FE_SYMBOL_TABLE *Table)
{
    UCHAR Ctx[24];
    UCHAR Result = 0;
    UCHAR *Buffer;
    ULONG Count;

    if (!Client || !Table)
        return FALSE;
    ZeroMemory(Table, sizeof(*Table));

    Buffer = (UCHAR *)calloc(1, FE_SYMBOL_BUFFER_SIZE);
    if (!Buffer)
        return FALSE;

    ZeroMemory(Ctx, sizeof(Ctx));
    *(ULONG64 *)(Ctx + 8) = (ULONG64)(ULONG_PTR)Buffer;
    *(ULONG *)(Ctx + 16) = FE_SYMBOL_BUFFER_SIZE;

    if (!XpchInvoke(Client, XPCH_CMD_QUERY_DRIVER_OBJECTS,
                    Ctx, sizeof(Ctx), NULL, 0, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = *(const ULONG *)(const void *)Buffer;
    if (Count == 0 || Count > FE_SYMBOL_RECORD_COUNT_MAX) {
        free(Buffer);
        return FALSE;
    }

    Table->Buffer = Buffer;
    Table->Count = Count;
    return TRUE;
}

void FeCloseSymbolTable(FE_SYMBOL_TABLE *Table)
{
    if (!Table)
        return;
    free(Table->Buffer);
    Table->Buffer = NULL;
    Table->Count = 0;
    Table->LastModule[0] = 0;
    Table->LastCompany[0] = 0;
}

BOOL FeResolveSymbol(FE_SYMBOL_TABLE *Table, ULONG64 Address,
                     char *Module, size_t ModuleChars,
                     char *Company, size_t CompanyChars)
{
    ULONG i;

    if (Module && ModuleChars)
        Module[0] = 0;
    if (Company && CompanyChars)
        Company[0] = 0;
    if (!Table || !Table->Buffer || !Address)
        return FALSE;

    for (i = 0; i < Table->Count; i++) {
        const UCHAR *Rec = Table->Buffer + 8 + (size_t)i * FE_SYMBOL_RECORD_SIZE;
        ULONG64 Base = *(const ULONG64 *)(const void *)(Rec + FE_SYMBOL_BASE_OFFSET);
        ULONG Size = *(const ULONG *)(const void *)(Rec + FE_SYMBOL_SIZE_OFFSET);
        WCHAR Name[FE_NET_NAME_CHARS];
        FE_FILE_VER Ver;

        if (!Base || !Size)
            continue;
        if (Address < Base || Address - Base >= Size)
            continue;

        memcpy(Name, Rec + FE_SYMBOL_NAME_OFFSET, FE_PNP_NAME_BYTES);
        Name[FE_NET_NAME_CHARS - 1] = 0;
        NvWideToAnsi(Name, FE_NET_NAME_CHARS, Module, ModuleChars);

        /* 同一模块的多个 handler 命中同一路径，缓存一次版本查询 */
        if (Company && CompanyChars && Module && Module[0]) {
            if (Table->LastModule[0] && !strcmp(Table->LastModule, Module)) {
                strcpy_s(Company, CompanyChars, Table->LastCompany);
            } else {
                ZeroMemory(&Ver, sizeof(Ver));
                if (FeLoadFileVersion(Module, &Ver) && Ver.CompanyName[0])
                    strcpy_s(Company, CompanyChars, Ver.CompanyName);
                strcpy_s(Table->LastModule, sizeof(Table->LastModule), Module);
                strcpy_s(Table->LastCompany, sizeof(Table->LastCompany), Company);
            }
        }
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// NdisTdiCallback（0xE6 / 0xE7）
// ---------------------------------------------------------------------------
BOOL FeLoadTdiCallbacks(XPCH_CLIENT *Client, FE_TDI_CALLBACK_LIST *List)
{
    static const char *Names[2] = { "TdiRegisterDeviceObject", "TdiPnPHandler" };
    ULONG64 Out[6];
    UCHAR Result = 0;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    ZeroMemory(Out, sizeof(Out));

    /* Out 48 字节：驱动要求第 4 参数（OutSize）= 48 */
    if (!XpchInvoke(Client, XPCH_CMD_GET_TDI_CALLBACKS,
                    NULL, 0, Out, sizeof(Out), &Result) || Result != 1)
        return FALSE;

    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);

    List->Count = 2;
    for (i = 0; i < 2; i++) {
        FE_TDI_CALLBACK_ENTRY *Item = &List->Items[i];

        strcpy_s(Item->Name, sizeof(Item->Name), Names[i]);
        Item->Current = Out[4 + i];
        Item->Original = Out[2 + i];
        Item->Hooked = (Item->Current != Item->Original);
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, Item->Current,
                            Item->Module, sizeof(Item->Module),
                            Item->Company, sizeof(Item->Company));
    }

    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    return TRUE;
}

BOOL FeRestoreTdiCallbacks(XPCH_CLIENT *Client, UCHAR *ResultByte)
{
    UCHAR Result = 0;

    if (ResultByte)
        *ResultByte = 0;
    if (!Client || !Client->Opened)
        return FALSE;
    XpchInvoke(Client, XPCH_CMD_RESTORE_TDI_CALLBACKS, NULL, 0, NULL, 0, &Result);
    if (ResultByte)
        *ResultByte = Result;
    return Result == 1;
}

// ---------------------------------------------------------------------------
// TdiPnpClient（0xE8）
// ---------------------------------------------------------------------------
BOOL FeLoadTdiPnpClients(XPCH_CLIENT *Client, FE_TDI_PNP_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, Total, i;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Total = 0;
    List->Items = NULL;

    Buffer = (UCHAR *)calloc(1, FE_PNP_BUFFER_SIZE);
    if (!Buffer)
        return FALSE;

    /* Out 4MB：驱动要求第 4 参数（OutSize）= 0x400000 */
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_TDI_PNP_CLIENTS,
                    NULL, 0, Buffer, FE_PNP_BUFFER_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Total = *(const ULONG *)(const void *)Buffer;
    Count = *(const ULONG *)(const void *)(Buffer + 4);
    if (Count > FE_PNP_MAX_COUNT)
        Count = FE_PNP_MAX_COUNT;

    if (Count) {
        List->Items = (FE_TDI_PNP_ENTRY *)calloc(Count, sizeof(FE_TDI_PNP_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
    }

    for (i = 0; i < Count; i++) {
        const UCHAR *Rec = Buffer + (size_t)i * FE_PNP_RECORD_SIZE;
        FE_TDI_PNP_ENTRY *Item = &List->Items[i];
        WCHAR Name[FE_NET_NAME_CHARS];

        memcpy(Name, Rec + FE_PNP_NAME_OFFSET, FE_PNP_NAME_BYTES);
        Name[FE_NET_NAME_CHARS - 1] = 0;
        NvWideToAnsi(Name, FE_NET_NAME_CHARS, Item->ClientName, sizeof(Item->ClientName));

        Item->ClientObject = *(const ULONG64 *)(const void *)(Rec + FE_PNP_OBJECT_OFFSET);
        Item->BindingHandler = *(const ULONG64 *)(const void *)(Rec + FE_PNP_BINDING_OFFSET);
        Item->UnBindHandler = *(const ULONG64 *)(const void *)(Rec + FE_PNP_UNBIND_OFFSET);
        Item->AddAddressHandler = *(const ULONG64 *)(const void *)(Rec + FE_PNP_ADDADDR_OFFSET);
        Item->DelAddressHandler = *(const ULONG64 *)(const void *)(Rec + FE_PNP_DELADDR_OFFSET);
        Item->PnPPowerHandler = *(const ULONG64 *)(const void *)(Rec + FE_PNP_PNPPOWER_OFFSET);
    }

    List->Count = Count;
    List->Total = Total;
    free(Buffer);
    return TRUE;
}

void FeFreeTdiPnpClients(FE_TDI_PNP_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Total = 0;
}

// ---------------------------------------------------------------------------
// NdisTcpOffloadHandlers（0xEA）
//   原版客户端 sub_1400AB550 → sub_1400256C0（发 0xEA，OutSize=176）
//   驱动侧 CmdQuerySsdtDetails（SSDT.c:2539 / 原 0x140067428）：
//     count=7 @+0，记录 @+8 步长 24：原始@+0、当前@+8；
//     名称槽 +16 由客户端依次填 off_1406D49B0 的 7 个名字。
// ---------------------------------------------------------------------------
BOOL FeLoadNdisOffloadHandlers(XPCH_CLIENT *Client, FE_NDIS_OFFLOAD_LIST *List)
{
    static const char *Names[FE_NDIS_OFFLOAD_MAX] = {
        "NdisTcpChimneyOffloadHandlers",
        "NdisMTcpOffloadEventIndicate",
        "NdisMTcpOffloadReceiveIndicate",
        "NdisMTcpOffloadSendComplete",
        "NdisMTcpOffloadReceiveComplete",
        "NdisMTcpOffloadDisconnectComplete",
        "NdisMTcpOffloadForwardComplete"
    };
    UCHAR Out[176];
    UCHAR Result = 0;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG Count, i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    ZeroMemory(Out, sizeof(Out));

    /* Out 176 字节：驱动要求第 4 参数（OutSize）= 0xB0 */
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NDIS_OFFLOAD,
                    NULL, 0, Out, sizeof(Out), &Result) || Result != 1)
        return FALSE;

    Count = *(const ULONG *)(const void *)Out;
    if (Count > FE_NDIS_OFFLOAD_MAX)
        Count = FE_NDIS_OFFLOAD_MAX;

    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (i = 0; i < Count; i++) {
        const UCHAR *Rec = Out + 8 + (size_t)i * 24;
        FE_NDIS_OFFLOAD_ENTRY *Item = &List->Items[i];

        strcpy_s(Item->Name, sizeof(Item->Name), Names[i]);
        Item->Original = *(const ULONG64 *)(const void *)(Rec + 0);
        Item->Current = *(const ULONG64 *)(const void *)(Rec + 8);
        Item->Hooked = (Item->Current != Item->Original);
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, Item->Current,
                            Item->Module, sizeof(Item->Module),
                            Item->Company, sizeof(Item->Company));
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);

    List->Count = Count;
    return TRUE;
}


// ---------------------------------------------------------------------------
// Ndis Handler（0xE1）
//   原版客户端 sub_14009B1E0 → sub_1400250D0（发 0xE1，OutSize=0x400000）
//   驱动侧 CmdEnumProcessListEx（原 0x140062ED8）把 handler 指针数组放在
//   输出缓冲 +0x58 起的 records 区（记录步长 0x1E0）。
//   handler 名称**不由驱动返回**，是客户端按序套两张静态字符串表：
//     off_1406D49F0 — 75 项（miniport / adapter 级，清单里的 22 项在此表前段）
//     off_1406D5050 — 59 项（protocol / 结构内 handler）
//   本机实测两表对应的槽全为 0（无 NDIS miniport 注册），原版同样如此。
//   见 docs/reversing/全命令矩阵收敛实录_2026-10-25.md §3。
// ---------------------------------------------------------------------------
static const char *const s_NdisHandlerNamesA[75] = {
    "OpenAdapterCompleteHandler",
    "CloseAdapterCompleteHandler",
    "(Wan)SendCompleteHandler",
    "(Wan)TransferDataCompleteHandler",
    "ResetCompleteHandler",
    "RequestCompleteHandler",
    "(Wan)ReceiveHandler",
    "ReceiveCompleteHandler",
    "StatusHandler",
    "StatusCompleteHandler",
    "ReceivePacketHandler",
    "BindAdapterHandler",
    "UnbindAdapterHandler",
    "PnPEventHandler",
    "UnloadHandler",
    "ReservedHandlers[0]",
    "ReservedHandlers[1]",
    "ReservedHandlers[2]",
    "ReservedHandlers[3]",
    "CoSendCompleteHandler",
    "CoStatusHandler",
    "CoReceivePacketHandler",
    "CoAfRegisterNotifyHandler",
    "InitiateOffloadCompleteHandler",
    "TerminateOffloadCompleteHandler",
    "UpdateOffloadCompleteHandler",
    "InvalidateOffloadCompleteHandler",
    "QueryOffloadCompleteHandler",
    "IndicateOffloadEventHandler",
    "TcpOffloadSendCompleteHandler",
    "TcpOffloadReceiveCompleteHandler",
    "TcpOffloadDisconnectCompleteHandler",
    "TcpOffloadForwardCompleteHandler",
    "TcpOffloadEventHandler",
    "TcpOffloadReceiveIndicateHandler",
    "BindAdapterHandlerEx",
    "UnbindAdapterHandlerEx",
    "OpenAdapterCompleteHandlerEx",
    "CloseAdapterCompleteHandlerEx",
    "UninstallHandler",
    "ReceiveNetBufferListsHandler",
    "SendNetBufferListsCompleteHandler",
    "CoReceiveNetBufferListsHandler",
    "CoSendNetBufferListsCompleteHandler",
    "OidRequestCompleteHandler",
    "DirectOidRequestCompleteHandler",
    "AllocateSharedMemoryHandler",
    "FreeSharedMemoryHandler",
    "FastIoCheckIfPossible",
    "FastIoRead",
    "FastIoWrite",
    "FastIoQueryBasicInfo",
    "FastIoQueryStandardInfo",
    "FastIoLock",
    "FastIoUnlockSingle",
    "FastIoUnlockAll",
    "FastIoUnlockAllByKey",
    "FastIoDeviceControl",
    "AcquireFileForNtCreateSection",
    "ReleaseFileForNtCreateSection",
    "FastIoDetachDevice",
    "FastIoQueryNetworkOpenInfo",
    "AcquireForModWrite",
    "MdlRead",
    "MdlReadComplete",
    "PrepareMdlWrite",
    "MdlWriteComplete",
    "FastIoReadCompressed",
    "FastIoWriteCompressed",
    "MdlReadCompleteCompressed",
    "MdlWriteCompleteCompressed",
    "FastIoQueryOpen",
    "ReleaseForModWrite",
    "AcquireForCcFlush",
    "ReleaseForCcFlush",
};

static const char *const s_NdisHandlerNamesB[59] = {
    "(Wan)SendHandler",
    "TransferDataHandler",
    "SendCompleteHandler",
    "TransferDataCompleteHandler",
    "ReceiveHandler",
    "ReceiveCompleteHandler",
    "WanReceiveHandler",
    "RequestCompleteHandler",
    "ReceivePacketHandler",
    "SendPacketsHandler",
    "ResetHandler",
    "RequestHandler",
    "ResetCompleteHandler",
    "StatusHandler",
    "StatusCompleteHandler",
    "WSendHandler",
    "WTransferDataHandler",
    "WSendPacketsHandler",
    "CancelSendPacketsHandler",
    "MiniportCoCreateVcHandler",
    "MiniportCoRequestHandler",
    "CoCreateVcHandler",
    "CoDeleteVcHandler",
    "CmActivateVcCompleteHandler",
    "CmDeactivateVcCompleteHandler",
    "CoRequestCompleteHandler",
    "InitiateOffloadCompleteHandler",
    "TerminateOffloadCompleteHandler",
    "UpdateOffloadCompleteHandler",
    "InvalidateOffloadCompleteHandler",
    "QueryOffloadCompleteHandler",
    "IndicateOffloadEventHandler",
    "TcpOffloadSendCompleteHandler",
    "TcpOffloadReceiveCompleteHandler",
    "TcpOffloadDisconnectCompleteHandler",
    "TcpOffloadForwardCompleteHandler",
    "TcpOffloadEventHandler",
    "TcpOffloadReceiveIndicateHandler",
    "NextSendHandler",
    "NextReturnNetBufferListsHandler",
    "OidRequestHandler",
    "ProtSendNetBufferListsComplete",
    "NextSendNetBufferListsComplete",
    "ReceiveNetBufferLists",
    "SavedSendNBLHandler",
    "SavedSendPacketsHandler",
    "SavedCancelSendPacketsHandler",
    "Saved(Wan)SendHandler",
    "Ndis5WanSendHandler",
    "ProtSendCompleteHandler",
    "OidRequestCompleteHandler",
    "CoRequestHandler",
    "MiniportCoOidRequestHandler",
    "CoOidRequestCompleteHandler",
    "CoOidRequestHandler",
    "DirectOidRequestCompleteHandler",
    "DirectOidRequestHandler",
    "AllocateSharedMemoryHandler",
    "FreeSharedMemoryHandler",
};

BOOL FeLoadNdisHandlers(XPCH_CLIENT *Client, FE_NDIS_HANDLER_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Total, i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));

    Buffer = (UCHAR *)calloc(1, FE_NDIS_HANDLER_OUT_SIZE);
    if (!Buffer)
        return FALSE;

    /* 驱动要求 OutSize = 0x400000 */
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_PROCESS_LIST_EX,
                    NULL, 0, Buffer, FE_NDIS_HANDLER_OUT_SIZE, &Result)
        || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    /* 两种表共用同一段槽区；A 在前、B 紧随其后（原版按同样顺序扫描）。
       槽从 out+0x58 起，共 A_MAX + B_MAX 个 qword。 */
    Total = FE_NDIS_HANDLER_TABLE_A_MAX + FE_NDIS_HANDLER_TABLE_B_MAX;
    for (i = 0; i < Total; i++) {
        ULONG64 Value = *(const ULONG64 *)(const void *)
                        (Buffer + FE_NDIS_HANDLER_BASE_OFF + (size_t)i * 8);
        ULONG TableIdx;
        ULONG InTable;

        List->Scanned++;
        if (!Value)
            continue;                 /* 本机未注册该 handler */

        if (i < FE_NDIS_HANDLER_TABLE_A_MAX) {
            TableIdx = 1;
            InTable = i;
        } else {
            TableIdx = 2;
            InTable = i - FE_NDIS_HANDLER_TABLE_A_MAX;
        }

        {
            FE_NDIS_HANDLER_ENTRY *Item = &List->Items[List->Count];
            const char *Name = (TableIdx == 1)
                ? s_NdisHandlerNamesA[InTable]
                : s_NdisHandlerNamesB[InTable];
            strcpy_s(Item->Name, sizeof(Item->Name), Name);
            Item->Table = TableIdx;
            Item->Index = InTable;
            Item->Value = Value;
            List->Count++;
        }
    }

    free(Buffer);
    return TRUE;
}

void FePrintNdisHandlers(XPCH_CLIENT *Client)
{
    FE_NDIS_HANDLER_LIST List;
    ULONG i;

    if (!FeLoadNdisHandlers(Client, &List)) {
        printf("NdisHandler: 0xE1 query failed (connected=%d)\n",
               Client && Client->Opened);
        return;
    }
    printf("NdisHandler (cmd 0xE1, %lu live / %lu scanned)\n",
           List.Count, List.Scanned);
    if (!List.Count) {
        printf("  (all slots are 0 - no NDIS miniport/protocol handlers "
               "registered on this machine)\n");
        return;
    }
    printf("  %-4s %-5s %-38s %s\n", "Tbl", "Idx", "Fun Name", "Entry");
    for (i = 0; i < List.Count; i++) {
        printf("  %-4lu %-5lu %-38s 0x%016llX\n",
               List.Items[i].Table, List.Items[i].Index,
               List.Items[i].Name,
               (unsigned long long)List.Items[i].Value);
    }
}

// ---------------------------------------------------------------------------
// NdisOidTable（0xEC）
//   原版客户端 sub_1400AAEB0 → sub_140025B50（发 0xEC，OutSize=2MB）
//   驱动侧 CmdReadExportDirectory（SSDT.c:2679 / 原 0x1400608E4）：
//     前半 = 当前表；后半（+0x100000）= 原始表（+8/+16 由 RVA 重定位到 KernelBase）；
//     记录步长 24：类型ID@+0、PreFun@+8、PostFun@+16，全 0 记录结束。
//   客户端再把类型ID经 off_1406D0E50 的 738 项静态表换成名字（未命中→
//   "UnknowType"），并对每条非空 Pre/Post 指针加一行。
// ---------------------------------------------------------------------------
const char *FeOidName(ULONG64 TypeId)
{
    size_t i;

    for (i = 0; i < XPC_OID_NAME_COUNT; i++) {
        if ((ULONG64)g_XpcOidNames[i].Id == TypeId)
            return g_XpcOidNames[i].Name;
    }
    return NULL;
}

BOOL FeLoadNdisOidTable(XPCH_CLIENT *Client, FE_NDIS_OID_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count = 0;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Items = NULL;

    Buffer = (UCHAR *)calloc(1, 2 * FE_OID_HALF_SIZE);
    if (!Buffer)
        return FALSE;

    /* Out 2MB：驱动要求第 4 参数（OutSize）= 0x200000 */
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NDIS_OID_TABLE,
                    NULL, 0, Buffer, 2 * FE_OID_HALF_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    while (Count < FE_OID_MAX_COUNT) {
        const UCHAR *Rec = Buffer + (size_t)Count * FE_OID_RECORD_SIZE;
        if (!*(const ULONG64 *)(const void *)(Rec + 0) &&
            !*(const ULONG64 *)(const void *)(Rec + 8) &&
            !*(const ULONG64 *)(const void *)(Rec + 16))
            break;
        Count++;
    }

    if (Count) {
        ULONG i;

        List->Items = (FE_NDIS_OID_ENTRY *)calloc(Count, sizeof(FE_NDIS_OID_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
        for (i = 0; i < Count; i++) {
            const UCHAR *Cur = Buffer + (size_t)i * FE_OID_RECORD_SIZE;
            const UCHAR *Orig = Cur + FE_OID_HALF_SIZE;

            List->Items[i].TypeId = *(const ULONG64 *)(const void *)(Cur + 0);
            List->Items[i].CurrentPre = *(const ULONG64 *)(const void *)(Cur + 8);
            List->Items[i].CurrentPost = *(const ULONG64 *)(const void *)(Cur + 16);
            List->Items[i].OriginalPre = *(const ULONG64 *)(const void *)(Orig + 8);
            List->Items[i].OriginalPost = *(const ULONG64 *)(const void *)(Orig + 16);
        }
    }

    List->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeNdisOidTable(FE_NDIS_OID_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

// ---------------------------------------------------------------------------
// Ndis Interface（0xF0）
//   原版客户端 sub_1400AAB70 → sub_140026220（发 0xF0，OutSize=2MB）
//   驱动侧原始处理函数 EnumKernelModules（0x1400669B8）：输出 count@+0，
//   记录@+8 步长 0x270（模块加载器记录）。原版前端直接把这些记录按
//   “接口信息”字段偏移格式化，本实现按客户端语义 1:1 复刻。
//   每项输出：Interface[%d]: 0x%p + 17 行信息 + 1 行空分隔行。
// ---------------------------------------------------------------------------
static const char *NvAccessTypeName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Loopback";
    case 2:  return "Broadcast";
    case 3:  return "Point To Point";
    case 4:  return "Point To Multi Point";
    default: return "Unknow";
    }
}

static const char *NvDirectionTypeName(ULONG Value)
{
    switch (Value) {
    case 0:  return "SendReceive";
    case 1:  return "SendOnly";
    case 2:  return "ReceiveOnly";
    default: return "Unknow";
    }
}

static const char *NvConnectionTypeName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Dedicated";
    case 2:  return "Passive";
    case 3:  return "Demand";
    default: return "Unknow";
    }
}

static const char *NvMediaTypeName(ULONG Value)
{
    switch (Value) {
    case 0:  return "802_3";
    case 1:  return "802_5";
    case 2:  return "Fddi";
    case 3:  return "Wan";
    case 4:  return "LocalTalk";
    case 5:  return "Dix";
    case 6:  return "ArcnetRaw";
    case 7:  return "Arcnet878_2";
    case 8:  return "Atm";
    case 9:  return "WirelessWan";
    case 10: return "Irda";
    case 11: return "Bpc";
    case 12: return "CoWan";
    case 13: return "1394";
    case 14: return "InfiniBand";
    case 15: return "Tunnel";
    case 16: return "Native802_11";
    case 17: return "Loopback";   /* 原版默认分支保留初值，17 显示 Loopback */
    default: return "Unknow";
    }
}

static const char *NvMediaConnectStateName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Connected";
    case 2:  return "Disconnected";
    default: return "Unknow";
    }
}

static const char *NvMediaDuplexStateName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Half";
    case 2:  return "Full";
    default: return "Unknow";
    }
}

static const char *NvAdminStatusName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Up";
    case 2:  return "Down";
    case 3:  return "Testing";
    default: return "Unknow";
    }
}

static const char *NvOperStatusName(ULONG Value)
{
    switch (Value) {
    case 1:  return "Up";
    case 2:  return "Down";
    case 3:  return "Testing";
    case 5:  return "Dormant";
    case 6:  return "Not Present";
    case 7:  return "Lower Layer Down";
    default: return "Unknow";
    }
}

int FeFormatNdisInterfaceLines(const FE_NDIS_IF_ENTRY *Entry,
                               char Lines[FE_NDIS_IF_LINE_COUNT][FE_NET_PATH_CHARS])
{
    char Descr[FE_NDIS_IF_DESCR_CHARS];

    if (!Entry || !Lines)
        return 0;
    NvWideToAnsi(Entry->IfDescr, -1, Descr, sizeof(Descr));

    sprintf_s(Lines[0], FE_NET_PATH_CHARS, "        Flags: %d", Entry->Flags);
    sprintf_s(Lines[1], FE_NET_PATH_CHARS, "        Mtu: %d", Entry->Mtu);
    sprintf_s(Lines[2], FE_NET_PATH_CHARS, "        PromiscuousMode: %d",
              Entry->PromiscuousMode);
    sprintf_s(Lines[3], FE_NET_PATH_CHARS,
              "        InterfaceGuid: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
              Entry->InterfaceGuidData1, Entry->InterfaceGuidData2,
              Entry->InterfaceGuidData3,
              Entry->InterfaceGuidData4[0], Entry->InterfaceGuidData4[1],
              Entry->InterfaceGuidData4[2], Entry->InterfaceGuidData4[3],
              Entry->InterfaceGuidData4[4], Entry->InterfaceGuidData4[5],
              Entry->InterfaceGuidData4[6], Entry->InterfaceGuidData4[7]);
    sprintf_s(Lines[4], FE_NET_PATH_CHARS,
              "        NetworkGuid: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
              Entry->NetworkGuidData1, Entry->NetworkGuidData2,
              Entry->NetworkGuidData3,
              Entry->NetworkGuidData4[0], Entry->NetworkGuidData4[1],
              Entry->NetworkGuidData4[2], Entry->NetworkGuidData4[3],
              Entry->NetworkGuidData4[4], Entry->NetworkGuidData4[5],
              Entry->NetworkGuidData4[6], Entry->NetworkGuidData4[7]);
    sprintf_s(Lines[5], FE_NET_PATH_CHARS, "        ProviderIfContext: 0x%p",
              (void *)(ULONG_PTR)Entry->ProviderIfContext);
    sprintf_s(Lines[6], FE_NET_PATH_CHARS, "        ProviderHandle: 0x%p",
              (void *)(ULONG_PTR)Entry->ProviderHandle);
    sprintf_s(Lines[7], FE_NET_PATH_CHARS, "        ifDescr: %s", Descr);
    sprintf_s(Lines[8], FE_NET_PATH_CHARS, "        ifIndex: %d", Entry->IfIndex);
    sprintf_s(Lines[9], FE_NET_PATH_CHARS, "        AccessType: %s",
              NvAccessTypeName(Entry->AccessType));
    sprintf_s(Lines[10], FE_NET_PATH_CHARS, "        DirectionType: %s",
              NvDirectionTypeName(Entry->DirectionType));
    sprintf_s(Lines[11], FE_NET_PATH_CHARS, "        ConnectionType: %s",
              NvConnectionTypeName(Entry->ConnectionType));
    sprintf_s(Lines[12], FE_NET_PATH_CHARS, "        MediaType: %s",
              NvMediaTypeName(Entry->MediaType));
    sprintf_s(Lines[13], FE_NET_PATH_CHARS, "        MediaConnectState: %s",
              NvMediaConnectStateName(Entry->MediaConnectState));
    sprintf_s(Lines[14], FE_NET_PATH_CHARS, "        MediaDuplexState: %s",
              NvMediaDuplexStateName(Entry->MediaDuplexState));
    sprintf_s(Lines[15], FE_NET_PATH_CHARS, "        AdminStatus: %s",
              NvAdminStatusName(Entry->AdminStatus));
    sprintf_s(Lines[16], FE_NET_PATH_CHARS, "        OperStatus: %s",
              NvOperStatusName(Entry->OperStatus));
    return FE_NDIS_IF_LINE_COUNT;
}

BOOL FeLoadNdisInterfaces(XPCH_CLIENT *Client, FE_NDIS_IF_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, i;
    const ULONG MaxRecords = (2 * FE_OID_HALF_SIZE - 8) / FE_NDIS_IF_RECORD_SIZE;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Items = NULL;

    Buffer = (UCHAR *)calloc(1, 2 * FE_OID_HALF_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NDIS_INTERFACES,
                    NULL, 0, Buffer, 2 * FE_OID_HALF_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = *(ULONG *)(void *)Buffer;
    if (Count > FE_NDIS_IF_MAX_COUNT)
        Count = FE_NDIS_IF_MAX_COUNT;
    if (Count > MaxRecords)
        Count = MaxRecords;

    if (Count) {
        List->Items = (FE_NDIS_IF_ENTRY *)calloc(Count, sizeof(FE_NDIS_IF_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
        for (i = 0; i < Count; i++) {
            const UCHAR *Rec = Buffer + 8 + (size_t)i * FE_NDIS_IF_RECORD_SIZE;
            FE_NDIS_IF_ENTRY *Entry = &List->Items[i];

            Entry->LoaderEntry = *(const ULONG64 *)(const void *)(Rec + 0);
            Entry->Flags = *(const ULONG *)(const void *)(Rec + 8);
            Entry->Mtu = *(const ULONG *)(const void *)(Rec + 12);
            Entry->PromiscuousMode = *(const ULONG *)(const void *)(Rec + 16);
            Entry->AccessType = *(const ULONG *)(const void *)(Rec + 20);
            Entry->DirectionType = *(const ULONG *)(const void *)(Rec + 24);
            Entry->ConnectionType = *(const ULONG *)(const void *)(Rec + 28);
            Entry->MediaType = *(const ULONG *)(const void *)(Rec + 32);
            Entry->MediaConnectState = *(const ULONG *)(const void *)(Rec + 36);
            Entry->MediaDuplexState = *(const ULONG *)(const void *)(Rec + 40);
            Entry->AdminStatus = *(const ULONG *)(const void *)(Rec + 44);
            Entry->OperStatus = *(const ULONG *)(const void *)(Rec + 48);
            Entry->InterfaceGuidData1 = *(const ULONG *)(const void *)(Rec + 52);
            Entry->InterfaceGuidData2 = *(const USHORT *)(const void *)(Rec + 56);
            Entry->InterfaceGuidData3 = *(const USHORT *)(const void *)(Rec + 58);
            memcpy(Entry->InterfaceGuidData4, Rec + 60, 8);
            Entry->NetworkGuidData1 = *(const ULONG *)(const void *)(Rec + 68);
            Entry->NetworkGuidData2 = *(const USHORT *)(const void *)(Rec + 72);
            Entry->NetworkGuidData3 = *(const USHORT *)(const void *)(Rec + 74);
            memcpy(Entry->NetworkGuidData4, Rec + 76, 8);
            Entry->IfIndex = *(const ULONG *)(const void *)(Rec + 84);
            memcpy(Entry->IfDescr, Rec + 88, 512);
            Entry->IfDescr[FE_NDIS_IF_DESCR_CHARS - 1] = 0;
            Entry->ProviderIfContext = *(const ULONG64 *)(const void *)(Rec + 608);
            Entry->ProviderHandle = *(const ULONG64 *)(const void *)(Rec + 616);
        }
    }

    List->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeNdisInterfaces(FE_NDIS_IF_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

// ---------------------------------------------------------------------------
// 节点 6~10、12：通用指针表（原版 sub_1400A8FB0）
//   列：Index / Fun Entry / Module / File Corporation
//   输出：Count@+0；地址数组@+8；0xF7/0xF9 仅 8 字节、固定 1 项
// ---------------------------------------------------------------------------
typedef struct _NV_FWPS_DESC {
    ULONG       Node;
    ULONG       Command;
    ULONG       OutSize;
    ULONG       FixedCount;
    const char *Name;
} NV_FWPS_DESC;

static const NV_FWPS_DESC g_NvFwpsTables[] = {
    { 6,  XPCH_CMD_FWPS_TCPIP_TABLE,   FE_FWPS_LARGE_OUT_SIZE,  0, "FwpsTcpipDispatchTable" },
    { 7,  XPCH_CMD_FWPS_L2_TABLE,      FE_FWPS_LARGE_OUT_SIZE,  0, "FwpsL2DispatchTable"    },
    { 8,  XPCH_CMD_WFP_NBL_TABLE,      FE_FWPS_LARGE_OUT_SIZE,  0, "WfpNblDispatchTable"    },
    { 9,  XPCH_CMD_WFP_STREAM_SHIM,    FE_FWPS_LARGE_OUT_SIZE,  0, "WfpStreamShim"          },
    { 10, XPCH_CMD_WFP_MAC_SHIM,       FE_FWPS_SINGLE_OUT_SIZE, 1, "WfpMacShim"             },
    { 12, XPCH_CMD_NSI_LEGACY_HANDLER, FE_FWPS_SINGLE_OUT_SIZE, 1, "NsiLegacyHandler"       },
};

static const NV_FWPS_DESC *NvFwpsDesc(ULONG Node)
{
    size_t i;

    for (i = 0; i < sizeof(g_NvFwpsTables) / sizeof(g_NvFwpsTables[0]); i++) {
        if (g_NvFwpsTables[i].Node == Node)
            return &g_NvFwpsTables[i];
    }
    return NULL;
}

const char *FeFwpsTableName(ULONG Node)
{
    const NV_FWPS_DESC *Desc = NvFwpsDesc(Node);
    return Desc ? Desc->Name : "FwpsDispatchTable";
}

BOOL FeLoadFwpsTable(XPCH_CLIENT *Client, ULONG Command, ULONG OutSize,
                     ULONG FixedCount, FE_FWPS_TABLE *Table)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, Capacity;

    if (!Table || !OutSize)
        return FALSE;
    Table->Count = 0;
    Table->Entries = NULL;

    Buffer = (UCHAR *)calloc(1, OutSize);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, Command, NULL, 0, Buffer, OutSize, &Result) ||
        Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = FixedCount ? FixedCount : *(ULONG *)(void *)Buffer;
    Capacity = (OutSize - 8) / (ULONG)sizeof(ULONG64);
    if (Count > FE_FWPS_TABLE_MAX_ENTRIES)
        Count = FE_FWPS_TABLE_MAX_ENTRIES;
    if (Count > Capacity)
        Count = Capacity;

    if (Count) {
        Table->Entries = (ULONG64 *)calloc(Count, sizeof(ULONG64));
        if (!Table->Entries) {
            free(Buffer);
            return FALSE;
        }
        memcpy(Table->Entries, Buffer + 8, (size_t)Count * sizeof(ULONG64));
    }
    Table->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeFwpsTable(FE_FWPS_TABLE *Table)
{
    if (!Table)
        return;
    free(Table->Entries);
    Table->Entries = NULL;
    Table->Count = 0;
}

BOOL FePrintFwpsTable(XPCH_CLIENT *Client, ULONG Node)
{
    const NV_FWPS_DESC *Desc = NvFwpsDesc(Node);
    FE_FWPS_TABLE Table;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i;

    if (!Desc) {
        printf("unknown Fwps table node %lu\n", Node);
        return FALSE;
    }
    if (!FeLoadFwpsTable(Client, Desc->Command, Desc->OutSize,
                         Desc->FixedCount, &Table)) {
        printf("%s: 0x%02X query failed (connected=%d)\n",
               Desc->Name, Desc->Command, Client && Client->Opened);
        return FALSE;
    }

    printf("%s (cmd 0x%02X, %lu entries)\n", Desc->Name, Desc->Command,
           Table.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (i = 0; i < Table.Count; i++) {
        char Module[FE_NET_PATH_CHARS];
        char Company[FE_NET_COMPANY_CHARS];

        Module[0] = 0;
        Company[0] = 0;
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, Table.Entries[i],
                            Module, sizeof(Module),
                            Company, sizeof(Company));
        printf("  [%lu] 0x%016llX  %s  %s\n", i,
               (unsigned long long)Table.Entries[i],
               Module[0] ? Module : "unknown image",
               Company[0] ? Company : "");
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    FeFreeFwpsTable(&Table);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 11 NetioLayerCallback（0xF4）
//   原版 sub_1400AC070 → sub_140026460（OutSize=1MB）
//   输出：Count@+0；记录@+8 步长 16：{Id@+0, pad, Address@+8}
//   列：Index(=Id) / Fun Entry / Module / File Corporation
// ---------------------------------------------------------------------------
BOOL FeLoadNetioLayerCallbacks(XPCH_CLIENT *Client, FE_NETIO_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, Capacity, i;

    if (!List)
        return FALSE;
    List->Count = 0;
    List->Items = NULL;

    Buffer = (UCHAR *)calloc(1, FE_NETIO_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_KERNEL_MEMORY_CONTEXT,
                    NULL, 0, Buffer, FE_NETIO_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = *(ULONG *)(void *)Buffer;
    Capacity = (FE_NETIO_OUT_SIZE - 8) / FE_NETIO_RECORD_SIZE;
    if (Count > FE_NETIO_MAX_COUNT)
        Count = FE_NETIO_MAX_COUNT;
    if (Count > Capacity)
        Count = Capacity;

    if (Count) {
        List->Items = (FE_NETIO_ENTRY *)calloc(Count, sizeof(FE_NETIO_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
        for (i = 0; i < Count; i++) {
            const UCHAR *Rec = Buffer + 8 + (size_t)i * FE_NETIO_RECORD_SIZE;
            List->Items[i].Id = *(const ULONG *)(const void *)(Rec + 0);
            List->Items[i].Address = *(const ULONG64 *)(const void *)(Rec + 8);
        }
    }
    List->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeNetioLayerCallbacks(FE_NETIO_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

BOOL FePrintNetioLayerCallbacks(XPCH_CLIENT *Client)
{
    FE_NETIO_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i;

    if (!FeLoadNetioLayerCallbacks(Client, &List)) {
        printf("NetioLayerCallback: 0xF4 query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NetioLayerCallback (cmd 0xF4, %lu entries)\n", List.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (i = 0; i < List.Count; i++) {
        char Module[FE_NET_PATH_CHARS];
        char Company[FE_NET_COMPANY_CHARS];

        Module[0] = 0;
        Company[0] = 0;
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, List.Items[i].Address,
                            Module, sizeof(Module),
                            Company, sizeof(Company));
        printf("  [%lu] 0x%016llX  %s  %s\n", List.Items[i].Id,
               (unsigned long long)List.Items[i].Address,
               Module[0] ? Module : "unknown image",
               Company[0] ? Company : "");
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    FeFreeNetioLayerCallbacks(&List);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 13 WfpDeviceObject（0xFA）
//   原版 sub_1400ADB40 → sub_1400266C0（OutSize=16）
//   输出：Current@+0、Original@+8；两者相等 → "WfpDeviceObject is OK."
// ---------------------------------------------------------------------------
BOOL FeLoadWfpDeviceObject(XPCH_CLIENT *Client, FE_WFP_DEVICE *Device)
{
    UCHAR Buffer[FE_WFP_DEVICE_OUT_SIZE];
    UCHAR Result = 0;

    if (!Device)
        return FALSE;
    ZeroMemory(Buffer, sizeof(Buffer));
    if (!XpchInvoke(Client, XPCH_CMD_READ_KERNEL_MEMORY_RANGE_SIZE,
                    NULL, 0, Buffer, sizeof(Buffer), &Result) || Result != 1)
        return FALSE;
    Device->Current = *(ULONG64 *)(void *)(Buffer + 0);
    Device->Original = *(ULONG64 *)(void *)(Buffer + 8);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 14 WfpCallout（0xFC）
//   原版 sub_1400AD4E0 → sub_140026780（OutSize=4MB）
//   输出：Count@+0；HasFeCallout@+8；FeCallout 三回调@+24/+32/+40；
//         Callout 记录@+48 步长 32（Index@+0、Classify@+8、Notify@+16、FlowDelete@+24）
// ---------------------------------------------------------------------------
BOOL FeLoadWfpCallouts(XPCH_CLIENT *Client, FE_WFP_CALLOUT_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, Capacity, i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));

    Buffer = (UCHAR *)calloc(1, FE_WFP_CALLOUT_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_KERNEL_MEMORY_DETAIL,
                    NULL, 0, Buffer, FE_WFP_CALLOUT_OUT_SIZE, &Result) ||
        Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = *(ULONG *)(void *)Buffer;
    Capacity = (FE_WFP_CALLOUT_OUT_SIZE - FE_WFP_CALLOUT_RECORD_BASE) /
               FE_WFP_CALLOUT_RECORD_SIZE;
    if (Count > FE_WFP_CALLOUT_MAX_COUNT)
        Count = FE_WFP_CALLOUT_MAX_COUNT;
    if (Count > Capacity)
        Count = Capacity;

    List->HasFeCallout = (*(const UCHAR *)(const void *)(Buffer + 8) == 1);
    List->FeClassifyCallback = *(const ULONG64 *)(const void *)(Buffer + 24);
    List->FeNotifyCallback = *(const ULONG64 *)(const void *)(Buffer + 32);
    List->FeFlowDeleteFunction = *(const ULONG64 *)(const void *)(Buffer + 40);

    if (Count) {
        List->Items = (FE_WFP_CALLOUT_ENTRY *)calloc(
            Count, sizeof(FE_WFP_CALLOUT_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
        for (i = 0; i < Count; i++) {
            const UCHAR *Rec = Buffer + FE_WFP_CALLOUT_RECORD_BASE +
                               (size_t)i * FE_WFP_CALLOUT_RECORD_SIZE;
            List->Items[i].Index = *(const ULONG *)(const void *)(Rec + 0);
            List->Items[i].ClassifyCallback =
                *(const ULONG64 *)(const void *)(Rec + 8);
            List->Items[i].NotifyCallback =
                *(const ULONG64 *)(const void *)(Rec + 16);
            List->Items[i].FlowDeleteFunction =
                *(const ULONG64 *)(const void *)(Rec + 24);
        }
    }
    List->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeWfpCallouts(FE_WFP_CALLOUT_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

BOOL FePrintWfpCallouts(XPCH_CLIENT *Client)
{
    FE_WFP_CALLOUT_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i, f, rows = 0;

    if (!FeLoadWfpCallouts(Client, &List)) {
        printf("WfpCallout: 0xFC query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("WfpCallout (cmd 0xFC, %lu callouts)\n", List.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (i = 0; i < List.Count; i++) {
        const ULONG64 Callbacks[3] = { List.Items[i].ClassifyCallback,
                                       List.Items[i].NotifyCallback,
                                       List.Items[i].FlowDeleteFunction };
        static const char *Parts[3] = { "ClassifyCallback",
                                        "NotifyCallback",
                                        "FlowDeleteFunction" };
        for (f = 0; f < 3; f++) {
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            if (!Callbacks[f])
                continue;
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Callbacks[f],
                                Module, sizeof(Module),
                                Company, sizeof(Company));
            printf("  Callout[%lu].%s  0x%016llX  %s  %s\n",
                   List.Items[i].Index, Parts[f],
                   (unsigned long long)Callbacks[f],
                   Module[0] ? Module : "unknown image",
                   Company[0] ? Company : "");
            rows++;
        }
    }
    if (List.HasFeCallout && List.FeClassifyCallback) {
        printf("  FeCallout.ClassifyCallback  0x%016llX\n",
               (unsigned long long)List.FeClassifyCallback);
        rows++;
    }
    if (List.HasFeCallout && List.FeNotifyCallback) {
        printf("  FeCallout.NotifyCallback  0x%016llX\n",
               (unsigned long long)List.FeNotifyCallback);
        rows++;
    }
    if (List.HasFeCallout && List.FeFlowDeleteFunction) {
        printf("  FeCallout.FlowDeleteFunction  0x%016llX\n",
               (unsigned long long)List.FeFlowDeleteFunction);
        rows++;
    }
    printf("  total rows: %lu\n", rows);
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    FeFreeWfpCallouts(&List);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 16 NsiChangeNotification（0xFF）
//   原版 sub_1400ACA50 → sub_140026970（OutSize=4MB）
//   分组：Size@+0、Count@+4、条目@+16 步长 24（Node/Object/Zero）；
//   下一分组 = 本分组 + Size。客户端把 Object 当 Attach、Zero 当 Detach 显示。
// ---------------------------------------------------------------------------
BOOL FeLoadNsiChangeNotifications(XPCH_CLIENT *Client, FE_NSI_NOTIFY_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG GroupCount, g, Total = 0, Capacity;
    size_t Pos;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));

    Buffer = (UCHAR *)calloc(1, FE_NSI_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NSI_CHANGE_NOTIFICATION,
                    NULL, 0, Buffer, FE_NSI_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    GroupCount = *(ULONG *)(void *)Buffer;
    if (GroupCount > FE_NSI_GROUP_MAX)
        GroupCount = FE_NSI_GROUP_MAX;
    List->GroupCount = GroupCount;
    List->Groups = (FE_NSI_NOTIFY_GROUP *)calloc(
        GroupCount ? GroupCount : 1, sizeof(FE_NSI_NOTIFY_GROUP));
    if (!List->Groups) {
        free(Buffer);
        return FALSE;
    }

    Pos = 8;
    for (g = 0; g < GroupCount; g++) {
        ULONG Size, Count, k;

        if (Pos + 16 > FE_NSI_OUT_SIZE)
            break;
        Size = *(const ULONG *)(const void *)(Buffer + Pos);
        Count = *(const ULONG *)(const void *)(Buffer + Pos + 4);
        Capacity = (Size >= 16) ? (Size - 16) / FE_NSI_ENTRY_SIZE : 0;
        if (Count > Capacity)
            Count = Capacity;
        if (Pos + 16 + (size_t)Count * FE_NSI_ENTRY_SIZE > FE_NSI_OUT_SIZE)
            Count = (ULONG)((FE_NSI_OUT_SIZE - Pos - 16) / FE_NSI_ENTRY_SIZE);

        if (Count) {
            List->Groups[g].Items = (FE_NSI_NOTIFY_ENTRY *)calloc(
                Count, sizeof(FE_NSI_NOTIFY_ENTRY));
            if (!List->Groups[g].Items)
                break;
            for (k = 0; k < Count; k++) {
                const UCHAR *Rec = Buffer + Pos + 16 +
                                   (size_t)k * FE_NSI_ENTRY_SIZE;
                List->Groups[g].Items[k].Node =
                    *(const ULONG64 *)(const void *)(Rec + 0);
                List->Groups[g].Items[k].AttachCallback =
                    *(const ULONG64 *)(const void *)(Rec + 8);
                List->Groups[g].Items[k].DetachCallback =
                    *(const ULONG64 *)(const void *)(Rec + 16);
            }
        }
        List->Groups[g].Count = Count;
        Total += Count;

        if (Size < 16 || Pos + Size > FE_NSI_OUT_SIZE)
            break;
        Pos += Size;
    }
    List->Count = Total;
    free(Buffer);
    return TRUE;
}

void FeFreeNsiChangeNotifications(FE_NSI_NOTIFY_LIST *List)
{
    ULONG g;

    if (!List)
        return;
    if (List->Groups) {
        for (g = 0; g < List->GroupCount; g++)
            free(List->Groups[g].Items);
        free(List->Groups);
    }
    List->Groups = NULL;
    List->Count = 0;
    List->GroupCount = 0;
}

BOOL FePrintNsiChangeNotifications(XPCH_CLIENT *Client)
{
    FE_NSI_NOTIFY_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG g;

    if (!FeLoadNsiChangeNotifications(Client, &List)) {
        printf("NsiChangeNotification: 0xFF query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NsiChangeNotification (cmd 0xFF, %lu entries)\n", List.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (g = 0; g < List.GroupCount; g++) {
        ULONG k;
        for (k = 0; k < List.Groups[g].Count; k++) {
            const FE_NSI_NOTIFY_ENTRY *Item = &List.Groups[g].Items[k];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            if (Item->AttachCallback) {
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Item->AttachCallback,
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                printf("  NsiChangeNotification(0x%p).ChangeNotification_Attach"
                       "  0x%016llX  %s  %s\n",
                       (void *)(ULONG_PTR)Item->Node,
                       (unsigned long long)Item->AttachCallback,
                       Module[0] ? Module : "unknown image",
                       Company[0] ? Company : "");
            }
            if (Item->DetachCallback) {
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Item->DetachCallback,
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                printf("  NsiChangeNotification(0x%p).ChangeNotification_Detach"
                       "  0x%016llX  %s  %s\n",
                       (void *)(ULONG_PTR)Item->Node,
                       (unsigned long long)Item->DetachCallback,
                       Module[0] ? Module : "unknown image",
                       Company[0] ? Company : "");
            }
        }
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    FeFreeNsiChangeNotifications(&List);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 17 NsiChangeNotification_Monitor（0x100）
//   原版 sub_1400ACF80 → sub_140026A30（OutSize=4MB）
//   Count@+0；记录@+8 步长 64：Id@+8、7 个回调@+16..+64
//   名称：UnknowNameCallback1..5 / AttachCallback / DetchCallback
// ---------------------------------------------------------------------------
BOOL FeLoadNsiChangeMonitor(XPCH_CLIENT *Client, FE_NSI_MONITOR_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG Count, Capacity, i, f;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));

    Buffer = (UCHAR *)calloc(1, FE_NSI_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NSI_CHANGE_MONITOR,
                    NULL, 0, Buffer, FE_NSI_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    Count = *(ULONG *)(void *)Buffer;
    Capacity = (FE_NSI_OUT_SIZE - 8) / FE_NSI_MONITOR_STRIDE;
    if (Count > FE_NSI_MONITOR_MAX)
        Count = FE_NSI_MONITOR_MAX;
    if (Count > Capacity)
        Count = Capacity;

    if (Count) {
        List->Items = (FE_NSI_MONITOR_ENTRY *)calloc(
            Count, sizeof(FE_NSI_MONITOR_ENTRY));
        if (!List->Items) {
            free(Buffer);
            return FALSE;
        }
        for (i = 0; i < Count; i++) {
            const UCHAR *Rec = Buffer + 8 + (size_t)i * FE_NSI_MONITOR_STRIDE;
            List->Items[i].Id = *(const ULONG64 *)(const void *)(Rec + 8);
            for (f = 0; f < 7; f++)
                List->Items[i].Callbacks[f] =
                    *(const ULONG64 *)(const void *)(Rec + 16 + 8 * f);
        }
    }
    List->Count = Count;
    free(Buffer);
    return TRUE;
}

void FeFreeNsiChangeMonitor(FE_NSI_MONITOR_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

BOOL FePrintNsiChangeMonitor(XPCH_CLIENT *Client)
{
    static const char *Names[7] = {
        "UnknowNameCallback1", "UnknowNameCallback2", "UnknowNameCallback3",
        "UnknowNameCallback4", "UnknowNameCallback5", "AttachCallback",
        "DetchCallback"
    };
    FE_NSI_MONITOR_LIST List;
    ULONG i, f;

    if (!FeLoadNsiChangeMonitor(Client, &List)) {
        printf("NsiChangeNotificationMonitor: 0x100 query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NsiChangeNotificationMonitor (cmd 0x100, %lu entries)\n",
           List.Count);
    for (i = 0; i < List.Count; i++) {
        for (f = 0; f < 7; f++) {
            if (!List.Items[i].Callbacks[f])
                continue;
            printf("  NsiChangeNotificationMonitor(0x%p).%s  0x%016llX\n",
                   (void *)(ULONG_PTR)List.Items[i].Id, Names[f],
                   (unsigned long long)List.Items[i].Callbacks[f]);
        }
    }
    FeFreeNsiChangeMonitor(&List);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 15 NmrProvider(Client)（0xFE）
//   原版 sub_1400AC4F0 → sub_1400268B0（OutSize=4MB）
//   分组：Size@+0、Count@+4、NmrObject@+8、条目@+16 步长 40：
//   {EntryPtr@+0, IsClient@+8, Attach@+16, Detach@+24, Cleanup@+32}
//   名称：Nmr(0x%p).Client/Provider(0x%p).ProviderAttachClient /
//         ProviderDetachClient / ProviderCleanupBindingContext
// ---------------------------------------------------------------------------
BOOL FeLoadNmrProviders(XPCH_CLIENT *Client, FE_NMR_LIST *List)
{
    UCHAR *Buffer;
    UCHAR Result = 0;
    ULONG GroupCount, g, Total = 0, Capacity;
    size_t Pos;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));

    Buffer = (UCHAR *)calloc(1, FE_NMR_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_NMR_PROVIDERS,
                    NULL, 0, Buffer, FE_NMR_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }

    GroupCount = *(ULONG *)(void *)Buffer;
    if (GroupCount > FE_NMR_GROUP_MAX)
        GroupCount = FE_NMR_GROUP_MAX;
    List->GroupCount = GroupCount;
    List->Groups = (FE_NMR_GROUP *)calloc(
        GroupCount ? GroupCount : 1, sizeof(FE_NMR_GROUP));
    if (!List->Groups) {
        free(Buffer);
        return FALSE;
    }

    Pos = 8;
    for (g = 0; g < GroupCount; g++) {
        ULONG Size, Count, k;

        if (Pos + 16 > FE_NMR_OUT_SIZE)
            break;
        Size = *(const ULONG *)(const void *)(Buffer + Pos);
        Count = *(const ULONG *)(const void *)(Buffer + Pos + 4);
        List->Groups[g].NmrObject =
            *(const ULONG64 *)(const void *)(Buffer + Pos + 8);
        Capacity = (Size >= 16) ? (Size - 16) / FE_NMR_ENTRY_SIZE : 0;
        if (Count > Capacity)
            Count = Capacity;
        if (Pos + 16 + (size_t)Count * FE_NMR_ENTRY_SIZE > FE_NMR_OUT_SIZE)
            Count = (ULONG)((FE_NMR_OUT_SIZE - Pos - 16) / FE_NMR_ENTRY_SIZE);

        if (Count) {
            List->Groups[g].Items = (FE_NMR_ENTRY *)calloc(
                Count, sizeof(FE_NMR_ENTRY));
            if (!List->Groups[g].Items)
                break;
            for (k = 0; k < Count; k++) {
                const UCHAR *Rec = Buffer + Pos + 16 +
                                   (size_t)k * FE_NMR_ENTRY_SIZE;
                FE_NMR_ENTRY *Item = &List->Groups[g].Items[k];

                Item->EntryPtr = *(const ULONG64 *)(const void *)(Rec + 0);
                Item->IsClient = (*(const UCHAR *)(const void *)(Rec + 8) == 1);
                Item->AttachCallback =
                    *(const ULONG64 *)(const void *)(Rec + 16);
                Item->DetachCallback =
                    *(const ULONG64 *)(const void *)(Rec + 24);
                Item->CleanupCallback =
                    *(const ULONG64 *)(const void *)(Rec + 32);
            }
        }
        List->Groups[g].Count = Count;
        Total += Count;

        if (Size < 16 || Pos + Size > FE_NMR_OUT_SIZE)
            break;
        Pos += Size;
    }
    List->Count = Total;
    free(Buffer);
    return TRUE;
}

void FeFreeNmrProviders(FE_NMR_LIST *List)
{
    ULONG g;

    if (!List)
        return;
    if (List->Groups) {
        for (g = 0; g < List->GroupCount; g++)
            free(List->Groups[g].Items);
        free(List->Groups);
    }
    List->Groups = NULL;
    List->Count = 0;
    List->GroupCount = 0;
}

BOOL FePrintNmrProviders(XPCH_CLIENT *Client)
{
    static const char *CbNames[3] = {
        "ProviderAttachClient", "ProviderDetachClient",
        "ProviderCleanupBindingContext"
    };
    FE_NMR_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG g;

    if (!FeLoadNmrProviders(Client, &List)) {
        printf("NmrProvider(Client): 0xFE query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NmrProvider(Client) (cmd 0xFE, %lu entries)\n", List.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (g = 0; g < List.GroupCount; g++) {
        ULONG k;
        for (k = 0; k < List.Groups[g].Count; k++) {
            const FE_NMR_ENTRY *Item = &List.Groups[g].Items[k];
            const ULONG64 Callbacks[3] = { Item->AttachCallback,
                                           Item->DetachCallback,
                                           Item->CleanupCallback };
            ULONG f;

            for (f = 0; f < 3; f++) {
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!Callbacks[f])
                    continue;
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Callbacks[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                printf("  Nmr(0x%p).%s(0x%p).%s  0x%016llX  %s  %s\n",
                       (void *)(ULONG_PTR)List.Groups[g].NmrObject,
                       Item->IsClient ? "Client" : "Provider",
                       (void *)(ULONG_PTR)Item->EntryPtr, CbNames[f],
                       (unsigned long long)Callbacks[f],
                       Module[0] ? Module : "unknown image",
                       Company[0] ? Company : "");
            }
        }
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    FeFreeNmrProviders(&List);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 节点 18/19 Ipsec / Ipfltdrv Dispatch（0x11D / 0x11F）
//   块：Valid@+0；条目@+8 步长 48：{Original@+0, Entry@+8,
//   Primary@+16, Inline@+17}；节点 19 另含 FastIo 块（+1352）
//   仅显示 Primary/Inline 任一为 1 的条目；Original 仅在 Valid 时显示
// ---------------------------------------------------------------------------
const char *g_NvIrpNames[FE_DISPATCH_MAX_IRP] = {
    "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE",
    "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION", "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP", "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE", "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP_POWER"
};

const char *g_NvFastIoNames[FE_DISPATCH_MAX_FASTIO] = {
    "FastIoCheckIfPossible", "FastIoRead", "FastIoWrite",
    "FastIoQueryBasicInfo", "FastIoQueryStandardInfo", "FastIoLock",
    "FastIoUnlockSingle", "FastIoUnlockAll", "FastIoUnlockAllByKey",
    "FastIoDeviceControl", "AcquireFileForNtCreateSection",
    "ReleaseFileForNtCreateSection", "FastIoDetachDevice",
    "FastIoQueryNetworkOpenInfo", "AcquireForModWrite", "MdlRead",
    "MdlReadComplete", "PrepareMdlWrite", "MdlWriteComplete",
    "FastIoReadCompressed", "FastIoWriteCompressed",
    "MdlReadCompleteCompressed", "MdlWriteCompleteCompressed",
    "FastIoQueryOpen", "ReleaseForModWrite", "AcquireForCcFlush",
    "ReleaseForCcFlush"
};

static void NvParseDispatchBlock(const UCHAR *Block, ULONG MaxCount,
                                 FE_DISPATCH_BLOCK *Out)
{
    ULONG i;

    ZeroMemory(Out, sizeof(*Out));
    Out->Valid = (*(const UCHAR *)(const void *)Block == 1);
    Out->Count = MaxCount;
    for (i = 0; i < MaxCount; i++) {
        const UCHAR *Rec = Block + 8 + (size_t)i * FE_DISPATCH_ENTRY_SIZE;
        FE_DISPATCH_ENTRY *Entry = &Out->Entries[i];

        Entry->Original = *(const ULONG64 *)(const void *)(Rec + 0);
        Entry->Entry = *(const ULONG64 *)(const void *)(Rec + 8);
        Entry->Primary = (*(const UCHAR *)(const void *)(Rec + 16) == 1);
        Entry->Inline = (*(const UCHAR *)(const void *)(Rec + 17) == 1);
    }
}

BOOL FeLoadIpsecDispatch(XPCH_CLIENT *Client, FE_IPSEC_DISPATCH *Dispatch)
{
    UCHAR *Buffer;
    UCHAR Result = 0;

    if (!Dispatch)
        return FALSE;
    ZeroMemory(Dispatch, sizeof(*Dispatch));

    Buffer = (UCHAR *)calloc(1, FE_IPSEC_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_IPSEC_DISPATCH,
                    NULL, 0, Buffer, FE_IPSEC_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }
    NvParseDispatchBlock(Buffer + 8, FE_DISPATCH_MAX_IRP, &Dispatch->Irp);
    Dispatch->Irp.Valid = (*(const UCHAR *)(const void *)Buffer == 1);
    free(Buffer);
    return TRUE;
}

BOOL FePrintIpsecDispatch(XPCH_CLIENT *Client)
{
    FE_IPSEC_DISPATCH Dispatch;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i, Hooks = 0;

    if (!FeLoadIpsecDispatch(Client, &Dispatch)) {
        printf("Ipsec Dispatch: 0x11D query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("Ipsec Dispatch (cmd 0x11D, Fun Count: %lu)\n", Dispatch.Irp.Count);
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (i = 0; i < Dispatch.Irp.Count; i++) {
        const FE_DISPATCH_ENTRY *Item = &Dispatch.Irp.Entries[i];
        char Module[FE_NET_PATH_CHARS];
        char Company[FE_NET_COMPANY_CHARS];
        const char *Type;

        if (!Item->Primary && !Item->Inline)
            continue;
        Hooks++;
        if (Item->Primary && Item->Inline)
            Type = "ipsec & inline";
        else if (Item->Primary)
            Type = "ipsec hook";
        else
            Type = "inline hook";
        Module[0] = 0;
        Company[0] = 0;
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, Item->Entry, Module, sizeof(Module),
                            Company, sizeof(Company));
        printf("  %lu  %s  0x%016llX  %s  ", i, g_NvIrpNames[i],
               (unsigned long long)Item->Entry, Type);
        if (Dispatch.Irp.Valid)
            printf("0x%016llX", (unsigned long long)Item->Original);
        else
            printf("S_MR");
        printf("  %s  %s\n", Module[0] ? Module : "unknown image",
               Company[0] ? Company : "");
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    printf("Fun Count: %lu,  Hook: %lu\n", Dispatch.Irp.Count, Hooks);
    return TRUE;
}

BOOL FeLoadIpfDispatch(XPCH_CLIENT *Client, FE_IPF_DISPATCH *Dispatch)
{
    UCHAR *Buffer;
    UCHAR Result = 0;

    if (!Dispatch)
        return FALSE;
    ZeroMemory(Dispatch, sizeof(*Dispatch));

    Buffer = (UCHAR *)calloc(1, FE_IPF_OUT_SIZE);
    if (!Buffer)
        return FALSE;
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_IPF_DISPATCH,
                    NULL, 0, Buffer, FE_IPF_OUT_SIZE, &Result) || Result != 1) {
        free(Buffer);
        return FALSE;
    }
    Dispatch->Flags = *(const ULONG *)(const void *)Buffer;
    if (Dispatch->Flags & 1)
        NvParseDispatchBlock(Buffer + 8, FE_DISPATCH_MAX_IRP,
                             &Dispatch->Irp);
    if (Dispatch->Flags & 2)
        NvParseDispatchBlock(Buffer + FE_IPF_BLOCK_B_OFFSET,
                             FE_DISPATCH_MAX_FASTIO, &Dispatch->FastIo);
    Dispatch->Irp.Valid = (*(const UCHAR *)(const void *)(Buffer + 2) == 1);
    Dispatch->FastIo.Valid = (*(const UCHAR *)(const void *)(Buffer + 3) == 1);
    free(Buffer);
    return TRUE;
}

BOOL FePrintIpfDispatch(XPCH_CLIENT *Client)
{
    FE_IPF_DISPATCH Dispatch;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG Block, Scanned = 0, Hooks = 0;

    if (!FeLoadIpfDispatch(Client, &Dispatch)) {
        printf("Ipfltdrv Dispatch: 0x11F query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("Ipfltdrv Dispatch (cmd 0x11F)\n");
    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    for (Block = 0; Block < 2; Block++) {
        const FE_DISPATCH_BLOCK *Blk =
            Block ? &Dispatch.FastIo : &Dispatch.Irp;
        const char **Names = Block ? g_NvFastIoNames : g_NvIrpNames;
        ULONG i;

        if (Block == 0 && !(Dispatch.Flags & 1))
            continue;
        if (Block == 1 && !(Dispatch.Flags & 2))
            continue;
        for (i = 0; i < Blk->Count; i++) {
            const FE_DISPATCH_ENTRY *Item = &Blk->Entries[i];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];
            const char *Type;

            if (Block && !Item->Entry && !Item->Original)
                continue;
            Scanned++;
            if (!Item->Primary && !Item->Inline)
                continue;
            Hooks++;
            if (Item->Primary && Item->Inline)
                Type = "ipfltdrv & inline";
            else if (Item->Primary)
                Type = "ipfltdrv hook";
            else
                Type = "inline hook";
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Item->Entry, Module,
                                sizeof(Module), Company, sizeof(Company));
            printf("  %lu%s  %s  0x%016llX  %s  ", i,
                   Block ? "[FastIo]" : "", Names[i],
                   (unsigned long long)Item->Entry, Type);
            if (Blk->Valid)
                printf("0x%016llX", (unsigned long long)Item->Original);
            else
                printf("S_MR");
            printf("  %s  %s\n", Module[0] ? Module : "unknown image",
                   Company[0] ? Company : "");
        }
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    if (Scanned)
        printf("Fun Count: %lu,  Hook: %lu\n", Scanned, Hooks);
    else
        printf("Fun Count: 0,  Hook: %lu   <==>  IpFilterDriver maybe not load.\n",
               Hooks);
    return TRUE;
}

// ---------------------------------------------------------------------------
// 无界面输出（--network-cli）
// ---------------------------------------------------------------------------
BOOL FePrintTdiCallbacks(XPCH_CLIENT *Client)
{
    FE_TDI_CALLBACK_LIST List;
    ULONG i;

    if (!FeLoadTdiCallbacks(Client, &List)) {
        printf("NdisTdiCallback: 0xE6 query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NdisTdiCallback (cmd 0xE6, 6 QWORDs)\n");
    printf("  %-24s %-18s %-6s %-18s %s\n",
           "Fun Name", "Current Entry", "Hook", "Original Entry", "Module");
    for (i = 0; i < List.Count; i++) {
        printf("  %-24s 0x%016llX %-6s 0x%016llX %s\n",
               List.Items[i].Name,
               (unsigned long long)List.Items[i].Current,
               List.Items[i].Hooked ? "Hook" : "-",
               (unsigned long long)List.Items[i].Original,
               List.Items[i].Module[0] ? List.Items[i].Module : "-");
        if (List.Items[i].Company[0])
            printf("  %-24s %s\n", "", List.Items[i].Company);
    }
    return TRUE;
}

BOOL FePrintNdisOffloadHandlers(XPCH_CLIENT *Client)
{
    FE_NDIS_OFFLOAD_LIST List;
    ULONG i;

    if (!FeLoadNdisOffloadHandlers(Client, &List)) {
        printf("NdisTcpOffloadHandlers: 0xEA query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }
    printf("NdisTcpOffloadHandlers (cmd 0xEA, %lu entries)\n", List.Count);
    printf("  %-34s %-18s %-6s %-18s %s\n",
           "Fun Name", "Current Entry", "Hook", "Original Entry", "Module");
    for (i = 0; i < List.Count; i++) {
        printf("  %-34s 0x%016llX %-6s 0x%016llX %s\n",
               List.Items[i].Name,
               (unsigned long long)List.Items[i].Current,
               List.Items[i].Hooked ? "Hook" : "-",
               (unsigned long long)List.Items[i].Original,
               List.Items[i].Module[0] ? List.Items[i].Module : "-");
        if (List.Items[i].Company[0])
            printf("  %-34s %s\n", "", List.Items[i].Company);
    }
    return TRUE;
}

BOOL FePrintNdisOidTable(XPCH_CLIENT *Client)
{
    FE_NDIS_OID_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i, Rows = 0, Hooks = 0;

    if (!FeLoadNdisOidTable(Client, &List)) {
        printf("NdisOidTable: 0xEC query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }

    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    printf("NdisOidTable (cmd 0xEC, %lu entries)\n", List.Count);
    printf("  %-46s %-18s %-6s %-18s %s\n",
           "Fun Name", "Current Entry", "Hook", "Original Entry", "Module");
    for (i = 0; i < List.Count; i++) {
        const ULONG64 Current[2] = { List.Items[i].CurrentPre,
                                     List.Items[i].CurrentPost };
        const ULONG64 Original[2] = { List.Items[i].OriginalPre,
                                      List.Items[i].OriginalPost };
        const char *TypeName = FeOidName(List.Items[i].TypeId);
        ULONG f;

        for (f = 0; f < 2; f++) {
            char Name[128];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            if (!Current[f] && !Original[f])
                continue;
            sprintf_s(Name, sizeof(Name), "%s %sFun",
                      TypeName ? TypeName : "UnknowType",
                      f ? "Post" : "Pre");
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Current[f], Module, sizeof(Module),
                                Company, sizeof(Company));
            if (Current[f] != Original[f])
                Hooks++;
            printf("  %-46s 0x%016llX %-6s 0x%016llX %s\n",
                   Name,
                   (unsigned long long)Current[f],
                   (Current[f] != Original[f]) ? "Hook" : "-",
                   (unsigned long long)Original[f],
                   Module[0] ? Module : "-");
            if (Company[0])
                printf("  %-46s %s\n", "", Company);
            Rows++;
        }
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    printf("  rows=%lu, hooks=%lu\n", Rows, Hooks);
    FeFreeNdisOidTable(&List);
    return TRUE;
}

BOOL FePrintNdisInterfaces(XPCH_CLIENT *Client)
{
    FE_NDIS_IF_LIST List;
    ULONG i;

    if (!FeLoadNdisInterfaces(Client, &List)) {
        printf("Ndis Interface: 0xF0 query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }

    printf("Ndis Interface (cmd 0xF0, %lu entries)\n", List.Count);
    for (i = 0; i < List.Count; i++) {
        char Lines[FE_NDIS_IF_LINE_COUNT][FE_NET_PATH_CHARS];
        ULONG Line;

        printf("Interface[%lu]: 0x%p\n", i,
               (void *)(ULONG_PTR)List.Items[i].LoaderEntry);
        FeFormatNdisInterfaceLines(&List.Items[i], Lines);
        for (Line = 0; Line < FE_NDIS_IF_LINE_COUNT; Line++)
            printf("%s\n", Lines[Line]);
        printf("\n");
    }
    FeFreeNdisInterfaces(&List);
    return TRUE;
}

BOOL FePrintTdiPnpClients(XPCH_CLIENT *Client)
{
    static const char *FieldNames[5] = {
        "BindingHandler", "UnBindHandler", "AddAddressHandler",
        "DelAddressHandler", "PnPPowerHandler"
    };
    FE_TDI_PNP_LIST List;
    FE_SYMBOL_TABLE Symbols;
    BOOL HaveSymbols;
    ULONG i, Rows = 0;

    if (!FeLoadTdiPnpClients(Client, &List)) {
        printf("TdiPnpClient: 0xE8 query failed (connected=%d)\n",
               Client && Client->Opened);
        return FALSE;
    }

    HaveSymbols = FeOpenSymbolTable(Client, &Symbols);
    printf("TdiPnpClient (cmd 0xE8, %lu clients / %lu objects)\n",
           List.Count, List.Total);
    printf("  %-28s %-18s %-20s %-18s %s\n",
           "Client Name", "Client Object", "Fun Name", "Fun Entry", "Module");
    for (i = 0; i < List.Count; i++) {
        const ULONG64 Handlers[5] = {
            List.Items[i].BindingHandler,
            List.Items[i].UnBindHandler,
            List.Items[i].AddAddressHandler,
            List.Items[i].DelAddressHandler,
            List.Items[i].PnPPowerHandler
        };
        ULONG f;

        for (f = 0; f < 5; f++) {
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            if (!Handlers[f])
                continue;
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Handlers[f], Module, sizeof(Module),
                                Company, sizeof(Company));
            printf("  %-28s 0x%016llX %-20s 0x%016llX %s\n",
                   List.Items[i].ClientName[0] ? List.Items[i].ClientName : "-",
                   (unsigned long long)List.Items[i].ClientObject,
                   FieldNames[f],
                   (unsigned long long)Handlers[f],
                   Module[0] ? Module : "-");
            if (Company[0])
                printf("  %-28s %s\n", "", Company);
            Rows++;
        }
    }
    if (HaveSymbols)
        FeCloseSymbolTable(&Symbols);
    printf("  rows=%lu\n", Rows);
    FeFreeTdiPnpClients(&List);
    return TRUE;
}
