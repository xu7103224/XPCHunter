// ============================================================================
// FeNetworkPage.c — Network 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

/* 列规格：Percent=1 时按列表客户区宽度百分比（原版 formatter 的算法），
   否则为固定像素（原版页初始化时的 100/100/60/100/240/100）。 */
typedef struct _NW_COLUMN {
    const char *Title;
    int         Value;
    int         Percent;
} NW_COLUMN;

HWND g_hNwTree, g_hNwList, g_hNwStatus;
int  g_NwNode = 1;

/* 2026-10-29：节点 30/31 的追加回调（Item / Detail 两列） */
static int g_NrvRow = 0;
static void NrvAddToNetList(const char *Item, const char *Detail)
{
    NwAddRow(g_hNwList, g_NrvRow++, Item ? Item : "", Detail ? Detail : "", "", "", "", "");
}

void CreateNwColumns(HWND hList, int node)
{
    static const NW_COLUMN Node1Cols[6] = {
        { "Fun Name",         15, 1 },
        { "Current Entry",    15, 1 },
        { "Hook",             10, 1 },
        { "Original Entry",   15, 1 },
        { "Module",           30, 1 },
        { "File Corporation", 15, 1 }
    };
    static const NW_COLUMN Node2Cols[6] = {
        { "Client Name",      15, 1 },
        { "Client Object",    15, 1 },
        { "Fun Name",         15, 1 },
        { "Fun Entry",        15, 1 },
        { "Module",           25, 1 },
        { "File Corporation", 15, 1 }
    };
    static const NW_COLUMN NwFwpsCols[4] = {
        { "Index",             10, 1 },
        { "Fun Entry",         30, 1 },
        { "Module",            35, 1 },
        { "File Corporation",  25, 1 }
    };
    static const NW_COLUMN NwWfpDeviceCols[3] = {
        { "Current Device Object",  40, 1 },
        { "Hook",                   20, 1 },
        { "Original Device Object", 40, 1 }
    };
    static const NW_COLUMN NwCalloutCols[4] = {
        { "Fun Name",         25, 1 },
        { "Fun Entry",        30, 1 },
        { "Module",           30, 1 },
        { "File Corporation", 15, 1 }
    };
    static const NW_COLUMN NwNsiCols[4] = {
        { "Fun Name",         30, 1 },
        { "Fun Entry",        25, 1 },
        { "Module",           30, 1 },
        { "File Corporation", 15, 1 }
    };
    static const NW_COLUMN NwDispatchCols[6] = {
        { "Index",            1, 1 },
        { "Fun Name",         2, 1 },
        { "Current Entry",    2, 1 },
        { "Hook",             1, 1 },
        { "Original Entry",   2, 1 },
        { "File Corporation", 3, 1 }
    };
    static const NW_COLUMN PageInitCols[6] = {
        { "Fun Name",        100, 0 },
        { "Current Entry",   100, 0 },
        { "Hook",             60, 0 },
        { "Original Entry",  100, 0 },
        { "Module",          240, 0 },
        { "File Corporation",100, 0 }
    };
    const NW_COLUMN *cols = PageInitCols;
    LVCOLUMNA c;
    RECT rc;
    int i, cx;

    if (!hList)
        return;
    if (node == 1 || node == 3 || node == 4)
        cols = Node1Cols;
    else if (node == 2)
        cols = Node2Cols;
    GetClientRect(hList, &rc);
    cx = rc.right;
    if (cx < 200)
        cx = 940;

    while (ListView_DeleteColumn(hList, 0))
        ;
    if (node == 5) {
        /* 原版 sub_1400AAB70：单列 “Interface Information”，宽度=列表客户区 */
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = (char *)"Interface Information";
        c.cx = cx;
        c.iSubItem = 0;
        ListView_InsertColumn(hList, 0, &c);
        return;
    }
    if (node == 13) {
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (i = 0; i < 3; i++) {
            c.pszText = (char *)NwWfpDeviceCols[i].Title;
            c.cx = (cx * NwWfpDeviceCols[i].Value) / 100;
            c.iSubItem = i;
            ListView_InsertColumn(hList, i, &c);
        }
        return;
    }
    if (node == 18 || node == 19) {
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (i = 0; i < 6; i++) {
            c.pszText = (char *)NwDispatchCols[i].Title;
            c.cx = (cx * NwDispatchCols[i].Value) / 11;
            c.iSubItem = i;
            ListView_InsertColumn(hList, i, &c);
        }
        return;
    }
    if (node == 15 || node == 16 || node == 17) {
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (i = 0; i < 4; i++) {
            c.pszText = (char *)NwNsiCols[i].Title;
            c.cx = (cx * NwNsiCols[i].Value) / 100;
            c.iSubItem = i;
            ListView_InsertColumn(hList, i, &c);
        }
        return;
    }
    if (node == 14) {
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (i = 0; i < 4; i++) {
            c.pszText = (char *)NwCalloutCols[i].Title;
            c.cx = (cx * NwCalloutCols[i].Value) / 100;
            c.iSubItem = i;
            ListView_InsertColumn(hList, i, &c);
        }
        return;
    }
    if (node == 6 || node == 7 || node == 8 || node == 9 || node == 10 ||
        node == 11 || node == 12) {
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (i = 0; i < 4; i++) {
            c.pszText = (char *)NwFwpsCols[i].Title;
            c.cx = (cx * NwFwpsCols[i].Value) / 100;
            c.iSubItem = i;
            ListView_InsertColumn(hList, i, &c);
        }
        return;
    }
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (i = 0; i < 6; i++) {
        c.pszText = (char *)cols[i].Title;
        c.cx = cols[i].Percent ? (cx * cols[i].Value) / 100 : cols[i].Value;
        c.iSubItem = i;
        ListView_InsertColumn(hList, i, &c);
    }
}

void NwAddRow(HWND hList, int row, const char *s0, const char *s1,
                     const char *s2, const char *s3, const char *s4,
                     const char *s5)
{
    LVITEMA it;
    const char *vals[6];
    int i;

    vals[0] = s0; vals[1] = s1; vals[2] = s2;
    vals[3] = s3; vals[4] = s4; vals[5] = s5;

    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.pszText = (char *)vals[0];
    SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
    it.mask = LVIF_TEXT;
    it.iItem = row;
    for (i = 1; i < 6; i++) {
        it.iSubItem = i;
        it.pszText = (char *)vals[i];
        SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&it);
    }
}

HTREEITEM NwInsertNode(HTREEITEM Parent, const char *Name, LPARAM Node)
{
    TVINSERTSTRUCTA tv;

    ZeroMemory(&tv, sizeof(tv));
    tv.hParent = Parent;
    tv.hInsertAfter = TVI_LAST;
    tv.item.mask = TVIF_TEXT | TVIF_PARAM;
    tv.item.pszText = (char *)Name;
    tv.item.lParam = Node;
    return (HTREEITEM)SendMessageA(g_hNwTree, TVM_INSERTITEMA, 0, (LPARAM)&tv);
}

HTREEITEM NwFindNode(HTREEITEM Parent, LPARAM Node)
{
    HTREEITEM h = TreeView_GetChild(g_hNwTree, Parent);

    while (h) {
        TVITEMA it;
        ZeroMemory(&it, sizeof(it));
        it.mask = TVIF_PARAM;
        it.hItem = h;
        if (TreeView_GetItem(g_hNwTree, &it) && it.lParam == Node)
            return h;
        h = TreeView_GetNextSibling(g_hNwTree, h);
    }
    return NULL;
}

/* 原版 sub_1400A78F0：按 build 条件插入节点，节点 5 是根级兄弟节点。 */
void BuildNwTree(void)
{
    FE_OS_INFO Os;
    ULONG Build = 0;
    HTREEITEM Root;

    if (!g_hNwTree)
        return;
    TreeView_DeleteAllItems(g_hNwTree);
    if (FeLoadOsInfo(&Os))
        Build = Os.Build;

    Root = NwInsertNode(TVI_ROOT, "Network Callback", (LPARAM)(LONG_PTR)0xFFFF0000);
    NwInsertNode(Root, "NdisTdiCallback", 1);
    NwInsertNode(Root, "TdiPnpClient", 2);
    NwInsertNode(Root, "Ipfltdrv Dispatch Fun", 19);
    if (Build < 6000) {
        NwInsertNode(Root, "Ipsec Dispatch Fun", 18);
        NwInsertNode(Root, "IpFirewallHook", 21);
        if (Build < 7600)
            NwInsertNode(Root, "IpFilterHook", 20);
    } else {
        NwInsertNode(Root, "NdisTcpOffloadHandlers", 3);
        NwInsertNode(Root, "NdisOidTable", 4);
        NwInsertNode(Root, "FwpsTcpipDispatchTable", 6);
        if (Build >= 9200)
            NwInsertNode(Root, "FwpsL2DispatchTable", 7);
        if (Build >= 7600)
            NwInsertNode(Root, "WfpNblDispatchTable", 8);
        NwInsertNode(Root, "WfpStreamShim", 9);
        if (Build == 7600 || Build == 7601)
            NwInsertNode(Root, "WfpMacShim", 10);
        if (Build >= 7600)
            NwInsertNode(Root, "NetioLayerCallback", 11);
        NwInsertNode(Root, "NsiLegacyHandler", 12);
        NwInsertNode(Root, "WfpDeviceObject", 13);
        NwInsertNode(Root, "WfpCallout", 14);
        NwInsertNode(Root, "NmrProvider(Client)", 15);
        NwInsertNode(Root, "NsiChangeNotification", 16);
        NwInsertNode(Root, "NsiChangeNotification_Monitor", 17);
        NwInsertNode(Root, "Afd Dispatch Fun", 22);
        NwInsertNode(TVI_ROOT, "Ndis Interface", 5);
        /* 2026-10-29：两个纯注册表视图（不依赖驱动） */
        NwInsertNode(TVI_ROOT, "IE Plugin", 30);
        NwInsertNode(TVI_ROOT, "IFEO Hijack", 31);
    }
}

const char *NwNodeName(int node)
{
    switch (node) {
    case 1:  return "NdisTdiCallback";
    case 2:  return "TdiPnpClient";
    case 3:  return "NdisTcpOffloadHandlers";
    case 4:  return "NdisOidTable";
    case 5:  return "Ndis Interface";
    case 6:  return "FwpsTcpipDispatchTable";
    case 7:  return "FwpsL2DispatchTable";
    case 8:  return "WfpNblDispatchTable";
    case 9:  return "WfpStreamShim";
    case 10: return "WfpMacShim";
    case 11: return "NetioLayerCallback";
    case 12: return "NsiLegacyHandler";
    case 13: return "WfpDeviceObject";
    case 14: return "WfpCallout";
    case 15: return "NmrProvider(Client)";
    case 16: return "NsiChangeNotification";
    case 17: return "NsiChangeNotification_Monitor";
    case 18: return "Ipsec Dispatch Fun";
    case 19: return "Ipfltdrv Dispatch Fun";
    case 20: return "IpFilterHook";
    case 21: return "IpFirewallHook";
    case 22: return "Afd Dispatch Fun";
    case 30: return "IE Plugin";
    case 31: return "IFEO Hijack";
    default: return "Network Callback";
    }
}

void DoRefreshNetwork(void)
{
    char status[512];

    if (!g_hNwList || !g_hNwStatus)
        return;
    ListView_DeleteAllItems(g_hNwList);
    CreateNwColumns(g_hNwList, g_NwNode);

    if (g_NwNode != 1 && g_NwNode != 2 && g_NwNode != 3 && g_NwNode != 4 &&
        g_NwNode != 5 && g_NwNode != 6 && g_NwNode != 7 && g_NwNode != 8 &&
        g_NwNode != 9 && g_NwNode != 10 && g_NwNode != 11 && g_NwNode != 12 &&
        g_NwNode != 13 && g_NwNode != 14 && g_NwNode != 15 &&
        g_NwNode != 16 && g_NwNode != 17 && g_NwNode != 18 && g_NwNode != 19) {
        sprintf_s(status, sizeof(status),
                  "%s: formatter not implemented yet (node %d)",
                  NwNodeName(g_NwNode), g_NwNode);
        SetWindowTextA(g_hNwStatus, status);
        return;
    }

    if (!g_Client.Opened) {
        SetWindowTextA(g_hNwStatus, "Network: not connected");
        return;
    }

    if (g_NwNode == 1) {
        FE_TDI_CALLBACK_LIST List;
        ULONG i;
        int row = 0;

        if (!FeLoadTdiCallbacks(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus,
                           "Network: 0xE6 rejected (not TDI-capable or not initialized)");
            return;
        }
        for (i = 0; i < List.Count; i++) {
            char cur[32], orig[32];
            sprintf_s(cur, sizeof(cur), "0x%016llX",
                      (unsigned long long)List.Items[i].Current);
            sprintf_s(orig, sizeof(orig), "0x%016llX",
                      (unsigned long long)List.Items[i].Original);
            NwAddRow(g_hNwList, row++,
                     List.Items[i].Name,
                     cur,
                     List.Items[i].Hooked ? "Hook" : "-",
                     orig,
                     List.Items[i].Module[0] ? List.Items[i].Module : "-",
                     List.Items[i].Company[0] ? List.Items[i].Company : "-");
        }
        sprintf_s(status, sizeof(status),
                  "NdisTdiCallback Fun Count: %lu", List.Count);
        SetWindowTextA(g_hNwStatus, status);
    } else if (g_NwNode == 3) {
        FE_NDIS_OFFLOAD_LIST List;
        ULONG i;
        int row = 0;

        if (!FeLoadNdisOffloadHandlers(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus,
                           "NdisTcpOffloadHandlers: 0xEA rejected");
            return;
        }
        for (i = 0; i < List.Count; i++) {
            char cur[32], orig[32];
            sprintf_s(cur, sizeof(cur), "0x%016llX",
                      (unsigned long long)List.Items[i].Current);
            sprintf_s(orig, sizeof(orig), "0x%016llX",
                      (unsigned long long)List.Items[i].Original);
            NwAddRow(g_hNwList, row++,
                     List.Items[i].Name,
                     cur,
                     List.Items[i].Hooked ? "Hook" : "-",
                     orig,
                     List.Items[i].Module[0] ? List.Items[i].Module
                                             : "unknown image",
                     List.Items[i].Company[0] ? List.Items[i].Company
                                              : "unknown");
        }
        sprintf_s(status, sizeof(status),
                  "NdisTcpOffloadHandlers Fun Count: %lu", List.Count);
        SetWindowTextA(g_hNwStatus, status);
    } else if (g_NwNode == 4) {
        FE_NDIS_OID_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i, rows = 0, hooks = 0;
        int row = 0;

        if (!FeLoadNdisOidTable(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "NdisOidTable: 0xEC rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < List.Count; i++) {
            const ULONG64 Current[2] = { List.Items[i].CurrentPre,
                                         List.Items[i].CurrentPost };
            const ULONG64 Original[2] = { List.Items[i].OriginalPre,
                                          List.Items[i].OriginalPost };
            const char *TypeName = FeOidName(List.Items[i].TypeId);
            ULONG f;

            for (f = 0; f < 2; f++) {
                char Name[128];
                char cur[32], orig[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!Current[f] && !Original[f])
                    continue;
                sprintf_s(Name, sizeof(Name), "%s %sFun",
                          TypeName ? TypeName : "UnknowType",
                          f ? "Post" : "Pre");
                sprintf_s(cur, sizeof(cur), "0x%016llX",
                          (unsigned long long)Current[f]);
                sprintf_s(orig, sizeof(orig), "0x%016llX",
                          (unsigned long long)Original[f]);
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Current[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                if (Current[f] != Original[f])
                    hooks++;
                NwAddRow(g_hNwList, row++,
                         Name,
                         cur,
                         (Current[f] != Original[f]) ? "Hook" : "-",
                         orig,
                         Module[0] ? Module : "unknown image",
                         Company[0] ? Company : "unknown");
                rows++;
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status),
                  "NdisOidTable Fun Count: %lu, Hook: %lu", rows, hooks);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNdisOidTable(&List);
    } else if (g_NwNode == 5) {
        FE_NDIS_IF_LIST List;
        ULONG i;
        int row = 0;

        if (!FeLoadNdisInterfaces(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "Ndis Interface: 0xF0 rejected");
            return;
        }
        for (i = 0; i < List.Count; i++) {
            char Header[64];
            char Lines[FE_NDIS_IF_LINE_COUNT][FE_NET_PATH_CHARS];
            ULONG Line;

            sprintf_s(Header, sizeof(Header), "Interface[%lu]: 0x%p", i,
                      (void *)(ULONG_PTR)List.Items[i].LoaderEntry);
            NwAddRow(g_hNwList, row++, Header, "", "", "", "", "");
            FeFormatNdisInterfaceLines(&List.Items[i], Lines);
            for (Line = 0; Line < FE_NDIS_IF_LINE_COUNT; Line++)
                NwAddRow(g_hNwList, row++, Lines[Line], "", "", "", "", "");
            NwAddRow(g_hNwList, row++, "", "", "", "", "", "");
        }
        sprintf_s(status, sizeof(status), "Ndis Interface : %lu", List.Count);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNdisInterfaces(&List);
    } else if (g_NwNode == 6 || g_NwNode == 7 || g_NwNode == 8 ||
               g_NwNode == 9 || g_NwNode == 10 || g_NwNode == 12) {
        FE_FWPS_TABLE Table;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i;
        int row = 0;

        if (!FeLoadFwpsTable(&g_Client,
                             (g_NwNode == 6)  ? XPCH_CMD_FWPS_TCPIP_TABLE :
                             (g_NwNode == 7)  ? XPCH_CMD_FWPS_L2_TABLE :
                             (g_NwNode == 8)  ? XPCH_CMD_WFP_NBL_TABLE :
                             (g_NwNode == 9)  ? XPCH_CMD_WFP_STREAM_SHIM :
                             (g_NwNode == 10) ? XPCH_CMD_WFP_MAC_SHIM :
                                                XPCH_CMD_NSI_LEGACY_HANDLER,
                             (g_NwNode == 10 || g_NwNode == 12)
                                 ? FE_FWPS_SINGLE_OUT_SIZE : FE_FWPS_LARGE_OUT_SIZE,
                             (g_NwNode == 10 || g_NwNode == 12) ? 1 : 0,
                             &Table)) {
            sprintf_s(status, sizeof(status), "%s: command rejected",
                      NwNodeName(g_NwNode));
            SetWindowTextA(g_hNwStatus, status);
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < Table.Count; i++) {
            char Index[16], Entry[32];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            sprintf_s(Index, sizeof(Index), "%lu", i);
            sprintf_s(Entry, sizeof(Entry), "0x%p",
                      (void *)(ULONG_PTR)Table.Entries[i]);
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Table.Entries[i],
                                Module, sizeof(Module),
                                Company, sizeof(Company));
            NwAddRow(g_hNwList, row++,
                     Index, Entry,
                     Module[0] ? Module : "unknown image",
                     Company[0] ? Company : "",
                     "", "");
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status), "%s Fun Count: %lu",
                  NwNodeName(g_NwNode), Table.Count);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeFwpsTable(&Table);
    } else if (g_NwNode == 11) {
        FE_NETIO_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i;
        int row = 0;

        if (!FeLoadNetioLayerCallbacks(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "NetioLayerCallback: 0xF4 rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < List.Count; i++) {
            char Index[16], Entry[32];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];

            sprintf_s(Index, sizeof(Index), "%lu", List.Items[i].Id);
            sprintf_s(Entry, sizeof(Entry), "0x%p",
                      (void *)(ULONG_PTR)List.Items[i].Address);
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, List.Items[i].Address,
                                Module, sizeof(Module),
                                Company, sizeof(Company));
            NwAddRow(g_hNwList, row++,
                     Index, Entry,
                     Module[0] ? Module : "unknown image",
                     Company[0] ? Company : "",
                     "", "");
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status), "NetioLayerCallback Fun Count: %lu",
                  List.Count);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNetioLayerCallbacks(&List);
    } else if (g_NwNode == 13) {
        FE_WFP_DEVICE Device;

        if (!FeLoadWfpDeviceObject(&g_Client, &Device)) {
            SetWindowTextA(g_hNwStatus, "WfpDeviceObject: 0xFA rejected");
            return;
        }
        {
            char Current[32], Original[32];
            sprintf_s(Current, sizeof(Current), "0x%p",
                      (void *)(ULONG_PTR)Device.Current);
            sprintf_s(Original, sizeof(Original), "0x%p",
                      (void *)(ULONG_PTR)Device.Original);
            NwAddRow(g_hNwList, 0, Current,
                     (Device.Current == Device.Original) ? "-" : "Hook",
                     Original, "", "", "");
        }
        SetWindowTextA(g_hNwStatus, (Device.Current == Device.Original)
            ? "WfpDeviceObject is OK."
            : "WfpDeviceObject been Replaced.");
    } else if (g_NwNode == 14) {
        FE_WFP_CALLOUT_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i, f;
        int row = 0;

        if (!FeLoadWfpCallouts(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "WfpCallout: 0xFC rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < List.Count; i++) {
            const ULONG64 Callbacks[3] = { List.Items[i].ClassifyCallback,
                                           List.Items[i].NotifyCallback,
                                           List.Items[i].FlowDeleteFunction };
            static const char *Parts[3] = { "ClassifyCallback",
                                            "NotifyCallback",
                                            "FlowDeleteFunction" };
            for (f = 0; f < 3; f++) {
                char Name[64], Entry[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!Callbacks[f])
                    continue;
                sprintf_s(Name, sizeof(Name), "Callout[%lu].%s",
                          List.Items[i].Index, Parts[f]);
                sprintf_s(Entry, sizeof(Entry), "0x%p",
                          (void *)(ULONG_PTR)Callbacks[f]);
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Callbacks[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                NwAddRow(g_hNwList, row++, Name, Entry,
                         Module[0] ? Module : "unknown image",
                         Company[0] ? Company : "", "", "");
            }
        }
        if (List.HasFeCallout) {
            const ULONG64 FeCallbacks[3] = { List.FeClassifyCallback,
                                             List.FeNotifyCallback,
                                             List.FeFlowDeleteFunction };
            static const char *FeNames[3] = {
                "FeCallout.ClassifyCallback",
                "FeCallout.NotifyCallback",
                "FeCallout.FlowDeleteFunction"
            };
            for (f = 0; f < 3; f++) {
                char Entry[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!FeCallbacks[f])
                    continue;
                sprintf_s(Entry, sizeof(Entry), "0x%p",
                          (void *)(ULONG_PTR)FeCallbacks[f]);
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, FeCallbacks[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                NwAddRow(g_hNwList, row++, FeNames[f], Entry,
                         Module[0] ? Module : "unknown image",
                         Company[0] ? Company : "", "", "");
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status), "WfpCallout Fun Count: %d", row);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeWfpCallouts(&List);
    } else if (g_NwNode == 15) {
        static const char *NmrNames[3] = {
            "ProviderAttachClient", "ProviderDetachClient",
            "ProviderCleanupBindingContext"
        };
        FE_NMR_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG g, k, f;
        int row = 0;

        if (!FeLoadNmrProviders(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "NmrProvider(Client): 0xFE rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (g = 0; g < List.GroupCount; g++) {
            for (k = 0; k < List.Groups[g].Count; k++) {
                const FE_NMR_ENTRY *Item = &List.Groups[g].Items[k];
                const ULONG64 Callbacks[3] = { Item->AttachCallback,
                                               Item->DetachCallback,
                                               Item->CleanupCallback };

                for (f = 0; f < 3; f++) {
                    char Name[112], Entry[32];
                    char Module[FE_NET_PATH_CHARS];
                    char Company[FE_NET_COMPANY_CHARS];

                    if (!Callbacks[f])
                        continue;
                    sprintf_s(Name, sizeof(Name),
                              "Nmr(0x%p).%s(0x%p).%s",
                              (void *)(ULONG_PTR)List.Groups[g].NmrObject,
                              Item->IsClient ? "Client" : "Provider",
                              (void *)(ULONG_PTR)Item->EntryPtr, NmrNames[f]);
                    sprintf_s(Entry, sizeof(Entry), "0x%p",
                              (void *)(ULONG_PTR)Callbacks[f]);
                    Module[0] = 0;
                    Company[0] = 0;
                    if (HaveSymbols)
                        FeResolveSymbol(&Symbols, Callbacks[f],
                                        Module, sizeof(Module),
                                        Company, sizeof(Company));
                    NwAddRow(g_hNwList, row++, Name, Entry,
                             Module[0] ? Module : "unknown image",
                             Company[0] ? Company : "", "", "");
                }
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status),
                  "NmrProvider(Client) Fun Count: %d", row);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNmrProviders(&List);
    } else if (g_NwNode == 16) {
        FE_NSI_NOTIFY_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG g, k;
        int row = 0;

        if (!FeLoadNsiChangeNotifications(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus, "NsiChangeNotification: 0xFF rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (g = 0; g < List.GroupCount; g++) {
            for (k = 0; k < List.Groups[g].Count; k++) {
                const FE_NSI_NOTIFY_ENTRY *Item = &List.Groups[g].Items[k];
                const ULONG64 Callbacks[2] = { Item->AttachCallback,
                                               Item->DetachCallback };
                static const char *Parts[2] = { "ChangeNotification_Attach",
                                                "ChangeNotification_Detach" };
                ULONG f;

                for (f = 0; f < 2; f++) {
                    char Name[80], Entry[32];
                    char Module[FE_NET_PATH_CHARS];
                    char Company[FE_NET_COMPANY_CHARS];

                    if (!Callbacks[f])
                        continue;
                    sprintf_s(Name, sizeof(Name),
                              "NsiChangeNotification(0x%p).%s",
                              (void *)(ULONG_PTR)Item->Node, Parts[f]);
                    sprintf_s(Entry, sizeof(Entry), "0x%p",
                              (void *)(ULONG_PTR)Callbacks[f]);
                    Module[0] = 0;
                    Company[0] = 0;
                    if (HaveSymbols)
                        FeResolveSymbol(&Symbols, Callbacks[f],
                                        Module, sizeof(Module),
                                        Company, sizeof(Company));
                    NwAddRow(g_hNwList, row++, Name, Entry,
                             Module[0] ? Module : "unknown image",
                             Company[0] ? Company : "", "", "");
                }
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status),
                  "NsiChangeNotification Fun Count: %d", row);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNsiChangeNotifications(&List);
    } else if (g_NwNode == 17) {
        static const char *MonitorNames[7] = {
            "UnknowNameCallback1", "UnknowNameCallback2",
            "UnknowNameCallback3", "UnknowNameCallback4",
            "UnknowNameCallback5", "AttachCallback", "DetchCallback"
        };
        FE_NSI_MONITOR_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i, f;
        int row = 0;

        if (!FeLoadNsiChangeMonitor(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus,
                           "NsiChangeNotificationMonitor: 0x100 rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < List.Count; i++) {
            for (f = 0; f < 7; f++) {
                char Name[96], Entry[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!List.Items[i].Callbacks[f])
                    continue;
                sprintf_s(Name, sizeof(Name),
                          "NsiChangeNotificationMonitor(0x%p).%s",
                          (void *)(ULONG_PTR)List.Items[i].Id,
                          MonitorNames[f]);
                sprintf_s(Entry, sizeof(Entry), "0x%p",
                          (void *)(ULONG_PTR)List.Items[i].Callbacks[f]);
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, List.Items[i].Callbacks[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                NwAddRow(g_hNwList, row++, Name, Entry,
                         Module[0] ? Module : "unknown image",
                         Company[0] ? Company : "", "", "");
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status),
                  "NsiChangeNotificationMonitor Fun Count: %d", row);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeNsiChangeMonitor(&List);
    } else if (g_NwNode == 18) {
        FE_IPSEC_DISPATCH Dispatch;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i;
        int row = 0, hooks = 0;

        if (!FeLoadIpsecDispatch(&g_Client, &Dispatch)) {
            SetWindowTextA(g_hNwStatus, "Ipsec Dispatch: 0x11D rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < Dispatch.Irp.Count; i++) {
            const FE_DISPATCH_ENTRY *Item = &Dispatch.Irp.Entries[i];
            char Name[80], Entry[32], Original[32];
            char Module[FE_NET_PATH_CHARS];
            char Company[FE_NET_COMPANY_CHARS];
            const char *Type;

            if (!Item->Primary && !Item->Inline)
                continue;
            hooks++;
            if (Item->Primary && Item->Inline)
                Type = "ipsec & inline";
            else if (Item->Primary)
                Type = "ipsec hook";
            else
                Type = "inline hook";
            sprintf_s(Name, sizeof(Name), "%lu", i);
            sprintf_s(Entry, sizeof(Entry), "0x%p", (void *)(ULONG_PTR)Item->Entry);
            if (Dispatch.Irp.Valid)
                sprintf_s(Original, sizeof(Original), "0x%p",
                          (void *)(ULONG_PTR)Item->Original);
            else
                strcpy_s(Original, sizeof(Original), "S_MR");
            Module[0] = 0;
            Company[0] = 0;
            if (HaveSymbols)
                FeResolveSymbol(&Symbols, Item->Entry, Module, sizeof(Module),
                                Company, sizeof(Company));
            NwAddRow(g_hNwList, row++, Name, g_NvIrpNames[i], Entry,
                     Type, Original, Company[0] ? Company : "");
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status), "Fun Count: %lu,  Hook: %d",
                  Dispatch.Irp.Count, hooks);
        SetWindowTextA(g_hNwStatus, status);
    } else if (g_NwNode == 19) {
        FE_IPF_DISPATCH Dispatch;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG Block, scanned = 0;
        int row = 0, hooks = 0;

        if (!FeLoadIpfDispatch(&g_Client, &Dispatch)) {
            SetWindowTextA(g_hNwStatus, "Ipfltdrv Dispatch: 0x11F rejected");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (Block = 0; Block < 2; Block++) {
            const FE_DISPATCH_BLOCK *Blk = Block ? &Dispatch.FastIo : &Dispatch.Irp;
            const char **Names = Block ? g_NvFastIoNames : g_NvIrpNames;
            ULONG i;

            if (Block == 0 && !(Dispatch.Flags & 1))
                continue;
            if (Block == 1 && !(Dispatch.Flags & 2))
                continue;
            for (i = 0; i < Blk->Count; i++) {
                const FE_DISPATCH_ENTRY *Item = &Blk->Entries[i];
                char Name[80], Entry[32], Original[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];
                const char *Type;

                if (Block && !Item->Entry && !Item->Original)
                    continue;
                scanned++;
                if (!Item->Primary && !Item->Inline)
                    continue;
                hooks++;
                if (Item->Primary && Item->Inline)
                    Type = "ipfltdrv & inline";
                else if (Item->Primary)
                    Type = "ipfltdrv hook";
                else
                    Type = "inline hook";
                sprintf_s(Name, sizeof(Name), Block ? "%lu[FastIo]" : "%lu", i);
                sprintf_s(Entry, sizeof(Entry), "0x%p",
                          (void *)(ULONG_PTR)Item->Entry);
                if (Blk->Valid)
                    sprintf_s(Original, sizeof(Original), "0x%p",
                              (void *)(ULONG_PTR)Item->Original);
                else
                    strcpy_s(Original, sizeof(Original), "S_MR");
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Item->Entry, Module,
                                    sizeof(Module), Company, sizeof(Company));
                NwAddRow(g_hNwList, row++, Name, Names[i], Entry, Type,
                         Original, Company[0] ? Company : "");
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        if (scanned)
            sprintf_s(status, sizeof(status), "Fun Count: %lu,  Hook: %d",
                      scanned, hooks);
        else
            sprintf_s(status, sizeof(status),
                      "Fun Count: 0,  Hook: %d   <==>  IpFilterDriver maybe not load.",
                      hooks);
        SetWindowTextA(g_hNwStatus, status);
    } else if (g_NwNode == 30) {
        /* 2026-10-29 IE 插件（纯注册表枚举，无需驱动） */
        ULONG n;
        char status[256];
        g_NrvRow = 0;
        n = FeLoadIePlugins(NrvAddToNetList);
        sprintf_s(status, sizeof(status), "IE Plugin: %lu registered (BHO/Extension)", n);
        SetWindowTextA(g_hNwStatus, status);
    } else if (g_NwNode == 31) {
        /* 2026-10-29 IFEO 映像劫持（纯注册表枚举） */
        ULONG n;
        char status[256];
        g_NrvRow = 0;
        n = FeLoadIfeoEntries(NrvAddToNetList);
        sprintf_s(status, sizeof(status),
                  "IFEO Hijack: %lu suspicious entr(ies) with Debugger/GlobalFlag", n);
        SetWindowTextA(g_hNwStatus, status);
    } else {
        static const char *FieldNames[5] = {
            "BindingHandler", "UnBindHandler", "AddAddressHandler",
            "DelAddressHandler", "PnPPowerHandler"
        };
        FE_TDI_PNP_LIST List;
        FE_SYMBOL_TABLE Symbols;
        BOOL HaveSymbols;
        ULONG i, rows = 0;
        int row = 0;

        if (!FeLoadTdiPnpClients(&g_Client, &List)) {
            SetWindowTextA(g_hNwStatus,
                           "Network: 0xE8 rejected (needs 4MB output)");
            return;
        }
        HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
        for (i = 0; i < List.Count; i++) {
            ULONG64 Handlers[5];
            ULONG f;

            Handlers[0] = List.Items[i].BindingHandler;
            Handlers[1] = List.Items[i].UnBindHandler;
            Handlers[2] = List.Items[i].AddAddressHandler;
            Handlers[3] = List.Items[i].DelAddressHandler;
            Handlers[4] = List.Items[i].PnPPowerHandler;

            for (f = 0; f < 5; f++) {
                char entry[32];
                char object[32];
                char Module[FE_NET_PATH_CHARS];
                char Company[FE_NET_COMPANY_CHARS];

                if (!Handlers[f])
                    continue;
                Module[0] = 0;
                Company[0] = 0;
                if (HaveSymbols)
                    FeResolveSymbol(&Symbols, Handlers[f],
                                    Module, sizeof(Module),
                                    Company, sizeof(Company));
                sprintf_s(entry, sizeof(entry), "0x%016llX",
                          (unsigned long long)Handlers[f]);
                sprintf_s(object, sizeof(object), "0x%016llX",
                          (unsigned long long)List.Items[i].ClientObject);
                NwAddRow(g_hNwList, row++,
                         List.Items[i].ClientName[0] ? List.Items[i].ClientName : "-",
                         object,
                         FieldNames[f],
                         entry,
                         Module[0] ? Module : "-",
                         Company[0] ? Company : "-");
                rows++;
            }
        }
        if (HaveSymbols)
            FeCloseSymbolTable(&Symbols);
        sprintf_s(status, sizeof(status),
                  "TdiPnpClient Fun Count: %lu", rows);
        SetWindowTextA(g_hNwStatus, status);
        FeFreeTdiPnpClients(&List);
    }
}


/* 原版恢复入口：sub_1400A6840 -> sub_140025510（cmd 0xE7），无参数。 */
void NwRestoreTdi(void)
{
    UCHAR res = 0;
    char msg[256];

    if (!g_Client.Opened) {
        SetWindowTextA(g_hNwStatus, "Restore TDI hooks: not connected");
        return;
    }
    if (FeRestoreTdiCallbacks(&g_Client, &res))
        sprintf_s(msg, sizeof(msg),
                  "NdisTdiCallback: restore (0xE7) sent, result=%u", res);
    else
        sprintf_s(msg, sizeof(msg),
                  "NdisTdiCallback: restore (0xE7) rejected (result=%u)", res);
    DoRefreshNetwork();
    SetWindowTextA(g_hNwStatus, msg);
}

void NwSelectNode(int Node)
{
    HTREEITEM h = NwFindNode(TVI_ROOT, Node);

    if (!h || !g_hNwTree)
        return;
    g_NwNode = Node;
    /* TVM_SELECTITEM + TVGN_CARVE(9)：旧 SDK 未定义 TVGN_CARVE */
    SendMessageA(g_hNwTree, TVM_SELECTITEM, (WPARAM)9, (LPARAM)h);
    DoRefreshNetwork();
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Network 页段，逐字保留） ---- */
void FeNetworkPagePageShow(HWND hWnd, int page)
{
int isNetwork = (page == 4);     /* 第 5 个 Tab = Network */
    /* Network 页：切到该页时按需拉一次数据 */
    if (g_hNwTree)   ShowWindow(g_hNwTree,   isNetwork ? SW_SHOW : SW_HIDE);
    if (g_hNwList)   ShowWindow(g_hNwList,   isNetwork ? SW_SHOW : SW_HIDE);
    if (g_hNwStatus) ShowWindow(g_hNwStatus, isNetwork ? SW_SHOW : SW_HIDE);
    if (isNetwork && g_Client.Opened)
        DoRefreshNetwork();}
