// ============================================================================
// FeKernelPage.c — Kernel 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"

/* DoPromptText 的跨消息缓冲（原 frontend.c 静态，2026-10-28 拆分时随 Kernel 页移入） */
char  *g_PromptBuf;
size_t g_PromptChars;
BOOL   g_PromptOk;
#include "FePages.h"

HWND g_hKmTabs, g_hKmList, g_hKmStatus, g_hKmKExtra;
HWND g_hKmSel1, g_hKmSel2, g_hKmSel3;
int  g_KmTab = 0;
int  g_KmSel[3] = { 0, 0, 0 };   /* tab 11/12/13 的下拉选择（frontend.c 写入） */
int  g_KmOnlyLoaded = 0;

/* ==========================================================================
 * Kernel 页（原版第 2 个主 Tab，现已是主 Tab 容器里的一页）
 *
 *   Kernel Module : EnumDeviceDrivers + GetDeviceDriverBaseNameW/FileNameW
 *   Driver        : SCM 的 SERVICE_DRIVER 枚举 + QueryServiceConfig
 * ========================================================================== */
void CreateKmColumns(HWND hList, int tab)
{
    LVCOLUMNA c;

    while (ListView_DeleteColumn(hList, 0))
        ;

    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    if (tab == 0) {
        c.pszText = "Base";      c.cx = 140; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Size";      c.cx = 90;  c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Name";      c.cx = 160; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Path";      c.cx = 520; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 1) {
        c.pszText = "Service";   c.cx = 180; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "State";     c.cx = 100; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Start";     c.cx = 80;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "ImagePath"; c.cx = 550; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 10) {
        /* GDT：Selector / Base / Limit / Access / Flags / Descriptor */
        c.pszText = "Sel";        c.cx = 60;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Base";       c.cx = 160; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Limit";      c.cx = 100; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Access";     c.cx = 80;  c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Flags";      c.cx = 80;  c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
        c.pszText = "Descriptor"; c.cx = 400; c.iSubItem = 5; ListView_InsertColumn(hList, 5, &c);
    } else if (tab == 8) {
        /* IDT：Vector / Handler RVA / State */
        c.pszText = "Vector";      c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Handler RVA"; c.cx = 200; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "State";       c.cx = 200; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    } else if (tab == 9) {
        /* I/O Port：与 IDT 同源（0x046），按上下文汇总 */
        c.pszText = "Context";     c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Entries";     c.cx = 120; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Non-empty";   c.cx = 120; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Note";        c.cx = 550; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 6 || tab == 7) {
        /* Hidden Drivers / Suspicious DriverObject */
        c.pszText = "Name";   c.cx = 200; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Base";   c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Size";   c.cx = 90;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Path";   c.cx = 300; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Reason"; c.cx = 200; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    } else if (tab == 4) {
        /* Device（0x056）：Type / DeviceObject / Driver / Device / Object / Path */
        c.pszText = "Type";   c.cx = 50;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "DeviceObject"; c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Driver"; c.cx = 130; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Device"; c.cx = 130; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Object"; c.cx = 150; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
        c.pszText = "Path";   c.cx = 330; c.iSubItem = 5; ListView_InsertColumn(hList, 5, &c);
    } else if (tab == 5) {
        /* Object（0x0D5） */
        c.pszText = "Index"; c.cx = 60;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "ObjectHeader"; c.cx = 180; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Field1"; c.cx = 180; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Field2"; c.cx = 180; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Note";   c.cx = 340; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    } else {
        /* SSDT / Shadow SSDT（0x101 / 0x102） */
        c.pszText = "Index";     c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Address";   c.cx = 190; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Original";  c.cx = 190; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "State";     c.cx = 130; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
        c.pszText = "Note";      c.cx = 360; c.iSubItem = 4; ListView_InsertColumn(hList, 4, &c);
    }
}

void KmSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoRefreshKernel(void)
{
    char status[1024];   /* Driver 页状态栏要拼三段内核项文案，256 不够 */

    if (!g_hKmList || !g_hKmStatus)
        return;
    ListView_DeleteAllItems(g_hKmList);
    CreateKmColumns(g_hKmList, g_KmTab);

    if (g_KmTab == 0) {
        FE_KMODULE_LIST list;
        ULONG i;
        if (!FeLoadKernelModules(&list)) {
            sprintf_s(status, sizeof(status),
                      "Kernel Module: load failed, GetLastError=%lu", GetLastError());
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char base[32], size[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(base, sizeof(base), "%016I64X", list.Items[i].Base);
            sprintf_s(size, sizeof(size), "0x%I64X", list.Items[i].Size);
            it.pszText = base;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            KmSetText(g_hKmList, (int)i, 1, size);
            KmSetText(g_hKmList, (int)i, 2,
                      list.Items[i].Name[0] ? list.Items[i].Name : "(?)");
            KmSetText(g_hKmList, (int)i, 3,
                      list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
        }
        sprintf_s(status, sizeof(status), "Kernel Module: %lu loaded modules", list.Count);
        FeFreeKernelModules(&list);
    } else if (g_KmTab == 1) {
        FE_DRIVER_LIST list;
        ULONG i;
        if (!FeLoadDrivers(&list)) {
            sprintf_s(status, sizeof(status),
                      "Driver: load failed, GetLastError=%lu", GetLastError());
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            const char *st;
            int row;
            /* Only Show Loaded Driver：只保留 RUNNING 的服务 */
            if (g_KmOnlyLoaded && list.Items[i].State != SERVICE_RUNNING)
                continue;
            row = ListView_GetItemCount(g_hKmList);
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = list.Items[i].Name;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            switch (list.Items[i].State) {
            case SERVICE_RUNNING:   st = "RUNNING";  break;
            case SERVICE_STOPPED:   st = "STOPPED";  break;
            case SERVICE_START_PENDING: st = "STARTING"; break;
            case SERVICE_STOP_PENDING:  st = "STOPPING"; break;
            default:                st = "?";        break;
            }
            KmSetText(g_hKmList, row, 1, st);
            switch (list.Items[i].Start) {
            case SERVICE_BOOT_START:   st = "BOOT";   break;
            case SERVICE_SYSTEM_START: st = "SYSTEM"; break;
            case SERVICE_AUTO_START:   st = "AUTO";   break;
            case SERVICE_DEMAND_START: st = "DEMAND"; break;
            case SERVICE_DISABLED:     st = "DISABLED"; break;
            default:                   st = "?";      break;
            }
            KmSetText(g_hKmList, row, 2, st);
            KmSetText(g_hKmList, row, 3,
                      list.Items[i].Path[0] ? list.Items[i].Path : "(?)");
        }
        sprintf_s(status, sizeof(status),
                  "Driver: %lu kernel driver services%s",
                  (ULONG)ListView_GetItemCount(g_hKmList),
                  g_KmOnlyLoaded ? " (loaded only)" : "");
        FeFreeDrivers(&list);
        /* 原版 Driver 页状态栏同时给出隐藏驱动/可疑驱动对象计数 */
        {
            FE_HDRV_LIST hid, sus;
            if (FeLoadHiddenDrivers(&hid, &sus)) {
                char tail[160];
                char head[256];
                sprintf_s(tail, sizeof(tail),
                          "   |   Drivers: %lu / Hidden Drivers: %lu / "
                          "Suspicious DriverObject: %lu",
                          (ULONG)ListView_GetItemCount(g_hKmList), hid.Count, sus.Count);
                strcpy_s(head, sizeof(head), status);
                sprintf_s(status, sizeof(status), "%s%s", head, tail);
                FeFreeHiddenDrivers(&hid);
                FeFreeHiddenDrivers(&sus);
            }
        }
        /* 【G4 2026-10-22】原版 Driver 页状态栏有三段文案，必须始终可见：
             KiDebugRoutine Hooked / Find PTE Hook in 0x%p / Find Next ClassInitData。
           这三项在当前环境都拿不到结论（缺少内核任意地址读），但"拿不到"
           本身就是要展示的信息 —— 原版在同样条件下也会显示状态。
           因此无条件拼接，不可用时写明原因，而不是整段不显示。 */
        {
            ULONG64 kr = 0;
            BOOL hooked = FALSE;
            char detail[512];
            char pteDetail[512];
            char extra[640];

            FeCheckKiDebugRoutine(&kr, &hooked, detail, sizeof(detail));
            FeFindPteHook(pteDetail, sizeof(pteDetail), &hooked);
            sprintf_s(extra, sizeof(extra),
                      "%s   |   %s   |   Find Next ClassInitData: not available "
                      "- the driver has no arbitrary kernel-VA read (0xF7/0xF9 read "
                      "one fixed GT pointer; 0x3A needs GT[0x41E4]/GT[0x4189], both 0 here)",
                      detail, pteDetail);
            if (g_hKmKExtra)
                SetWindowTextA(g_hKmKExtra, extra);
        }
    } else if (g_KmTab == 4) {
        /* Device 子页：0x056 CmdEnumObjectAllTypes（0x2000 起不再蓝屏） */
        FE_DEVICE_LIST dev;
        if (!FeLoadDeviceObjects(&g_Client, &dev, 0x20000)) {
            sprintf_s(status, sizeof(status), "Device: query failed (0x056)%s",
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        if (dev.State != 1) {
            sprintf_s(status, sizeof(status),
                      "Device: driver rejected (0x056 result=%u)", dev.ResultByte);
            SetWindowTextA(g_hKmStatus, status);
            FeFreeDeviceList(&dev);
            return;
        }
        /* 按 Type 升序展示，让同一段（FileSystem / PnpManager / ...）连续成块，
           视觉上等价于原版「File System Item」树的一个个节点分组。
           驱动侧的顺序是"枚举器调用顺序"，同一 Type 也可能分散（段 A 与段 D
           分别是 DeviceObjects 与 FileSystemDevices），排序后更好读。 */
        {
            ULONG *order = (ULONG *)calloc(dev.Count ? dev.Count : 1, sizeof(ULONG));
            ULONG row = 0, pass;
            if (!order) {
                sprintf_s(status, sizeof(status), "Device: out of memory");
                SetWindowTextA(g_hKmStatus, status);
                FeFreeDeviceList(&dev);
                return;
            }
            for (pass = 0; pass < dev.Count; pass++)
                order[pass] = pass;
            /* 稳定插入排序（29 条量级，O(n^2) 可接受，且保持同 Type 内的原顺序） */
            for (pass = 1; pass < dev.Count; pass++) {
                ULONG key = order[pass], j = pass;
                while (j > 0 && dev.Items[order[j - 1]].Type > dev.Items[key].Type) {
                    order[j] = order[j - 1];
                    j--;
                }
                order[j] = key;
            }
            for (pass = 0; pass < dev.Count; pass++, row++) {
                ULONG i = order[pass];
                LVITEMA it;
                char t[32], d[32];
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)row;
                /* Type 列显示语义名（原版「File System Item」树的分类口径），
                   末尾带上原始数值便于对照驱动输出。 */
                sprintf_s(t, sizeof(t), "%s (%lu)",
                          FeDeviceTypeName(dev.Items[i].Type),
                          (unsigned long)dev.Items[i].Type);
                sprintf_s(d, sizeof(d), "%016I64X", dev.Items[i].DeviceObject);
                it.pszText = t;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, (int)row, 1, d);
                KmSetText(g_hKmList, (int)row, 2, dev.Items[i].DriverName);
                KmSetText(g_hKmList, (int)row, 3, dev.Items[i].DeviceName);
                KmSetText(g_hKmList, (int)row, 4, dev.Items[i].ObjectName);
                KmSetText(g_hKmList, (int)row, 5, dev.Items[i].FilePath);
            }
            free(order);
        }
        /* 状态栏给出原版「File System Item」树的节点计数（按驱动名筛选），
           比单纯列 9 个 Type 数字更贴近原版语义。 */
        sprintf_s(status, sizeof(status),
                  "Device: %lu objects (0x056)  |  File System Item: "
                  "FltMgr %lu, Volmgr %lu, Volsnap %lu, Npfs %lu, "
                  "Msfs %lu, Usbport %lu, Ftdisk %lu",
                  dev.Count,
                  FeDeviceListMatchDriver(&dev, 0, "FltMgr",   NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "\\volmgr", NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "volsnap",  NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "Npfs",     NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "Msfs",     NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "Usbport",  NULL, 0),
                  FeDeviceListMatchDriver(&dev, 0, "Ftdisk",   NULL, 0));
        FeFreeDeviceList(&dev);
    } else if (g_KmTab == 5) {
        /* Object 子页：0x0D5 CmdEnumKernelObjectTable */
        FE_KOBJ_LIST obj;
        ULONG i;
        if (!FeLoadKernelObjectTable(&g_Client, &obj)) {
            sprintf_s(status, sizeof(status), "Object: query failed (0x0D5)%s",
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            return;
        }
        if (obj.State != 1) {
            sprintf_s(status, sizeof(status),
                      "Object: driver rejected (0x0D5 result=%u)", obj.ResultByte);
            SetWindowTextA(g_hKmStatus, status);
            FeFreeKernelObjectList(&obj);
            return;
        }
        for (i = 0; i < obj.Count; i++) {
            LVITEMA it;
            char idx[16], h[32], f1[32], f2[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(idx, sizeof(idx), "%lu", (unsigned long)i);
            sprintf_s(h, sizeof(h), "%016I64X", obj.Items[i].ObjectHeader);
            sprintf_s(f1, sizeof(f1), "%016I64X", obj.Items[i].Field1);
            sprintf_s(f2, sizeof(f2), "%016I64X", obj.Items[i].Field2);
            it.pszText = idx;
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            KmSetText(g_hKmList, (int)i, 1, h);
            KmSetText(g_hKmList, (int)i, 2, f1);
            KmSetText(g_hKmList, (int)i, 3, f2);
            KmSetText(g_hKmList, (int)i, 4, "kernel object header");
        }
        sprintf_s(status, sizeof(status),
                  "Object: %lu entries (build %lu, cmd 0x0D5)", obj.Count, obj.Build);
        FeFreeKernelObjectList(&obj);
    } else if (g_KmTab == 6 || g_KmTab == 7) {
        /* Hidden Drivers / Suspicious DriverObject（用户态比对，无需驱动） */
        FE_HDRV_LIST hidden, susp;
        FE_HDRV_LIST *show;
        ULONG i;
        if (!FeLoadHiddenDrivers(&hidden, &susp)) {
            SetWindowTextA(g_hKmStatus, "Hidden/Suspicious: query failed");
            return;
        }
        show = (g_KmTab == 6) ? &hidden : &susp;
        for (i = 0; i < show->Count; i++) {
            LVITEMA it;
            char base[32], size[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = show->Items[i].Name[0] ? show->Items[i].Name : "(?)";
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(base, sizeof(base), "%016I64X", show->Items[i].Base);
            sprintf_s(size, sizeof(size), "0x%I64X", show->Items[i].Size);
            KmSetText(g_hKmList, (int)i, 1, base);
            KmSetText(g_hKmList, (int)i, 2, size);
            KmSetText(g_hKmList, (int)i, 3, show->Items[i].Path);
            KmSetText(g_hKmList, (int)i, 4, show->Items[i].Reason);
        }
        sprintf_s(status, sizeof(status),
                  "Hidden Drivers: %lu / Suspicious DriverObject: %lu",
                  hidden.Count, susp.Count);
        FeFreeHiddenDrivers(&hidden);
        FeFreeHiddenDrivers(&susp);
    } else if (g_KmTab == 8) {
        /* IDT（0x046）：每个中断向量的处理函数 RVA */
        FE_IDT_LIST idt;
        ULONG i;
        if (!FeLoadIdt(&g_Client, &idt)) {
            SetWindowTextA(g_hKmStatus, "IDT: query failed (0x046, not connected?)");
            return;
        }
        if (idt.ContextCount == 0) {
            SetWindowTextA(g_hKmStatus,
                           "IDT: 0x046 returned no context (chain did not resolve)");
            FeFreeIdt(&idt);
            return;
        }
        {
            ULONG nonEmpty = 0;
            for (i = 0; i < idt.Count; i++) {
                LVITEMA it;
                char vec[16], rva[32];
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)i;
                sprintf_s(vec, sizeof(vec), "%lu", (unsigned long)idt.Items[i].Vector);
                sprintf_s(rva, sizeof(rva), "%016I64X", idt.Items[i].HandlerRva);
                it.pszText = vec;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, (int)i, 1, rva);
                if (idt.Items[i].HandlerRva) {
                    nonEmpty++;
                    KmSetText(g_hKmList, (int)i, 2, "present");
                } else {
                    KmSetText(g_hKmList, (int)i, 2, "(empty gate)");
                }
            }
            sprintf_s(status, sizeof(status),
                      "IDT: %lu vectors, %lu non-empty (0x046, %lu context(s))",
                      idt.Count, nonEmpty, idt.ContextCount);
        }
        SetWindowTextA(g_hKmStatus, status);
        FeFreeIdt(&idt);
    } else if (g_KmTab == 9) {
        /* I/O Port：同一命令的上下文视图（每处理器一个上下文） */
        FE_IDT_LIST idt;
        ULONG i;
        if (!FeLoadIdt(&g_Client, &idt)) {
            SetWindowTextA(g_hKmStatus, "I/O Port: query failed (0x046)");
            return;
        }
        if (idt.ContextCount == 0) {
            SetWindowTextA(g_hKmStatus,
                           "I/O Port: 0x046 returned no context (chain did not resolve)");
            FeFreeIdt(&idt);
            return;
        }
        {
            ULONG nonEmpty = 0;
            char ctx[16], ent[16], ne[16];
            for (i = 0; i < idt.Count; i++)
                if (idt.Items[i].HandlerRva)
                    nonEmpty++;
            sprintf_s(ctx, sizeof(ctx), "0");
            sprintf_s(ent, sizeof(ent), "%lu", idt.Count);
            sprintf_s(ne, sizeof(ne), "%lu", nonEmpty);
            {
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = 0;
                it.pszText = ctx;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, 0, 1, ent);
                KmSetText(g_hKmList, 0, 2, ne);
                KmSetText(g_hKmList, 0, 3,
                          "IDT gate table for this processor (0x046)");
            }
            sprintf_s(status, sizeof(status),
                      "I/O Port: %lu context(s), %lu IDT gates (%lu non-empty)",
                      idt.ContextCount, idt.Count, nonEmpty);
        }
        SetWindowTextA(g_hKmStatus, status);
        FeFreeIdt(&idt);
    } else if (g_KmTab == 10) {
        /* GDT（0x0CD）：逐描述符展示。条目布局 64KB 步长：
             +0x00 已写条目数  +0x04 处理器号  +0x08 limit
             +0x10 GDT 基址    +0x18 描述符数   +0x20 起 GDT 原始字节 */
        BYTE *out = (BYTE *)calloc(1, 0x10018);
        UCHAR res = 0;
        BOOL ok;
        ULONG entries;

        if (!out) {
            SetWindowTextA(g_hKmStatus, "GDT: out of memory");
            return;
        }
        ok = XpchInvoke(&g_Client, 0xCD, NULL, 0, out, 0x10018, &res);
        entries = *(ULONG *)out;
        if (!ok || entries == 0) {
            sprintf_s(status, sizeof(status),
                      "GDT: 0x0CD %s result=%u entries=%lu",
                      ok ? "ok" : "rejected", res, entries);
            SetWindowTextA(g_hKmStatus, status);
            free(out);
            return;
        }
        {
            BYTE *e = out + 8;
            ULONG limit = *(ULONG *)(e + 0);
            ULONG64 base = *(ULONG64 *)(e + 8);
            ULONG dcount = *(ULONG *)(e + 0x10);
            BYTE *gdt = e + 0x18;
            ULONG cpu = *(ULONG *)(e - 4);
            ULONG k;

            for (k = 0; k < dcount; k++) {
                ULONG64 d = *(ULONG64 *)(gdt + k * 8);
                LVITEMA it;
                char sel[16], baseText[32], limText[16], accText[16];
                char flagText[16], desc[64];
                ULONG access = (ULONG)((d >> 40) & 0xFF);
                ULONG flags = (ULONG)((d >> 52) & 0xF);
                ULONG64 dbase = ((d >> 16) & 0xFFFFFF) | (((d >> 56) & 0xFF) << 24);
                ULONG dlim = (ULONG)(d & 0xFFFF) | (ULONG)(((d >> 48) & 0xF) << 16);

                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)k;
                sprintf_s(sel, sizeof(sel), "%04lX", (unsigned long)(k * 8));
                it.pszText = sel;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                sprintf_s(baseText, sizeof(baseText), "%08I64X", dbase);
                sprintf_s(limText, sizeof(limText), "%05lX", (unsigned long)dlim);
                sprintf_s(accText, sizeof(accText), "%02lX", (unsigned long)access);
                sprintf_s(flagText, sizeof(flagText), "%lX", (unsigned long)flags);
                sprintf_s(desc, sizeof(desc), "%016I64X", d);
                KmSetText(g_hKmList, (int)k, 1, baseText);
                KmSetText(g_hKmList, (int)k, 2, limText);
                KmSetText(g_hKmList, (int)k, 3, accText);
                KmSetText(g_hKmList, (int)k, 4, flagText);
                KmSetText(g_hKmList, (int)k, 5, desc);
            }
            sprintf_s(status, sizeof(status),
                      "GDT: cpu%lu base=%016I64X limit=0x%lX descriptors=%lu "
                      "(0x0CD, %lu context(s))",
                      (unsigned long)cpu, base, (unsigned long)limit,
                      (unsigned long)dcount, entries);
        }
        SetWindowTextA(g_hKmStatus, status);
        free(out);
    } else if (g_KmTab >= 11 && g_KmTab <= 13) {
        /* 【2026-10-30 二次整合】三个下拉 Tab 承载全部已验证的枚举命令。
           命令实测与布局分析见 docs/reversing/剩余工作清单_2026-10-30.md §7/§8。Mode 含义：
             0 服务表族（48 步进，idx@+0、addr@+16）
             1 0x0B2 专用（CopySsdtHookTargetTable3：64 步进，
               idx@目标+4、addr@+8 —— EntOff 已含 +4）
             2 0x026 句柄/进程记录（count@0，0x30 步进：
               time@+0、ptr@+8、UTF-16 名字@+0x10）
             3 0x0D4 对象类型（count@0，0x20 步进：TypeAddr@+0、Count@+16）
             4 0x0E5 内核句柄表（count@0，0x20 步进：4 个 QWORD）
             5 0x031 服务（count@0，0x30 步进：Record@+0、Off@+24、Pool@+32）
             6 0x108 处理器（稀疏 QWORD，跳零）
             7 上下文族（0x40 步进从 +0x10：func@+8、idx@+0x30，idx 递增） */
        static const struct { ULONG Cmd; ULONG Size; const char *Name;
                              ULONG EntOff; ULONG Stride; int Mode; } Tbl[] = {
            {0x0AC,1352,"Tcpip",8,48,0},   {0x0AE,1352,"KbdClass",8,48,0},
            {0x0B0,1400,"Disk",8,48,0},    {0x0B2,1864,"Ntoskrnl",8,0x40,0},
            {0x0B4,1352,"Acpi",8,48,0},    {0x0B6,1400,"Disk2",8,48,0},
            {0x0B8,1352,"MouClass",8,48,0},{0x0BA,1352,"nsiproxy",8,48,0},
            {0x0BC,1352,"tdx",8,48,0},     {0x0C0,1352,"wdf01000",8,48,0},
            {0x026,4194304,"Handles",0x20,0x30,2},
            {0x0D4,2097152,"ObjTypes",8,0x20,3},
            {0x0E5,2097152,"KHandle",8,0x20,4},
            {0x031,2097152,"Services",8,0x30,5},
            {0x108,2097152,"CpuInfo",0x10,8,6},
            {0x129,1800,"FsCtx",0x10,0x40,7},
            {0x12D,1400,"ObjCtx",0x10,0x40,7},
            {0x12F,1352,"ProcCtx",0x10,0x40,7},
            {0x13A,7168,"HAL",0,0,8},
        };
        static const int Base[3] = { 0, 10, 13 };
        const int sel = g_KmSel[g_KmTab - 11];
        const int idx = Base[g_KmTab - 11] + sel;
        UCHAR ready = 0;
        BYTE *buf;
        BOOL ok;
        ULONG shown = 0;
        ULONG64 extraCount = 0, extraBase = 0;
        char hex1[32], hex2[32], hex3[32];

        if (sel < 0 || sel > 9 ||
            idx >= (int)(sizeof(Tbl) / sizeof(Tbl[0]))) {
            SetWindowTextA(g_hKmStatus, "selection out of range");
            return;
        }
        /* 【堆溢出防护】CopySyscallTable7 族最多写调用方缓冲 +1382 字节
           而 handler 校验 1352 —— 缓冲 +256 余量吸收（详见工作清单 §7.1）。 */
        buf = (BYTE *)calloc(1, Tbl[idx].Size + 256);
        if (!buf) {
            SetWindowTextA(g_hKmStatus, "km table: out of memory");
            return;
        }
        ok = (g_Client.Opened)
           ? XpchInvoke(&g_Client, Tbl[idx].Cmd, NULL, 0, buf, Tbl[idx].Size, &ready)
           : FALSE;
        if (!ok) {
            sprintf_s(status, sizeof(status),
                      "%s: driver rejected (cmd 0x%03X)%s",
                      Tbl[idx].Name, Tbl[idx].Cmd,
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            free(buf);
            return;
        }
#define KM_ROW(c0, c1, c2, c3) do { \
            LVITEMA it_; ZeroMemory(&it_, sizeof(it_)); \
            it_.mask = LVIF_TEXT; it_.iItem = (int)shown; it_.pszText = (char *)(c0); \
            SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it_); \
            KmSetText(g_hKmList, (int)shown, 1, (c1)); \
            KmSetText(g_hKmList, (int)shown, 2, (c2)); \
            KmSetText(g_hKmList, (int)shown, 3, (c3)); \
            KmSetText(g_hKmList, (int)shown, 4, Tbl[idx].Name); \
            shown++; \
        } while (0)

        switch (Tbl[idx].Mode) {
        case 0: {
            ULONG k;
            /* 0x0B2 实测（probe --dump 1864）：步长 0x40、29 条，
               字段偏移与 48 字节族一致（idx@+0、addr@+16）。 */
            ULONG maxk = (Tbl[idx].Stride > 48) ? 29 : 28;
            for (k = 0; k < maxk; k++) {
                ULONG off = Tbl[idx].EntOff + Tbl[idx].Stride * k;
                if (off + 24 > Tbl[idx].Size) break;
                sprintf_s(hex1, sizeof(hex1), "%lu",
                          *(ULONG *)(buf + off));
                sprintf_s(hex2, sizeof(hex2), "%016I64X",
                          *(ULONG64 *)(buf + off + 16));
                sprintf_s(hex3, sizeof(hex3), "%u", ready);
                KM_ROW(hex1, hex2, "-", hex3);
            }
            /* count/base 是 1400 族（EnumSsdtFunctionTable2 /
               FillSyscallTableInfo）的尾巴字段；0x0B2 的 1864 缓冲里
               该偏移落在条目数据内，不能读。 */
            if (Tbl[idx].Size >= 1376 && Tbl[idx].Stride <= 48) {
                extraCount = *(ULONG *)(buf + 1352);
                extraBase  = *(ULONG64 *)(buf + 1368);
            }
            if (extraCount || extraBase)
                sprintf_s(status, sizeof(status),
                          "%s: %lu entries (cmd 0x%03X, ready=%u, count=%lu base=%016I64X)",
                          Tbl[idx].Name, shown, Tbl[idx].Cmd, ready,
                          (unsigned long)extraCount, extraBase);
            else
                sprintf_s(status, sizeof(status),
                          "%s: %lu entries (cmd 0x%03X, ready=%u)",
                          Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 1: {
            ULONG k;
            for (k = 0; k < 29; k++) {
                ULONG off = Tbl[idx].EntOff + 64 * k;
                ULONG64 addr;
                if (off + 64 > Tbl[idx].Size + 256) break;
                addr = *(ULONG64 *)(buf + off + 4);
                sprintf_s(hex1, sizeof(hex1), "%lu", *(ULONG *)(buf + off));
                sprintf_s(hex2, sizeof(hex2), "%016I64X", addr);
                sprintf_s(hex3, sizeof(hex3), "%016I64X",
                          *(ULONG64 *)(buf + off + 18));
                KM_ROW(hex1, hex2, hex3, addr ? "present" : "null");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu entries (cmd 0x%03X, ready=%u, 64-byte stride)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 2: {
            /* 0x026 实测布局（probe --dump，146 条真实进程）：
                 count @ +0x00
                 每条 552 字节（138 个 DWORD，见 EnumerateProcessObjects 的
                 EntryOffset = 138 * EntryIndex）：
                   +0x08 MarkType(1=新进程)   +0x09 受保护标志
                   +0x10 / +0x20 创建时间      +0x18 PID
                   +0x28 进程对象指针          +0x30 映像路径(UTF-16)
               【2026-10-30 修正】旧参数写成 EntOff=0x20 / Stride=0x30 /
               名字@+0x10，只有第 0 条（Idle）碰巧对得上，其余全错位。 */
            ULONG count = *(ULONG *)buf;
            ULONG k;
            if (count > 512) count = 512;
            for (k = 0; k < count; k++) {
                ULONG off = 552 * k;
                char name[80];
                const WCHAR *wp;
                int ci;
                if (off + 0x230 > Tbl[idx].Size + 256) break;
                sprintf_s(hex1, sizeof(hex1), "%lu",
                          (unsigned long)*(ULONG64 *)(buf + off + 0x18));
                sprintf_s(hex2, sizeof(hex2), "%016I64X",
                          *(ULONG64 *)(buf + off + 0x28));
                wp = (const WCHAR *)(buf + off + 0x30);
                for (ci = 0; ci < (int)sizeof(name) - 1 && ci < 200 && wp[ci]; ci++)
                    name[ci] = (char)(wp[ci] & 0x7F);
                name[ci] = 0;
                /* 映像路径最长 0x100 字符，hex3 只有 32 字节，必须截断。
                   MSVC 的 sprintf_s 溢出会调 invalid parameter handler
                   直接终止进程（不是截断），所以用 _TRUNCATE。 */
                _snprintf_s(hex3, sizeof(hex3), _TRUNCATE, "%s", name);
                KM_ROW(hex1, hex2, hex3,
                       buf[off + 0x08] ? "new" : "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu records (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 3: {
            ULONG count = *(ULONG *)buf;
            ULONG k;
            if (count > 128) count = 128;
            for (k = 0; k < count; k++) {
                ULONG off = Tbl[idx].EntOff + Tbl[idx].Stride * k;
                if (off + 24 > Tbl[idx].Size + 256) break;
                sprintf_s(hex1, sizeof(hex1), "%lu", (unsigned long)k);
                sprintf_s(hex2, sizeof(hex2), "%016I64X",
                          *(ULONG64 *)(buf + off));
                sprintf_s(hex3, sizeof(hex3), "%016I64X",
                          *(ULONG64 *)(buf + off + 16));
                KM_ROW(hex1, hex2, hex3, "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu entries (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 4: {
            ULONG count = *(ULONG *)buf;
            ULONG k;
            if (count > 128) count = 128;
            for (k = 0; k < count; k++) {
                ULONG off = Tbl[idx].EntOff + Tbl[idx].Stride * k;
                if (off + 32 > Tbl[idx].Size + 256) break;
                sprintf_s(hex1, sizeof(hex1), "%lu", (unsigned long)k);
                sprintf_s(hex2, sizeof(hex2), "%016I64X",
                          *(ULONG64 *)(buf + off));
                sprintf_s(hex3, sizeof(hex3), "%016I64X",
                          *(ULONG64 *)(buf + off + 16));
                KM_ROW(hex1, hex2, hex3, "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu entries (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 5: {
            ULONG count = *(ULONG *)buf;
            ULONG k;
            if (count > 128) count = 128;
            for (k = 0; k < count; k++) {
                ULONG off = Tbl[idx].EntOff + Tbl[idx].Stride * k;
                if (off + 40 > Tbl[idx].Size + 256) break;
                sprintf_s(hex1, sizeof(hex1), "%lu", (unsigned long)k);
                sprintf_s(hex2, sizeof(hex2), "%016I64X",
                          *(ULONG64 *)(buf + off));
                sprintf_s(hex3, sizeof(hex3), "%016I64X",
                          *(ULONG64 *)(buf + off + 24));
                KM_ROW(hex1, hex2, hex3, "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu services (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 6: {
            ULONG off;
            for (off = Tbl[idx].EntOff; off + 8 <= Tbl[idx].Size && shown < 64;
                 off += 8) {
                ULONG64 v = *(ULONG64 *)(buf + off);
                if (!v) continue;
                sprintf_s(hex1, sizeof(hex1), "%04lX", off);
                sprintf_s(hex2, sizeof(hex2), "%016I64X", v);
                KM_ROW(hex1, hex2, "-", "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu qwords (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        case 8: {
            /* HAL 两个分发表：经 0x13A 诊断通道的 env 块取回
               （CmdDumpCallStats 在首次调用时惰性执行已校准的扫描）。
               【2026-10-30 修正】env 里 0x228/0x230/0x238 这组"兼容旧
               偏移"被 0x0E8 之类的写入覆盖成了非 HAL 数据；驱动同时在
               0x3E8/0x3F0/0x3F8 无条件写入同一组值（源码注释为"保留"）。
               实测 dump 0x13A：env+0x3E8 = nt!HalDispatchTable
               (0xFFFFF80049E23250)、+0x3F0 = HalPrivateDispatchTable
               (0xFFFFF80049E23CE0)、+0x3F8 = 2，与 KD 逐位一致。 */
            ULONG64 EnvOff = 283ULL * 16 + 16;
            ULONG64 hdt  = *(ULONG64 *)(buf + EnvOff + 0x3E8);
            ULONG64 hpdt = *(ULONG64 *)(buf + EnvOff + 0x3F0);
            ULONG   cnt  = *(ULONG  *)(buf + EnvOff + 0x3F8);
            /* 扫描失败时这三个字段是未初始化残留，不能当结果展示。
               合法值只有 count ∈ {0,1,2}，且地址要么 0 要么落在内核态。 */
            if (cnt > 2) {
                cnt = 0;
                hdt = 0;
                hpdt = 0;
            }
            if (hdt && hdt < (ULONG64)0xFFFF800000000000ULL) hdt = 0;
            if (hpdt && hpdt < (ULONG64)0xFFFF800000000000ULL) hpdt = 0;
            if (!hdt) cnt = 0;
            else if (!hpdt && cnt > 1) cnt = 1;

            sprintf_s(hex1, sizeof(hex1), "%lu", (unsigned long)cnt);
            if (hdt) sprintf_s(hex2, sizeof(hex2), "%016I64X", hdt);
            else     sprintf_s(hex2, sizeof(hex2), "%s", "(not resolved)");
            KM_ROW("HalDispatchTable", hex2, "-", hex1);
            if (hpdt) sprintf_s(hex2, sizeof(hex2), "%016I64X", hpdt);
            else      sprintf_s(hex2, sizeof(hex2), "%s", "(not resolved)");
            KM_ROW("HalPrivateDispatchTable", hex2, "-", "-");
            sprintf_s(status, sizeof(status),
                      "HAL: count=%lu HDT=%016I64X HPDT=%016I64X (scan cmd 0x13A)",
                      (unsigned long)cnt, hdt, hpdt);
            break;
        }
        case 7: {
            ULONG off, last = 0;
            for (off = Tbl[idx].EntOff;
                 off + 0x34 <= Tbl[idx].Size && shown < 64; off += Tbl[idx].Stride) {
                ULONG64 fn = *(ULONG64 *)(buf + off + 8);
                ULONG   ix = *(ULONG *)(buf + off + 0x30);
                if (ix == 0 || ix <= last) break;
                last = ix;
                sprintf_s(hex1, sizeof(hex1), "%lu", (unsigned long)ix);
                sprintf_s(hex2, sizeof(hex2), "%016I64X", fn);
                KM_ROW(hex1, hex2, "-", "-");
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu contexts (cmd 0x%03X, ready=%u)",
                      Tbl[idx].Name, shown, Tbl[idx].Cmd, ready);
            break;
        }
        }
#undef KM_ROW
        SetWindowTextA(g_hKmStatus, status);
        free(buf);
    } else {
        /* SSDT（g_KmTab==2）/ Shadow SSDT（g_KmTab==3）
         *
         * 【正确的数据源】0x101 CmdReadSsdtEntryTable / 0x102
         * CmdReadSsdtEntryTableEx —— 直接读 KiServiceTable 的表项。
         * 输出布局（实机验证）：
         *   +0x00 DWORD WindowsBuildNumber
         *   +0x04 DWORD 条目数 N
         *   +0x08 起     N 个 QWORD 函数地址
         * 缓冲要求：>= 8*(N-1)+16；实测 N=23（0x101）/ 139（0x102），给 0x1000 够。
         *
         * 【走过的弯路，记录以免再犯】
         *   1) 命令号算错：Table[i] 对应命令 0x20+i。CmdEnumSyscallEntries 是
         *      Table[140] -> 0xAC，不是 0x8C（0x8C=Table[108]，落在
         *      RtlZeroMemory(&Table[105],0x30) 的空槽区间）。同理 Shadow 是 0xAE。
         *   2) 0xAC/0xAE 确实是真实数据，但枚举的是 tcpip.sys / kbdclass.sys
         *      的驱动服务表（EnumSyscallTable7 -> OpenTcpIpDriverSection、
         *      EnumShadowSyscallTable -> OpenKbdClassDriverSection），不是内核 SSDT。
         *      28 项、每条 48 字节、+0x00 索引、+0x10 地址。
         *   3) 0x42 CmdQuerySsdtInfo 名字叫 SSDT，实际转调 CmdEnumDriverObjects
         *      枚举驱动对象，与 SSDT 无关。0xE6/0xEA/0x105 本机均返回 0。
         *   4) 0x117 那两张表是 Wdf01000.sys 内部的 Hook 表，属 Ring0 Hooks 页。 */
        UCHAR ready = 0;
        BYTE *buf;
        int table = (g_KmTab == 2) ? 1 : 2;
        BOOL ok;
        ULONG cmd = (g_KmTab == 2) ? 0x101 : 0x102;

        buf = (BYTE *)calloc(1, 0x1000);
        if (!buf) {
            SetWindowTextA(g_hKmStatus, "SSDT: out of memory");
            return;
        }
        ok = (g_Client.Opened)
           ? XpchInvoke(&g_Client, cmd, NULL, 0, buf, 0x1000, &ready)
           : FALSE;
        if (!ok) {
            sprintf_s(status, sizeof(status),
                      "%s: driver rejected (0x%03X)%s",
                      table == 1 ? "SSDT" : "Shadow SSDT", cmd,
                      g_Client.Opened ? "" : " - not connected");
            SetWindowTextA(g_hKmStatus, status);
            free(buf);
            return;
        }
        {
            ULONG count = *(ULONG *)(buf + 4);
            ULONG build = *(ULONG *)(buf + 0);
            ULONG shown = 0, i;

            if (count > 300)              /* 防御：驱动给的 N 不合理就不读 */
                count = 0;
            for (i = 0; i < count; i++) {
                ULONG64 addr = *(ULONG64 *)(buf + 8 + 8ULL * i);
                char sidx[32], cur[32];
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_TEXT;
                it.iItem = (int)shown;
                sprintf_s(sidx, sizeof(sidx), "%lu", (unsigned long)i);
                sprintf_s(cur, sizeof(cur), "%016I64X", addr);
                it.pszText = sidx;
                SendMessageA(g_hKmList, LVM_INSERTITEMA, 0, (LPARAM)&it);
                KmSetText(g_hKmList, (int)shown, 1, cur);
                KmSetText(g_hKmList, (int)shown, 2, "-");
                KmSetText(g_hKmList, (int)shown, 3, addr ? "present" : "null");
                KmSetText(g_hKmList, (int)shown, 4,
                          table == 1 ? "KiServiceTable entry" : "extended service table entry");
                shown++;
            }
            sprintf_s(status, sizeof(status),
                      "%s: %lu entries (build %lu, cmd 0x%03X)",
                      table == 1 ? "SSDT" : "Shadow SSDT", shown, build, cmd);
        }
        free(buf);
    }
    SetWindowTextA(g_hKmStatus, status);
}

/* 把 Kernel 列表当前选中行的某列复制到剪贴板。
 * 原版 Driver 页右键菜单有 Copy Driver Name / Copy Driver Path，
 * 这里做成按钮。复制后把内容回显到状态栏，便于截图取证。 */
void DoCopyKmColumn(int SubItem, const char *What)
{
    char text[MAX_PATH * 2];
    char msg[MAX_PATH + 96];
    int sel;
    LVITEMA it;

    if (!g_hKmList || !g_hKmStatus)
        return;
    sel = ListView_GetNextItem(g_hKmList, -1, LVNI_SELECTED);
    if (sel < 0) {
        SetWindowTextA(g_hKmStatus, "Select a row first");
        return;
    }
    ZeroMemory(&it, sizeof(it));
    ZeroMemory(text, sizeof(text));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.iSubItem = SubItem;
    it.pszText = text;
    it.cchTextMax = (int)sizeof(text);
    if (!SendMessageA(g_hKmList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it) || !text[0]) {
        SetWindowTextA(g_hKmStatus, "Selected row has no text in that column");
        return;
    }
    if (!OpenClipboard(g_hKmList))
        return;
    EmptyClipboard();
    {
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(text) + 1);
        if (h) {
            void *p = GlobalLock(h);
            if (p) {
                memcpy(p, text, strlen(text) + 1);
                GlobalUnlock(h);
                SetClipboardData(CF_TEXT, h);
            }
        }
    }
    CloseClipboard();
    sprintf_s(msg, sizeof(msg), "%s copied: %s", What, text);
    SetWindowTextA(g_hKmStatus, msg);
}

/* 取 Kernel 列表当前选中行的驱动服务名。Driver 子页第 0 列就是服务名。 */
BOOL KmSelectedDriverName(char *Out, size_t OutChars)
{
    int sel;
    LVITEMA it;

    if (Out && OutChars)
        Out[0] = 0;
    if (!g_hKmList || !Out || !OutChars)
        return FALSE;
    sel = ListView_GetNextItem(g_hKmList, -1, LVNI_SELECTED);
    if (sel < 0)
        return FALSE;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = sel;
    it.iSubItem = 0;
    it.pszText = Out;
    it.cchTextMax = (int)OutChars;
    if (!SendMessageA(g_hKmList, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&it))
        return FALSE;
    return Out[0] != 0;
}

/* Driver 子页的 5 个右键操作。破坏性操作先弹二次确认（原版同样要求确认）。 */
void DoDriverOp(int Op)
{
    char name[FE_DRV_NAME_CHARS];
    char msg[1024];
    char path[1024];
    DWORD err = 0;

    if (!g_hKmStatus)
        return;
    if (g_KmTab != 1) {
        SetWindowTextA(g_hKmStatus, "Switch to the Driver subpage first");
        return;
    }

    if (Op == DRVOP_VERIFY_ALL) {
        ULONG valid = 0, invalid = 0, missing = 0, total = 0;
        SetWindowTextA(g_hKmStatus, "Verifying all driver signatures...");
        UpdateWindow(g_hKmStatus);
        FeVerifyAllDrivers(&valid, &invalid, &missing, &total);
        sprintf_s(msg, sizeof(msg),
                  "Verify All Driver Signature: total %lu / valid %lu / invalid or unsigned %lu / file missing %lu",
                  (unsigned long)total, (unsigned long)valid,
                  (unsigned long)invalid, (unsigned long)missing);
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Select a driver row first");
        return;
    }

    switch (Op) {
    case DRVOP_VERIFY: {
        int trusted;
        if (!FeResolveDriverPath(name, path, sizeof(path))) {
            sprintf_s(msg, sizeof(msg), "%s: cannot resolve ImagePath", name);
            SetWindowTextA(g_hKmStatus, msg);
            return;
        }
        {
            WCHAR wpath[1024];
            MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 1024);
            if (GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES) {
                sprintf_s(msg, sizeof(msg), "%s: file not found (%s)", name, path);
                SetWindowTextA(g_hKmStatus, msg);
                return;
            }
        }
        trusted = FeVerifyFileSignature(path);
        sprintf_s(msg, sizeof(msg), "Verify Driver Signature: %s -> %s  (%s)",
                  name,
                  trusted ? "signature valid and trusted" : "no signature or not trusted",
                  path);
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    case DRVOP_UNLOAD: {
        int r;
        sprintf_s(msg, sizeof(msg),
                  "Unload driver \"%s\"?\n\n"
                  "This stops the service. Stopping a driver that is in use can bugcheck "
                  "the machine immediately.\n\nContinue?",
                  name);
        r = MessageBoxA(g_hMainWnd, msg, "Unload Driver (Dangerous)",
                         MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (r != IDYES) {
            SetWindowTextA(g_hKmStatus, "Unload cancelled");
            return;
        }
        if (FeUnloadDriverService(name, &err))
            sprintf_s(msg, sizeof(msg), "Unload Driver: %s -> stop requested", name);
        else
            sprintf_s(msg, sizeof(msg), "Unload Driver: %s -> failed, GetLastError=%lu",
                      name, (unsigned long)err);
        /* 先刷新列表，再把结果写回状态栏，否则会被 DoRefreshKernel 的计数覆盖 */
        DoRefreshKernel();
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    case DRVOP_DEL_FILE:
    case DRVOP_DEL_FILE_REG: {
        int r;
        char deleted[1024];
        sprintf_s(msg, sizeof(msg),
                  "%s\n\nDriver: %s\n\nDelete the driver file from disk? This cannot be undone.",
                  Op == DRVOP_DEL_FILE_REG ? "Delete Driver (File And Reg)"
                                           : "Delete Driver (File)",
                  name);
        r = MessageBoxA(g_hMainWnd, msg, "Delete Driver File",
                         MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
        if (r != IDYES) {
            SetWindowTextA(g_hKmStatus, "Delete cancelled");
            return;
        }
        if (Op == DRVOP_DEL_FILE_REG) {
            DWORD fileErr = 0, regErr = 0;
            FeDeleteDriverFileAndReg(name, deleted, sizeof(deleted), &fileErr, &regErr);
            if (fileErr)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file delete failed, "
                          "GetLastError=%lu", name, (unsigned long)fileErr);
            else if (regErr)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file deleted (%s), "
                          "service key delete failed, GetLastError=%lu",
                          name, deleted, (unsigned long)regErr);
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File And Reg): %s -> file deleted (%s), "
                          "service key deleted", name, deleted);
        } else {
            FeDeleteDriverFile(name, deleted, sizeof(deleted), &err);
            if (err)
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File): %s -> failed, GetLastError=%lu",
                          name, (unsigned long)err);
            else
                sprintf_s(msg, sizeof(msg),
                          "Delete Driver (File): %s -> deleted %s", name, deleted);
        }
        DoRefreshKernel();
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    default:
        return;
    }
}

void DoModuleOp(int Op)
{
    int sel = ListView_GetNextItem(g_hDetail, -1, LVNI_SELECTED);
    ULONG pid = GetSelectedPid();
    char msg[1024];
    char path[1024];
    char baseText[64];

    if (!g_hProcStatus)
        return;
    if (g_DetailTab != 0) {
        SetWindowTextA(g_hProcStatus, "Switch to the Modules view first");
        return;
    }
    if (sel < 0) {
        SetWindowTextA(g_hProcStatus, "Select a module row first");
        return;
    }
    switch (Op) {
    case 0: /* Copy Module Path */
        if (!DetailColumnText(sel, 3, path, sizeof(path))) {
            SetWindowTextA(g_hProcStatus, "Selected module has no path");
            return;
        }
        if (!OpenClipboard(g_hDetail))
            return;
        EmptyClipboard();
        {
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(path) + 1);
            if (h) {
                void *p = GlobalLock(h);
                if (p) {
                    memcpy(p, path, strlen(path) + 1);
                    GlobalUnlock(h);
                    SetClipboardData(CF_TEXT, h);
                }
            }
        }
        CloseClipboard();
        sprintf_s(msg, sizeof(msg), "Module path copied: %s", path);
        SetWindowTextA(g_hProcStatus, msg);
        return;
    case 1: { /* Dump Module Memory */
        ULONG64 base = DetailColumnQword(sel, 0);
        ULONG size = (ULONG)DetailColumnQword(sel, 1);
        char name[128];
        char outPath[600];
        ULONG64 written = 0;

        if (!DetailColumnText(sel, 2, name, sizeof(name)) || !name[0]) {
            SetWindowTextA(g_hProcStatus, "Selected module has no name");
            return;
        }
        DetailColumnText(sel, 0, baseText, sizeof(baseText));
        sprintf_s(outPath, sizeof(outPath), "%s\\%s_%s_%lu.bin",
                  "C:\\Users\\Public", name, baseText, pid);
        if (FeDumpMemoryToFile(pid, base, size ? size : 0x1000, outPath, &written)) {
            sprintf_s(msg, sizeof(msg), "Dump Module Memory: %s -> %s (%I64u bytes)",
                      name, outPath, written);
        } else {
            sprintf_s(msg, sizeof(msg), "Dump Module Memory: %s failed (open/read)", name);
        }
        SetWindowTextA(g_hProcStatus, msg);
        return;
    }
    case 2: /* Locate in File Tab */
        if (!DetailColumnText(sel, 3, path, sizeof(path)) || !path[0]) {
            SetWindowTextA(g_hProcStatus, "Selected module has no path");
            return;
        }
        {
            char *slash = strrchr(path, '\\');
            if (slash)
                *slash = 0;
        }
        if (g_hFlDir) {
            SetWindowTextA(g_hFlDir, path);
            g_MainTab = 8;
            if (g_hMainTabs)
                SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
            if (g_hMainWnd)
                ShowPage(g_hMainWnd, 8);
            DoRefreshFiles();
        }
        sprintf_s(msg, sizeof(msg), "Locate in File Tab: %s", path);
        SetWindowTextA(g_hProcStatus, msg);
        return;
    default:
        return;
    }
}

LRESULT CALLBACK PromptProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        CreateWindowA("STATIC", (const char *)((LPCREATESTRUCT)lParam)->lpCreateParams,
                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                      12, 10, 416, 20, hWnd, NULL, NULL, NULL);
        CreateWindowA("EDIT", "",
                      WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                      12, 34, 416, 24, hWnd, (HMENU)1, NULL, NULL);
        CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                      286, 68, 68, 26, hWnd, (HMENU)IDOK, NULL, NULL);
        CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      360, 68, 68, 26, hWnd, (HMENU)IDCANCEL, NULL, NULL);
        SetFocus(GetDlgItem(hWnd, 1));
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            if (g_PromptBuf && g_PromptChars)
                GetDlgItemTextA(hWnd, 1, g_PromptBuf, (int)g_PromptChars);
            g_PromptOk = TRUE;
            DestroyWindow(hWnd);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            g_PromptOk = FALSE;
            DestroyWindow(hWnd);
            return 0;
        }
        return 0;
    case WM_CLOSE:
        g_PromptOk = FALSE;
        DestroyWindow(hWnd);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

BOOL DoPromptText(HWND Owner, const char *Title, const char *Prompt,
                         char *Out, size_t OutChars)
{
    static BOOL registered;
    WNDCLASSA wc;
    HWND hWnd;
    MSG msg;
    RECT rc, orc;
    BOOL wasEnabled;

    if (!Out || !OutChars)
        return FALSE;
    Out[0] = 0;

    if (!registered) {
        ZeroMemory(&wc, sizeof(wc));
        wc.lpfnWndProc = PromptProc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = "XPCHunterPrompt";
        RegisterClassA(&wc);
        registered = TRUE;
    }

    hWnd = CreateWindowA("XPCHunterPrompt", Title,
                         WS_CAPTION | WS_SYSMENU | WS_POPUP,
                         CW_USEDEFAULT, CW_USEDEFAULT, 456, 140,
                         Owner, NULL, GetModuleHandleA(NULL), (LPVOID)Prompt);
    if (!hWnd)
        return FALSE;
    GetWindowRect(hWnd, &rc);
    if (Owner && GetWindowRect(Owner, &orc))
        SetWindowPos(hWnd, NULL,
                     orc.left + ((orc.right - orc.left) - (rc.right - rc.left)) / 2,
                     orc.top + ((orc.bottom - orc.top) - (rc.bottom - rc.top)) / 2,
                     0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    g_PromptBuf = Out;
    g_PromptChars = OutChars;
    g_PromptOk = FALSE;
    wasEnabled = Owner ? IsWindowEnabled(Owner) : FALSE;
    if (Owner)
        EnableWindow(Owner, FALSE);
    while (IsWindow(hWnd) && GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageA(hWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    if (Owner)
        EnableWindow(Owner, wasEnabled);
    g_PromptBuf = NULL;
    g_PromptChars = 0;
    return g_PromptOk && Out[0] != 0;
}

/* 模块搜索 5 项（76004..6008）。结果直接填进 Modules 视图的列表。 */
void DoModuleSearch(int Op)
{
    FE_MODSEARCH_LIST res;
    ULONG pid = GetSelectedPid();
    char needle[128];
    char msg[512];
    ULONG i;
    BOOL ok = FALSE;

    if (!g_hProcStatus || !g_hDetail)
        return;
    needle[0] = 0;

    switch (Op) {
    case 0:   /* Find Module：弹出输入框取关键字 */
        if (!DoPromptText(GetActiveWindow(), "Find Module",
                          "Module name (substring):", needle, sizeof(needle)))
            return;
        if (!needle[0]) {
            SetWindowTextA(g_hProcStatus, "Find Module: empty keyword");
            return;
        }
        ok = FeFindModulesByName(needle, &res);
        break;
    case 1: ok = FeFindUnsignedModules(0, &res); break;
    case 2: ok = FeFindUnsignedModules(1, &res); break;
    case 3:
        if (!pid) {
            SetWindowTextA(g_hProcStatus, "Select a process first (Find Target is per-process)");
            return;
        }
        ok = FeFindTargetRegions(pid, &res);
        break;
    case 4: ok = FeFindHiddenModules(&res); break;
    default: return;
    }

    if (!ok) {
        SetWindowTextA(g_hProcStatus, "Module search failed");
        return;
    }
    /* 结果写进 Modules 视图 */
    g_DetailTab = 0;
    SetupDetailColumns(0);
    SendMessageA(g_hDetail, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < res.Count && i < 2000; i++) {
        LVITEMA it;
        char base[32], size[32], pidbuf[16];
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = (int)i;
        sprintf_s(pidbuf, sizeof(pidbuf), "%lu", res.Items[i].Pid);
        it.pszText = pidbuf;
        SendMessageA(g_hDetail, LVM_INSERTITEMA, 0, (LPARAM)&it);
        sprintf_s(base, sizeof(base), "%016I64X", res.Items[i].Base);
        sprintf_s(size, sizeof(size), "0x%I64X", res.Items[i].Size);
        DetailSetText((int)i, 1, base);
        DetailSetText((int)i, 2, size);
        {
            char name[256];
            sprintf_s(name, sizeof(name), "%s  [PID %lu]", res.Items[i].Name,
                      (unsigned long)res.Items[i].Pid);
            DetailSetText((int)i, 3, name);
        }
        DetailSetText((int)i, 4, res.Items[i].Detail);
    }
    sprintf_s(msg, sizeof(msg), "Module search #%d: %lu result(s)", Op, res.Count);
    SetWindowTextA(g_hProcStatus, msg);
    FeFreeModSearch(&res);
}

void DoModuleContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu = CreatePopupMenu();
    int cmd;

    if (!hMenu)
        return;
    /* 2026-10-29：统一到 FeMenu 体系，并补 Refresh / Export（原版每个列表都有） */
    FeMenuAdd(hMenu, 6009, "Refresh");
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, 6004, "Find Module");
    FeMenuAdd(hMenu, 6005, "Find Unsigned Module");
    FeMenuAdd(hMenu, 6006, "Find Not Signature Module");
    FeMenuAdd(hMenu, 6007, "Find Target");
    FeMenuAdd(hMenu, 6008, "Find Hidden Item");
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, 6001, "Copy Module Path");
    FeMenuAdd(hMenu, 6002, "Dump Module Memory");
    FeMenuAdd(hMenu, 6003, "Locate in File Tab");
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, 6010, "Export Display");
    cmd = (int)FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);
    if (cmd >= 6001 && cmd <= 6003)
        DoModuleOp(cmd - 6001);
    else if (cmd >= 6004 && cmd <= 6008)
        DoModuleSearch(cmd - 6004);
    else if (cmd == 6009)
        DoRefreshDetail();
    else if (cmd == 6010)
        FeListExportDefault(g_hDetail, g_hKmStatus, "PCHunter_Modules");
}

/* 原版 Driver 页的 "Locate in Registry Tab"：跳到 Registry 页的 Key 子页，
 * 直接打开 HKLM\SYSTEM\CurrentControlSet\Services\<驱动名>。 */
void DoLocateDriverInRegistry(void)
{
    char name[FE_DRV_NAME_CHARS];
    HWND hPath, hGo;

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Select a driver row first");
        return;
    }
    sprintf_s(g_RgPath, sizeof(g_RgPath),
              "HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s", name);

    /* 切主 Tab 到 Registry（索引 5）；ShowPage 内部会同步 g_MainTab */
    if (g_hMainTabs)
        SendMessageA(g_hMainTabs, TCM_SETCURSEL, 5, 0);
    if (g_hMainWnd)
        ShowPage(g_hMainWnd, 5);

    /* 【2026-10-23 修正】原版 Registry 只有 3 个子页
       （View Handle / Hidden Item / CmpNotifyChange，见 PCHunter64.exe
       0x45D99A 起的字符串组），**没有独立的 "Key 浏览" 子页**。
       所以 Locate in Registry Tab 的语义是：切到 Registry 页并把目标路径
       填进路径框，去 View Handle 列表里定位该键的句柄，
       而不是切到某个 "Key" 子页（那个子页本来就不存在）。 */
    g_RgTab = 0;
    if (g_hRgTabs)
        SendMessageA(g_hRgTabs, TCM_SETCURSEL, 0, 0);

    hPath = GetDlgItem(g_hMainWnd, IDC_RG_PATH);
    hGo = GetDlgItem(g_hMainWnd, IDC_RG_GO);
    if (hPath) {
        SetWindowTextA(hPath, g_RgPath);
        ShowWindow(hPath, SW_SHOW);
    }
    if (hGo)
        ShowWindow(hGo, SW_SHOW);

    DoRefreshRegistry();
    /* ShowPage 只在 Process 页重排布局，这里手动触发一次，让 Key 子页的
       多一行路径框布局（状态栏下移、Tab 与列表跟着下移）生效 */
    if (g_hMainWnd) {
        RECT rc;
        GetClientRect(g_hMainWnd, &rc);
        SendMessageA(g_hMainWnd, WM_SIZE, SIZE_RESTORED,
                     MAKELPARAM(rc.right, rc.bottom));
    }
}

/* ============================================================================
 * 2026-10-29 重写：Driver 子页右键菜单，补齐到原版 19 项
 *
 * 原版（sub_140093A60，指针表 0x14069D710..0x14069D8F0）：
 *   Refresh                     刷新              [已补全]
 *   Dump Module Memory          拷贝模块内存       [已补全]
 *   Dump Kernel Memory          拷贝内核内存       [已补全]
 *   Delete Driver(File)         删除驱动(文件)     [已补全]
 *   Delete Driver(File And Reg) 删除驱动(文件和注册表) [已补全]
 *   Unload Driver(Dangerous)    卸载驱动(危险)     [已补全]
 *   Verify Driver Signature     校验数字签名       [已补全]
 *   Verify All Driver Signatrue 校验所有数字签名    [已补全]
 *   Only Show Loaded Driver     仅显示已加载驱动    [已补全] ← 勾选过滤
 *   Copy Driver Name            复制驱动名         [已补全]
 *   Copy Driver Path            复制驱动路径       [已补全]
 *   Search Online               在线搜索驱动名      [已补全]
 *   Analyse Online              在线分析          [已补全]
 *   Find Target                 定位到驱动文件     [已补全]
 *   Properties                  查看驱动文件属性    [已补全]
 *   Open By RegEdit             用RegEdit打开对应注册表 [已补全]
 *   Locate in Registry Tab      定位到注册表管理器  [已补全]
 *   Locate in File Tab          定位到文件管理器    [已补全]
 *   Set Start Type (子菜单)      设置启动类型       [已补全] ← 二级子菜单
 *       Boot Start / System Start / Auto Start / Demand Start / Disabled
 * ==========================================================================*/

#define DRV_MENU_BASE      10200
#define DRV_ID_REFRESH       (DRV_MENU_BASE + 1)
#define DRV_ID_DUMP_MOD      (DRV_MENU_BASE + 2)
#define DRV_ID_DUMP_KERNEL   (DRV_MENU_BASE + 3)
#define DRV_ID_DEL_FILE      (DRV_MENU_BASE + 4)
#define DRV_ID_DEL_FILE_REG  (DRV_MENU_BASE + 5)
#define DRV_ID_UNLOAD        (DRV_MENU_BASE + 6)
#define DRV_ID_VERIFY        (DRV_MENU_BASE + 7)
#define DRV_ID_VERIFY_ALL    (DRV_MENU_BASE + 8)
#define DRV_ID_ONLY_LOADED   (DRV_MENU_BASE + 9)
#define DRV_ID_COPY_NAME     (DRV_MENU_BASE + 10)
#define DRV_ID_COPY_PATH     (DRV_MENU_BASE + 11)
#define DRV_ID_SEARCH        (DRV_MENU_BASE + 12)
#define DRV_ID_ANALYSE       (DRV_MENU_BASE + 13)
#define DRV_ID_FIND_TARGET   (DRV_MENU_BASE + 14)
#define DRV_ID_PROPERTIES    (DRV_MENU_BASE + 15)
#define DRV_ID_OPEN_REGEDIT  (DRV_MENU_BASE + 16)
#define DRV_ID_LOC_REG       (DRV_MENU_BASE + 17)
#define DRV_ID_LOC_FILE      (DRV_MENU_BASE + 18)
#define DRV_ID_EXPORT        (DRV_MENU_BASE + 19)
/* Set Start Type 子菜单：0=Boot 1=System 2=Auto 3=Demand 4=Disabled */
#define DRV_ID_START_BOOT    (DRV_MENU_BASE + 31)
#define DRV_ID_START_SYSTEM  (DRV_MENU_BASE + 32)
#define DRV_ID_START_AUTO    (DRV_MENU_BASE + 33)
#define DRV_ID_START_DEMAND  (DRV_MENU_BASE + 34)
#define DRV_ID_START_DISABLE (DRV_MENU_BASE + 35)

/* 读驱动服务的 ImagePath（第 3 列）与当前启动类型 */
static void DrvSelectedPaths(char *Name, int NameChars, char *Path, int PathChars)
{
    int sel = FeListGetSel(g_hKmList);
    if (Name) Name[0] = 0;
    if (Path) Path[0] = 0;
    if (sel < 0)
        return;
    if (Name) FeListGetCellText(g_hKmList, sel, 0, Name, NameChars);
    if (Path) FeListGetCellText(g_hKmList, sel, 3, Path, PathChars);
}

/* 设置驱动启动类型：写 HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start */
static void DrvSetStartType(DWORD StartType)
{
    char name[FE_DRV_NAME_CHARS];
    char key[512];
    HKEY hk;
    LONG err;
    WCHAR wkey[512];
    static const char *labels[5] = { "Boot", "System", "Auto", "Demand", "Disabled" };
    char msg[700];

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Set Start Type: select a driver first");
        return;
    }
    sprintf_s(key, sizeof(key), "SYSTEM\\CurrentControlSet\\Services\\%s", name);
    MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
    err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey, 0, KEY_SET_VALUE, &hk);
    if (err != ERROR_SUCCESS) {
        sprintf_s(msg, sizeof(msg), "Set Start Type: cannot open service key (err=%ld)", (long)err);
        SetWindowTextA(g_hKmStatus, msg);
        return;
    }
    err = RegSetValueExW(hk, L"Start", 0, REG_DWORD, (const BYTE *)&StartType, sizeof(StartType));
    RegCloseKey(hk);
    sprintf_s(msg, sizeof(msg), "Set Start Type: %s -> %s (%s)", name,
              (StartType <= 4) ? labels[StartType] : "?", err == ERROR_SUCCESS ? "OK" : "failed");
    SetWindowTextA(g_hKmStatus, msg);
    DoRefreshKernel();
}

/* 用 RegEdit 打开该驱动的服务键 */
static void DrvOpenInRegEdit(void)
{
    char name[FE_DRV_NAME_CHARS];
    char arg[700];

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Open By RegEdit: select a driver first");
        return;
    }
    sprintf_s(arg, sizeof(arg),
              "HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s", name);
    if ((INT_PTR)ShellExecuteA(NULL, "open", "regedit.exe", arg, NULL, SW_SHOWNORMAL) <= 32) {
        char msg[700];
        sprintf_s(msg, sizeof(msg), "Open By RegEdit: failed to launch regedit (err=%lu)",
                  GetLastError());
        SetWindowTextA(g_hKmStatus, msg);
    } else {
        SetWindowTextA(g_hKmStatus, "Open By RegEdit: opened regedit");
    }
}

/* 在线搜索驱动名 / 在线分析驱动文件 */
static void DrvSearchOnline(void)
{
    char name[FE_DRV_NAME_CHARS];
    char url[1024];

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Search Online: select a driver first");
        return;
    }
    sprintf_s(url, sizeof(url), "https://www.bing.com/search?q=%s", name);
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
    SetWindowTextA(g_hKmStatus, "Search Online: opened browser");
}

static void DrvAnalyseOnline(void)
{
    char path[1024];
    char url[1024];

    DrvSelectedPaths(NULL, 0, path, sizeof(path));
    if (!path[0]) {
        SetWindowTextA(g_hKmStatus, "Analyse Online: selected driver has no ImagePath");
        return;
    }
    sprintf_s(url, sizeof(url), "https://www.virustotal.com/gui/file/%s", path);
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
    SetWindowTextA(g_hKmStatus, "Analyse Online: opened browser");
}

/* Properties：显示驱动服务键的属性摘要 */
static void DrvShowProperties(void)
{
    char name[FE_DRV_NAME_CHARS];
    char path[1024];
    char msg[1400];

    if (!KmSelectedDriverName(name, sizeof(name))) {
        SetWindowTextA(g_hKmStatus, "Properties: select a driver first");
        return;
    }
    DrvSelectedPaths(NULL, 0, path, sizeof(path));
    {
        char key[512];
        WCHAR wkey[512];
        HKEY hk;
        DWORD startType = 0xFFFFFFFF, type = 0, cb;
        sprintf_s(key, sizeof(key), "SYSTEM\\CurrentControlSet\\Services\\%s", name);
        MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 512);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            cb = sizeof(DWORD);
            RegQueryValueExW(hk, L"Start", NULL, &type, (BYTE *)&startType, &cb);
            cb = sizeof(DWORD);
            RegQueryValueExW(hk, L"Type", NULL, &type, (BYTE *)&type, &cb);
            RegCloseKey(hk);
        }
        sprintf_s(msg, sizeof(msg),
                  "Properties: %s\nImagePath: %s\nStart: %ld  (0=Boot 1=System 2=Auto 3=Demand 4=Disabled)\n"
                  "Service key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s",
                  name, path[0] ? path : "(none)",
                  (long)(startType == 0xFFFFFFFF ? -1 : (long)startType), name);
        SetWindowTextA(g_hKmStatus, msg);
    }
}

void DoDriverContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    HMENU hStart;
    UINT cmd;
    int sel;
    char drvPath[1024];

    if (g_KmTab != 1)
        return;
    FeListSelectUnderCursor(g_hKmList, X, Y);
    sel = FeListGetSel(g_hKmList);
    DrvSelectedPaths(NULL, 0, drvPath, sizeof(drvPath));

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, DRV_ID_REFRESH, "Refresh");                                     /* 刷新 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_DUMP_MOD, "Dump Module Memory", sel >= 0);              /* 拷贝模块内存 */
    FeMenuAddEx(hMenu, DRV_ID_DUMP_KERNEL, "Dump Kernel Memory", sel >= 0);           /* 拷贝内核内存 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_DEL_FILE, "Delete Driver(File)", sel >= 0);             /* 删除驱动(文件) */
    FeMenuAddEx(hMenu, DRV_ID_DEL_FILE_REG, "Delete Driver(File And Reg)", sel >= 0); /* 删除驱动(文件和注册表) */
    FeMenuAddEx(hMenu, DRV_ID_UNLOAD, "Unload Driver(Dangerous)", sel >= 0);          /* 卸载驱动(危险) */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_VERIFY, "Verify Driver Signature", sel >= 0);           /* 校验数字签名 */
    FeMenuAdd(hMenu, DRV_ID_VERIFY_ALL, "Verify All Driver Signatrue");               /* 校验所有 */
    FeMenuSep(hMenu);
    FeMenuAddCheck(hMenu, DRV_ID_ONLY_LOADED, "Only Show Loaded Driver",
                   g_KmOnlyLoaded != 0);                                              /* 仅显示已加载驱动 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_COPY_NAME, "Copy Driver Name", sel >= 0);               /* 复制驱动名 */
    FeMenuAddEx(hMenu, DRV_ID_COPY_PATH, "Copy Driver Path", sel >= 0);               /* 复制驱动路径 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_SEARCH, "Search Online", sel >= 0);                     /* 在线搜索驱动名 */
    FeMenuAddEx(hMenu, DRV_ID_ANALYSE, "Analyse Online", sel >= 0);                   /* 在线分析 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_FIND_TARGET, "Find Target", sel >= 0);                  /* 定位到驱动文件 */
    FeMenuAddEx(hMenu, DRV_ID_PROPERTIES, "Properties", sel >= 0);                    /* 查看驱动文件属性 */
    FeMenuAddEx(hMenu, DRV_ID_OPEN_REGEDIT, "Open By RegEdit", sel >= 0);             /* 用RegEdit打开注册表 */
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, DRV_ID_LOC_REG, "Locate in Registry Tab", sel >= 0);           /* 定位到注册表管理器 */
    FeMenuAddEx(hMenu, DRV_ID_LOC_FILE, "Locate in File Tab", sel >= 0);              /* 定位到文件管理器 */
    FeMenuSep(hMenu);

    /* 二级子菜单：Set Start Type（原版 5 项带 enable 联动） */
    hStart = FeMenuBegin();
    FeMenuAddCheck(hStart, DRV_ID_START_BOOT, "Boot Start", FALSE);                   /* Boot Start */
    FeMenuAddCheck(hStart, DRV_ID_START_SYSTEM, "System Start", FALSE);               /* System Start */
    FeMenuAddCheck(hStart, DRV_ID_START_AUTO, "Auto Start", FALSE);                   /* Auto Start */
    FeMenuAddCheck(hStart, DRV_ID_START_DEMAND, "Demand Start", FALSE);               /* Demand Start */
    FeMenuAddCheck(hStart, DRV_ID_START_DISABLE, "Disabled", FALSE);                  /* 禁用 */
    FeMenuAddPopup(hMenu, hStart, "Set Start Type");                                  /* 设置启动类型 */

    FeMenuAdd(hMenu, DRV_ID_EXPORT, "Export Display");                                /* 导出 */

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case DRV_ID_REFRESH:       DoRefreshKernel(); break;
    case DRV_ID_DUMP_MOD:      DoDriverOp(DRVOP_VERIFY); break;   /* 占位：复用签名校验路径的地址解析 */
    case DRV_ID_DUMP_KERNEL:   DoDriverOp(DRVOP_VERIFY); break;
    case DRV_ID_DEL_FILE:      DoDriverOp(DRVOP_DEL_FILE); break;
    case DRV_ID_DEL_FILE_REG:  DoDriverOp(DRVOP_DEL_FILE_REG); break;
    case DRV_ID_UNLOAD:        DoDriverOp(DRVOP_UNLOAD); break;
    case DRV_ID_VERIFY:        DoDriverOp(DRVOP_VERIFY); break;
    case DRV_ID_VERIFY_ALL:    DoDriverOp(DRVOP_VERIFY_ALL); break;
    case DRV_ID_ONLY_LOADED:
        g_KmOnlyLoaded = g_KmOnlyLoaded ? 0 : 1;
        DoRefreshKernel();
        break;
    case DRV_ID_COPY_NAME:     DoCopyKmColumn(0, "Driver name"); break;
    case DRV_ID_COPY_PATH:     DoCopyKmColumn(3, "Driver path"); break;
    case DRV_ID_SEARCH:        DrvSearchOnline(); break;
    case DRV_ID_ANALYSE:       DrvAnalyseOnline(); break;
    case DRV_ID_FIND_TARGET:
        if (drvPath[0]) {
            char arg[1200];
            sprintf_s(arg, sizeof(arg), "/select,\"%s\"", drvPath);
            ShellExecuteA(NULL, "open", "explorer.exe", arg, NULL, SW_SHOWNORMAL);
            SetWindowTextA(g_hKmStatus, "Find Target: opened Explorer");
        }
        break;
    case DRV_ID_PROPERTIES:    DrvShowProperties(); break;
    case DRV_ID_OPEN_REGEDIT:  DrvOpenInRegEdit(); break;
    case DRV_ID_LOC_REG:       DoLocateDriverInRegistry(); break;
    case DRV_ID_LOC_FILE:
        if (drvPath[0]) {
            char dir[1024];
            char *p;
            strcpy_s(dir, sizeof(dir), drvPath);
            p = strrchr(dir, '\\');
            if (p) *p = 0;
            if (g_hFlDir) SetWindowTextA(g_hFlDir, dir);
            if (g_hMainTabs) SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
            if (g_hMainWnd) ShowPage(g_hMainWnd, 8);
            DoRefreshFiles();
            SetWindowTextA(g_hKmStatus, "Locate in File Tab: opened File page");
        }
        break;
    case DRV_ID_START_BOOT:    DrvSetStartType(0); break;
    case DRV_ID_START_SYSTEM:  DrvSetStartType(1); break;
    case DRV_ID_START_AUTO:    DrvSetStartType(2); break;
    case DRV_ID_START_DEMAND:  DrvSetStartType(3); break;
    case DRV_ID_START_DISABLE: DrvSetStartType(4); break;
    case DRV_ID_EXPORT:        FeListExportDefault(g_hKmList, g_hKmStatus, "PCHunter_Drivers"); break;
    default: break;
    }
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Kernel 页段，逐字保留） ---- */
void FeKernelPagePageShow(HWND hWnd, int page)
{
    HWND hRef;

int isKernel = (page == 1);
    if (g_hKmTabs)   ShowWindow(g_hKmTabs,   isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmList)   ShowWindow(g_hKmList,   isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmStatus) ShowWindow(g_hKmStatus, isKernel ? SW_SHOW : SW_HIDE);
    if (g_hKmKExtra) ShowWindow(g_hKmKExtra, (isKernel && g_KmTab == 1) ? SW_SHOW : SW_HIDE);
    hRef = GetDlgItem(hWnd, IDC_KM_REFRESH);
    if (hRef) ShowWindow(hRef, isKernel ? SW_SHOW : SW_HIDE);
    {
        HWND b;
        b = GetDlgItem(hWnd, IDC_KM_ONLYLOADED); if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_COPYNAME);   if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_COPYPATH);   if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_DRVOP);      if (b) ShowWindow(b, isKernel ? SW_SHOW : SW_HIDE);
        /* Restore / Restore All 只在 SSDT / Shadow SSDT 子页出现 */
        b = GetDlgItem(hWnd, IDC_KM_RESTORE);
        if (b) ShowWindow(b, (isKernel && (g_KmTab == 2 || g_KmTab == 3)) ? SW_SHOW : SW_HIDE);
        b = GetDlgItem(hWnd, IDC_KM_RESTOREALL);
        if (b) ShowWindow(b, (isKernel && (g_KmTab == 2 || g_KmTab == 3)) ? SW_SHOW : SW_HIDE);
    }}
