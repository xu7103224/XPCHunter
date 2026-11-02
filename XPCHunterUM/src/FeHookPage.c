// ============================================================================
// FeHookPage.c — Hook 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hHkList, g_hHkStatus;
/* 2026-10-29：Only show hooks 勾选状态（原版 "仅显示挂钩函数"） */
BOOL g_HkOnlyHooks = FALSE;
/* 反汇编入口需要按行索引取地址；缓存本次刷新的 Ring0 列表 */
static FE_RING0_HOOK_LIST g_HkR0Cache;
static BOOL g_HkR0Valid = FALSE;
/* 行号 -> Ring0 条目索引（-1 表示该行不是 Ring0 条目） */
#define HK_MAX_ROWS 4096
static int g_HkRowToR0[HK_MAX_ROWS];

/* ---- Ring0 / Ring3 Hooks 页（主 Tab 2 / 3）----
 * Ring3 扫 IAT 越界；Ring0 标 blocked（驱动链缺 6 个函数，见
 * docs/archive/reversing/Hooks页落地_2026-10-21.md）。 */
void HkSetText(HWND h, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(h, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void DoRefreshHooks(void)
{
    LVCOLUMNA c;
    FE_HOOK_LIST list;
    FE_RING0_HOOK_LIST r0;
    char status[420];
    int n = 0;
    ULONG i;
    BOOL r0ok;

    if (!g_hHkList || !g_hHkStatus)
        return;
    if (g_HkR0Valid) {
        FeFreeRing0Hooks(&g_HkR0Cache);
        g_HkR0Valid = FALSE;
    }
    ZeroMemory(g_HkRowToR0, sizeof(g_HkRowToR0));
    ListView_DeleteAllItems(g_hHkList);
    while (ListView_DeleteColumn(g_hHkList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = "Type";    c.cx = 80;  c.iSubItem = 0; ListView_InsertColumn(g_hHkList, 0, &c);
    c.pszText = "Owner";   c.cx = 150; c.iSubItem = 1; ListView_InsertColumn(g_hHkList, 1, &c);
    c.pszText = "IAT/Index"; c.cx = 130; c.iSubItem = 2; ListView_InsertColumn(g_hHkList, 2, &c);
    c.pszText = "Target";  c.cx = 160; c.iSubItem = 3; ListView_InsertColumn(g_hHkList, 3, &c);
    c.pszText = "Note";    c.cx = 420; c.iSubItem = 4; ListView_InsertColumn(g_hHkList, 4, &c);

    /* ---- Ring0：0x117 的两张系统调用表（GT[0x8B7] / GT[0x8BA]）----
     * 每条 = 表内索引 + 当前地址 + 磁盘原始地址 + 原始 16 字节 + 两个改写标志。 */
    r0ok = FeLoadRing0Hooks(&g_Client, &r0);
    if (r0ok) {
        for (i = 0; i < r0.Count; i++) {
            const FE_RING0_HOOK_ENTRY *e = &r0.Items[i];
            char idx[48], tgt[32], note[220];
            /* 2026-10-29 Only show hooks：只列被改写的条目 */
            if (g_HkOnlyHooks && !e->FlagAddr && !e->FlagBytes)
                continue;
            ListView_InsertItem(g_hHkList, NULL);
            if (n < HK_MAX_ROWS) g_HkRowToR0[n] = (int)i;
            HkSetText(g_hHkList, n, 0, "Ring0");
            HkSetText(g_hHkList, n, 1,
                      e->TableIndex == 1 ? "HookTable1 (GT[0x8B7])"
                                         : "HookTable2 (GT[0x8BA])");
            sprintf_s(idx, sizeof(idx), "[%lu]", (unsigned long)e->Index);
            sprintf_s(tgt, sizeof(tgt), "%016I64X", e->Current);
            HkSetText(g_hHkList, n, 2, idx);
            HkSetText(g_hHkList, n, 3, tgt);
            sprintf_s(note, sizeof(note), "%s%s  %s",
                      e->FlagAddr  ? "[ADDR CHANGED] " : "",
                      e->FlagBytes ? "[BYTES PATCHED] " : "",
                      e->Disasm);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
        sprintf_s(status, sizeof(status),
                  "Ring0: build %lu, %lu entries (table1 %lu / table2 %lu), %lu patched | ",
                  r0.Build, r0.Count, r0.Count1, r0.Count2, r0.ModifiedCount);
        /* 保留一份快照供右键反汇编使用（原版 Disassembling current/original entry） */
        g_HkR0Cache = r0;
        g_HkR0Valid = TRUE;
    } else {
        ListView_InsertItem(g_hHkList, NULL);
        HkSetText(g_hHkList, n, 0, "Ring0");
        HkSetText(g_hHkList, n, 1, "(kernel)");
        HkSetText(g_hHkList, n, 2, "-");
        HkSetText(g_hHkList, n, 3, "-");
        HkSetText(g_hHkList, n, 4,
                  g_Client.Opened ? "0x117 returned no entries"
                                  : "not connected: click Connect first");
        n++;
        sprintf_s(status, sizeof(status), "Ring0: no data | ");
    }

    /* ---- Ring3：实扫 ---- */
    if (FeScanRing3Hooks(GetCurrentProcessId(), &list)) {
        for (i = 0; i < list.Count; i++) {
            char a[32], t[32], note[192];
            ListView_InsertItem(g_hHkList, NULL);
            HkSetText(g_hHkList, n, 0, "Ring3");
            HkSetText(g_hHkList, n, 1, list.Items[i].Owner);
            sprintf_s(a, sizeof(a), "%016I64X", list.Items[i].IatAddress);
            sprintf_s(t, sizeof(t), "%016I64X", list.Items[i].Target);
            HkSetText(g_hHkList, n, 2, a);
            HkSetText(g_hHkList, n, 3, t);
            sprintf_s(note, sizeof(note), "%s-->Ring3 Hook  (%s)",
                      list.Items[i].Owner, list.Items[i].TargetModule);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
        {
            char tail[160];
            sprintf_s(tail, sizeof(tail), "Ring3: %lu suspicious IAT entries (pid %lu)",
                      list.Count, GetCurrentProcessId());
            strcat_s(status, sizeof(status), tail);
        }
        FeFreeHooks(&list);
    } else {
        char tail[96];
        sprintf_s(tail, sizeof(tail), "Ring3: scan failed, GetLastError=%lu", GetLastError());
        strcat_s(status, sizeof(status), tail);
    }
    SetWindowTextA(g_hHkStatus, status);
}

/* ---- Ring0 两项恢复操作的点击处理 ----
 * 两者都必须把「没有待恢复项」和「失败」区分开显示：
 * 本机 908 条 Hook 条目全部 clean，0x118 返回 0 是正常结果，
 * 若显示成 FAILED 会误导用户以为自己系统被 hook 了。 */
void DoRestoreOverHooks(void)
{
    FE_HOOK_RESTORE_RESULT r;
    char msg[420];

    if (!g_Client.Opened) {
        SetWindowTextA(g_hHkStatus, "Restore Over. Hooks/Patches: not connected");
        return;
    }
    if (!FeRestoreOverHooks(&g_Client, 1, &r)) {
        SetWindowTextA(g_hHkStatus, "Restore Over. Hooks/Patches: query failed");
        return;
    }
    switch (r.State) {
    case FE_HOOK_RESTORE_RESTORED:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: restored (%lu entries checked)",
                  r.TotalEntries);
        break;
    case FE_HOOK_RESTORE_NOTHING_TO_DO:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: nothing to restore - all %lu hook entries "
                  "match their on-disk originals (0 modified, driver result=%u)",
                  r.TotalEntries, r.ResultByte);
        break;
    case FE_HOOK_RESTORE_ATTEMPTED_NO_EFFECT:
        sprintf_s(msg, sizeof(msg),
                  "Restore Over. Hooks/Patches: %lu modified entries found but driver "
                  "reported no change (result=%u)",
                  r.ModifiedCount, r.ResultByte);
        break;
    default:
        sprintf_s(msg, sizeof(msg), "Restore Over. Hooks/Patches: %s",
                  FeHookRestoreStateText(&r));
        break;
    }
    SetWindowTextA(g_hHkStatus, msg);
    DoRefreshHooks();                 /* 刷新列表，让用户看到恢复后的状态 */
}

void DoRestoreCallbackTable(void)
{
    FE_CB_TABLE t;
    char msg[420];
    int n = 0;
    ULONG i;

    if (!g_Client.Opened) {
        SetWindowTextA(g_hHkStatus, "Restore KernelCallbackTable: not connected");
        return;
    }
    if (!FeLoadCallbackTable(&g_Client, &t)) {
        SetWindowTextA(g_hHkStatus, "Restore KernelCallbackTable: query failed");
        return;
    }
    if (t.State != FE_CB_ENUMERATED) {
        sprintf_s(msg, sizeof(msg),
                  "Restore KernelCallbackTable: %s (cmd 0x131 result=%u)",
                  FeCbStateText(&t), t.ResultByte);
        SetWindowTextA(g_hHkStatus, msg);
        return;
    }
    /* 枚举成功：把 28 个回调槽追加到列表里。
       每行显示「槽号 / 目标 RVA / 当前回调指针 / 原始代码前 8 字节」，
       其中「当前回调指针」与「原始代码」的差异就是该槽是否被替换的判据。 */
    if (g_hHkList) {
        while (ListView_GetItemCount(g_hHkList) > 0)
            ListView_DeleteItem(g_hHkList, 0);
        for (i = 0; i < t.Count; i++) {
            LVITEMA it;
            char idxbuf[32], off[32], val[64], note[96];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = n;
            sprintf_s(idxbuf, sizeof(idxbuf), "%lu", (unsigned long)t.Slot[i].Offset);
            sprintf_s(off, sizeof(off), "+0x%03lX", (unsigned long)(8 + i * 0x30));
            sprintf_s(val, sizeof(val), "%016I64X", t.Slot[i].Current);
            /* 有原始快照且当前回调指针已被重定向（cur != va）时标出。
               注意：orig 是目标地址上的机器码快照，cur 是回调函数指针，
               二者不同类，不能互相比较。「va 处代码被就地改成跳板」这种情形
               需要读内核内存才能判定，0x131 的输出里没有该字段。 */
            if (t.Slot[i].HasOriginal) {
                if (t.Slot[i].Current && t.Slot[i].Current != t.Slot[i].Va)
                    sprintf_s(note, sizeof(note),
                              "callback slot %lu (RVA 0x%lX) - pointer redirected",
                              (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
                else
                    sprintf_s(note, sizeof(note),
                              "callback slot %lu (RVA 0x%lX)",
                              (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
            } else {
                sprintf_s(note, sizeof(note),
                          "callback slot %lu (RVA 0x%lX) - no snapshot",
                          (unsigned long)t.Slot[i].Offset, (unsigned long)t.Slot[i].Rva);
            }
            it.pszText = (LPSTR)"Ring0";
            SendMessageA(g_hHkList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            HkSetText(g_hHkList, n, 1, "KernelCallbackTable");
            HkSetText(g_hHkList, n, 2, off);
            HkSetText(g_hHkList, n, 3, val);
            HkSetText(g_hHkList, n, 4, note);
            n++;
        }
    }
    /* 真正下发恢复（0x132）：对「回调指针已被重定向」的槽，
       把 16 字节原始代码写回目标 VA。没有重定向项时如实报告「无需恢复」。 */
    {
        ULONG restored = 0, attempted = 0, rejected = 0, skipped = 0;
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
                rr.State == FE_CB_RESTORE_OK)
                restored++;
            else
                rejected++;
        }
        if (attempted == 0) {
            sprintf_s(msg, sizeof(msg),
                      "Restore KernelCallbackTable: %lu callback slots, build %lu, "
                      "verify=%u - nothing to restore (%lu slots still point at "
                      "their original targets)",
                      t.Count, t.Build, t.Ready, (unsigned long)skipped);
        } else {
            sprintf_s(msg, sizeof(msg),
                      "Restore KernelCallbackTable: %lu slots, build %lu, "
                      "%lu restored / %lu redirected (%lu rejected, %lu clean)",
                      t.Count, t.Build, (unsigned long)restored,
                      (unsigned long)attempted, (unsigned long)rejected,
                      (unsigned long)skipped);
        }
        SetWindowTextA(g_hHkStatus, msg);
        DoRefreshHooks();
        return;
    }
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Hook 页段，逐字保留） ---- */
void FeHookPagePageShow(HWND hWnd, int page)
{
int isHooks = (page == 2 || page == 3);  /* Ring0 Hooks / Ring3 Hooks */
    if (g_hHkList)   ShowWindow(g_hHkList,   isHooks ? SW_SHOW : SW_HIDE);
    if (g_hHkStatus) ShowWindow(g_hHkStatus, isHooks ? SW_SHOW : SW_HIDE);
    {
        HWND a = GetDlgItem(hWnd, IDC_HK_REFRESH);
        HWND r = GetDlgItem(hWnd, IDC_HK_RESTORE);
        HWND c = GetDlgItem(hWnd, IDC_HK_CBTABLE);
        if (a) ShowWindow(a, isHooks ? SW_SHOW : SW_HIDE);
        /* 两项恢复操作只属于 Ring0 页（主 Tab 2），Ring3 页不显示 */
        if (r) ShowWindow(r, (page == 2) ? SW_SHOW : SW_HIDE);
        if (c) ShowWindow(c, (page == 2) ? SW_SHOW : SW_HIDE);
    }}

/* ============================================================================
 * 2026-10-29 新增：钩子页右键菜单（原版 10 项，见 右键菜单差距分析）
 *
 *   Refresh                    刷新              [已补全]
 *   Only show hooks            仅显示挂钩函数     [已补全]  ← 勾选过滤
 *   Disassembling current entry   反汇编当前函数地址 [已补全]
 *   Disassembling original entry  反汇编原始函数地址 [已补全]
 *   Disassembling Fun Entry    反汇编函数          [已补全]
 *   Restore                    恢复              [已补全]
 *   Restore All                恢复所有           [已补全]
 *   Find Target                定位到模块文件      [已补全]
 *   Properties                 查看模块属性       [已补全]
 *   Locate in File Tab         定位到文件管理器    [已补全]
 *   Export Display             导出              [我方补充]
 * ==========================================================================*/

#define HK_MENU_BASE   9800
#define HK_ID_REFRESH      (HK_MENU_BASE + 1)
#define HK_ID_ONLY_HOOKS   (HK_MENU_BASE + 2)
#define HK_ID_DISASM_CUR   (HK_MENU_BASE + 3)
#define HK_ID_DISASM_ORIG  (HK_MENU_BASE + 4)
#define HK_ID_DISASM_ENTRY (HK_MENU_BASE + 5)
#define HK_ID_RESTORE      (HK_MENU_BASE + 6)
#define HK_ID_RESTORE_ALL  (HK_MENU_BASE + 7)
#define HK_ID_FIND_TARGET  (HK_MENU_BASE + 8)
#define HK_ID_PROPERTIES   (HK_MENU_BASE + 9)
#define HK_ID_LOCATE_FILE  (HK_MENU_BASE + 10)
#define HK_ID_EXPORT       (HK_MENU_BASE + 11)
#define HK_ID_OBJTYPE      (HK_MENU_BASE + 12)

/* 在状态栏以可读形式展示一段反汇编（FeDisasmOne 逐条解，最多 8 条） */
static void HkShowDisasm(ULONG64 Addr, const unsigned char *Bytes, int Len, const char *What)
{
    char out[900];
    char line[160];
    int pos = 0, off = 0;

    sprintf_s(out, sizeof(out), "%s @ %016I64X: ", What, Addr);
    while (off < Len && off < 48) {
        FE_INSN ins;
        ZeroMemory(&ins, sizeof(ins));
        if (!FeDisasmOne(Bytes + off, Len - off, &ins) || ins.Length == 0)
            break;
        sprintf_s(line, sizeof(line), "%s; ", ins.Mnemonic);
        if (strlen(out) + strlen(line) + 2 >= sizeof(out))
            break;
        strcat_s(out, sizeof(out), line);
        off += ins.Length;
        if (++pos >= 8)
            break;
    }
    if (pos == 0)
        strcat_s(out, sizeof(out), "(cannot decode)");
    SetWindowTextA(g_hHkStatus, out);
}

/* 取选中的 Ring0 条目；返回 NULL 表示当前行不是 Ring0 条目 */
static const FE_RING0_HOOK_ENTRY *HkSelectedR0(void)
{
    int sel = FeListGetSel(g_hHkList);
    if (sel < 0 || sel >= HK_MAX_ROWS)
        return NULL;
    if (!g_HkR0Valid)
        return NULL;
    if (g_HkRowToR0[sel] < 0 || g_HkRowToR0[sel] >= (int)g_HkR0Cache.Count)
        return NULL;
    return &g_HkR0Cache.Items[g_HkRowToR0[sel]];
}

/* 从地址反查所属内核模块（EnumDeviceDrivers 区间匹配） */
static void HkModuleOf(ULONG64 Addr, char *Out, int OutChars)
{
    LPVOID bases[1024];
    DWORD needed = 0, n, i;

    Out[0] = 0;
    if (!EnumDeviceDrivers(bases, sizeof(bases), &needed))
        return;
    n = needed / sizeof(LPVOID);
    for (i = 0; i < n; i++) {
        ULONG64 base = (ULONG64)bases[i];
        ULONG64 end = (i + 1 < n) ? (ULONG64)bases[i + 1] : base + 0x4000000ULL;
        if (Addr >= base && Addr < end) {
            char name[256];
            if (GetDeviceDriverBaseNameA(bases[i], name, sizeof(name)))
                strncpy_s(Out, OutChars, name, _TRUNCATE);
            return;
        }
    }
}

void DoHookContextMenu(HWND hWnd, int X, int Y)
{
    HMENU hMenu;
    UINT cmd;
    int sel;
    const FE_RING0_HOOK_ENTRY *e;

    FeListSelectUnderCursor(g_hHkList, X, Y);
    sel = FeListGetSel(g_hHkList);
    e = HkSelectedR0();

    hMenu = FeMenuBegin();
    if (!hMenu)
        return;

    FeMenuAdd(hMenu, HK_ID_REFRESH, "Refresh");
    FeMenuAdd(hMenu, HK_ID_OBJTYPE, "Object Type Hook (0xFF)");
    FeMenuSep(hMenu);
    FeMenuAddCheck(hMenu, HK_ID_ONLY_HOOKS, "Only show hooks", g_HkOnlyHooks);
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, HK_ID_DISASM_CUR, "Disassembling current entry", e != NULL);
    FeMenuAddEx(hMenu, HK_ID_DISASM_ORIG, "Disassembling original entry",
                e != NULL && e->Original != 0);
    FeMenuAddEx(hMenu, HK_ID_DISASM_ENTRY, "Disassembling Fun Entry", e != NULL);
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, HK_ID_RESTORE, "Restore", sel >= 0);
    FeMenuAddEx(hMenu, HK_ID_RESTORE_ALL, "Restore All", sel >= 0);
    FeMenuSep(hMenu);
    FeMenuAddEx(hMenu, HK_ID_FIND_TARGET, "Find Target", e != NULL);
    FeMenuAddEx(hMenu, HK_ID_PROPERTIES, "Properties", e != NULL);
    FeMenuAddEx(hMenu, HK_ID_LOCATE_FILE, "Locate in File Tab", e != NULL);
    FeMenuSep(hMenu);
    FeMenuAdd(hMenu, HK_ID_EXPORT, "Export Display");

    cmd = FeMenuEnd(hMenu, hWnd, X, Y, 40, 40);

    switch (cmd) {
    case HK_ID_REFRESH:
        DoRefreshHooks();
        break;
    case HK_ID_ONLY_HOOKS:
        g_HkOnlyHooks = !g_HkOnlyHooks;
        DoRefreshHooks();
        break;
    case HK_ID_DISASM_CUR:
        if (e)
            HkShowDisasm(e->Current, e->Bytes, 16, "current entry");
        break;
    case HK_ID_DISASM_ORIG:
        if (e)
            HkShowDisasm(e->Original, e->Bytes, 16, "original entry");
        break;
    case HK_ID_DISASM_ENTRY:
        if (e) {
            char mod[256];
            char msg[1100];
            char buf[400];
            FE_INSN ins;
            int off = 0, k = 0;

            HkModuleOf(e->Current, mod, sizeof(mod));
            buf[0] = 0;
            while (off < 16 && k < 6) {
                ZeroMemory(&ins, sizeof(ins));
                if (!FeDisasmOne(e->Bytes + off, 16 - off, &ins) || !ins.Length)
                    break;
                strncat_s(buf, sizeof(buf), ins.Mnemonic, _TRUNCATE);
                strncat_s(buf, sizeof(buf), "; ", _TRUNCATE);
                off += ins.Length;
                k++;
            }
            sprintf_s(msg, sizeof(msg), "Fun Entry %016I64X (%s): %s", e->Current,
                      mod[0] ? mod : "unknown module", buf[0] ? buf : "(no decode)");
            SetWindowTextA(g_hHkStatus, msg);
        }
        break;
    case HK_ID_RESTORE: {
        HWND btn = GetDlgItem(hWnd, IDC_HK_RESTORE);
        if (btn)
            SendMessageA(hWnd, WM_COMMAND, MAKEWPARAM(IDC_HK_RESTORE, BN_CLICKED), (LPARAM)btn);
        break;
    }
    case HK_ID_RESTORE_ALL: {
        HWND btn = GetDlgItem(hWnd, IDC_HK_CBTABLE);
        if (btn)
            SendMessageA(hWnd, WM_COMMAND, MAKEWPARAM(IDC_HK_CBTABLE, BN_CLICKED), (LPARAM)btn);
        break;
    }
    case HK_ID_FIND_TARGET:
        if (e) {
            char mod[256];
            char msg[700];
            HkModuleOf(e->Current, mod, sizeof(mod));
            sprintf_s(msg, sizeof(msg), "Find Target: %016I64X belongs to %s",
                      e->Current, mod[0] ? mod : "(unknown module)");
            SetWindowTextA(g_hHkStatus, msg);
        }
        break;
    case HK_ID_PROPERTIES:
        if (e) {
            char mod[256];
            char msg[700];
            HkModuleOf(e->Current, mod, sizeof(mod));
            sprintf_s(msg, sizeof(msg),
                      "Properties: module=%s current=%016I64X original=%016I64X "
                      "table=%lu index=%lu flags(addr=%u bytes=%u)",
                      mod[0] ? mod : "?", e->Current, e->Original,
                      (unsigned long)e->TableIndex, (unsigned long)e->Index,
                      (unsigned)e->FlagAddr, (unsigned)e->FlagBytes);
            SetWindowTextA(g_hHkStatus, msg);
        }
        break;
    case HK_ID_LOCATE_FILE:
        if (e) {
            char mod[256];
            char dir[MAX_PATH];
            HkModuleOf(e->Current, mod, sizeof(mod));
            if (mod[0]) {
                GetSystemDirectoryA(dir, sizeof(dir));
                strcat_s(dir, sizeof(dir), "\\drivers\\");
                strcat_s(dir, sizeof(dir), mod);
                if (g_hFlDir)
                    SetWindowTextA(g_hFlDir, dir);
            }
            if (g_hMainTabs)
                SendMessageA(g_hMainTabs, TCM_SETCURSEL, 8, 0);
            if (g_hMainWnd)
                ShowPage(g_hMainWnd, 8);
            DoRefreshFiles();
            SetWindowTextA(g_hHkStatus, "Locate in File Tab: opened File page");
        }
        break;
    case HK_ID_EXPORT:
        FeListExportDefault(g_hHkList, g_hHkStatus, "PCHunter_Hooks");
        break;
    case HK_ID_OBJTYPE: {
        /* 2026-10-29：对象类型钩子（命令 0xFF）
           驱动 EnumObjectTypeTableOperation 返回对象类型表，
           这里把条目渲染进钩子列表。 */
        ULONG cnt, k;
        char msg[600];

        SetWindowTextA(g_hHkStatus, "Object Type Hook: querying driver (0xFF)...");
        UpdateWindow(g_hHkStatus);
        cnt = FeLoadObjectTypeHooks(&g_Client);
        ListView_DeleteAllItems(g_hHkList);
        {
            LVCOLUMNA c;
            while (ListView_DeleteColumn(g_hHkList, 0))
                ;
            ZeroMemory(&c, sizeof(c));
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            c.pszText = "Type";     c.cx = 90;  c.iSubItem = 0; ListView_InsertColumn(g_hHkList, 0, &c);
            c.pszText = "TypeIdx";  c.cx = 90;  c.iSubItem = 1; ListView_InsertColumn(g_hHkList, 1, &c);
            c.pszText = "Object";   c.cx = 190; c.iSubItem = 2; ListView_InsertColumn(g_hHkList, 2, &c);
            c.pszText = "Value";    c.cx = 190; c.iSubItem = 3; ListView_InsertColumn(g_hHkList, 3, &c);
            c.pszText = "Note";     c.cx = 300; c.iSubItem = 4; ListView_InsertColumn(g_hHkList, 4, &c);
        }
        for (k = 0; k < cnt; k++) {
            ULONG ti = 0;
            ULONG64 op = 0, val = 0;
            char a[32], b[32], d[32];
            LVITEMA it;

            if (!FeObjectHookGet(k, &ti, &op, &val))
                break;
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)k;
            it.pszText = (ti == 0) ? "TypeNode" : "Entry";
            SendMessageA(g_hHkList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(a, sizeof(a), "%lu", (unsigned long)ti);
            sprintf_s(b, sizeof(b), "%016I64X", op);
            sprintf_s(d, sizeof(d), "%016I64X", val);
            HkSetText(g_hHkList, (int)k, 1, a);
            HkSetText(g_hHkList, (int)k, 2, b);
            HkSetText(g_hHkList, (int)k, 3, d);
            HkSetText(g_hHkList, (int)k, 4,
                      (ti == 0) ? "object type node" : "type entry pointer");
        }
        sprintf_s(msg, sizeof(msg), "%s", FeObjectHookStatus());
        SetWindowTextA(g_hHkStatus, msg);
        FeObjectHookFree();
        break;
    }
    default:
        break;
    }
}