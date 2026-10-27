// ============================================================================
// FeHookPage.c — Hook 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hHkList, g_hHkStatus;

/* ---- Ring0 / Ring3 Hooks 页（主 Tab 2 / 3）----
 * Ring3 扫 IAT 越界；Ring0 标 blocked（驱动链缺 6 个函数，见
 * docs/reversing/Hooks页落地_2026-10-21.md）。 */
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
            ListView_InsertItem(g_hHkList, NULL);
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
        FeFreeRing0Hooks(&r0);
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
