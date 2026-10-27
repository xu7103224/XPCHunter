// ============================================================================
// FeRegistryPage.c — Registry 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）
// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"

HWND g_hRgTabs, g_hRgList, g_hRgStatus;
int  g_RgTab = 0;
char g_RgPath[512] = "HKLM\\SYSTEM\\CurrentControlSet\\Services";

/* ---- Registry 页（主 Tab 5）----
 * 两个子页：
 *   Reg Handle     全系统 ObjectType="Key" 的句柄（pid / handle / access / object）
 *   Hidden Item    控制字符键名 + HKCU\Software\Classes 独占项
 * 四列都可在列表里选中复制（Copy Key Name / RegPath / RegValue / RegData 由
 * 用户复制对应列实现；原版的复制菜单项文本与此一一对应）。 */
void RgSetText(HWND hList, int iItem, int iSub, const char *text)
{
    LVITEMA it;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iSubItem = iSub;
    it.pszText = (LPSTR)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
}

void CreateRgColumns(HWND hList, int tab)
{
    LVCOLUMNA c;
    while (ListView_DeleteColumn(hList, 0))
        ;
    ZeroMemory(&c, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    if (tab == 0) {
        c.pszText = "PID";     c.cx = 80;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Handle";  c.cx = 110; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Access";  c.cx = 110; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Key Object"; c.cx = 640; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else if (tab == 2) {
        /* CmpNotifyChange：CmRegisterCallback 注册的回调链。
           数据源为命令 0x127（CmdEnumRegistryContext），要求出参缓冲
           恰好 1800 字节（驱动里是 `BufferSize == 1800` 硬判断）。 */
        c.pszText = "Index";     c.cx = 70;  c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Function";  c.cx = 200; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Context";   c.cx = 200; c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
        c.pszText = "Slot";      c.cx = 400; c.iSubItem = 3; ListView_InsertColumn(hList, 3, &c);
    } else {
        c.pszText = "RegPath"; c.cx = 700; c.iSubItem = 0; ListView_InsertColumn(hList, 0, &c);
        c.pszText = "Reason";  c.cx = 260; c.iSubItem = 1; ListView_InsertColumn(hList, 1, &c);
        c.pszText = "Depth";   c.cx = 70;  c.iSubItem = 2; ListView_InsertColumn(hList, 2, &c);
    }
}

void DoRefreshRegistry(void)
{
    char status[256];

    if (!g_hRgList || !g_hRgStatus)
        return;
    ListView_DeleteAllItems(g_hRgList);
    CreateRgColumns(g_hRgList, g_RgTab);

    if (g_RgTab == 0) {
        FE_REG_HANDLE_LIST list;
        ULONG i;
        if (!FeLoadRegistryHandles(FE_REGH_MAX, &list)) {
            sprintf_s(status, sizeof(status),
                      "Reg Handle: query failed (KeyTypeIndex=%ld)", (long)list.KeyTypeIndex);
            SetWindowTextA(g_hRgStatus, status);
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char pid[24], h[32], acc[32], obj[32];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            sprintf_s(pid, sizeof(pid), "%lu", list.Items[i].Pid);
            it.pszText = pid;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            sprintf_s(h, sizeof(h), "0x%I64X", list.Items[i].Handle);
            sprintf_s(acc, sizeof(acc), "0x%lX", list.Items[i].Access);
            sprintf_s(obj, sizeof(obj), "%016I64X", list.Items[i].Object);
            RgSetText(g_hRgList, (int)i, 1, h);
            RgSetText(g_hRgList, (int)i, 2, acc);
            RgSetText(g_hRgList, (int)i, 3, obj);
        }
        sprintf_s(status, sizeof(status),
                  "Reg Handle: %lu open Key handles system-wide (type index %ld)",
                  list.Count, (long)list.KeyTypeIndex);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeRegistryHandles(&list);
    } else if (g_RgTab == 2) {
        /* 【2026-10-23 更正，撤回上一版错误实现】
           上一版把 0x127 的输出当成 CmRegisterCallback 回调链渲染，
           那是**错的**。三条独立证据：
             1. kd `lm a` 核对：输出里的地址全部落在 Npfs
                （0xFFFFF80539B7B670 / B270 / EAF0 → Npfs 段），
                另有 0xFFFFF80534525D40 → nt。
             2. 驱动源码：EnumerateRegistryContextTable 的数据源是
                BuildRegistryDriverPath() 打开的驱动，而该函数里的
                编码路径解码后是 `\FileSystem\Npfs`；它读该驱动 PE 节区
                +0x70（+112）处的 28 个函数指针（0..0x1B）。
             3. 记录布局确为 0x30 步长、+0x00 序号、+0x10 函数指针，
                但这只是"Npfs 分发表的函数指针"，与注册表无关。
           即：0x127 属于「驱动分发表 hook 检测」这一类，
           **不是** CmRegisterCallback 的注册表回调链（那需要读
           nt!CmpCallbackListHead，我们没有任意内核内存读取能力）。
           因此本子页如实标注没有数据源，不拿 Npfs 指针冒充。 */
        sprintf_s(status, sizeof(status),
                  "CmpNotifyChange: no data source. The registry callback "
                  "chain lives in nt!CmpCallbackListHead and no command "
                  "exposes it (0x127 enumerates Npfs dispatch-table "
                  "pointers, not CmRegisterCallback entries).");
        SetWindowTextA(g_hRgStatus, status);
    } else {
        FE_REG_HIDDEN_LIST list;
        ULONG i;
        if (!FeLoadHiddenRegKeys(&list)) {
            SetWindowTextA(g_hRgStatus, "Hidden Item: query failed");
            return;
        }
        for (i = 0; i < list.Count; i++) {
            LVITEMA it;
            char depth[16];
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT;
            it.iItem = (int)i;
            it.pszText = list.Items[i].Path;
            SendMessageA(g_hRgList, LVM_INSERTITEMA, 0, (LPARAM)&it);
            RgSetText(g_hRgList, (int)i, 1, list.Items[i].Reason);
            sprintf_s(depth, sizeof(depth), "%d", list.Items[i].Depth);
            RgSetText(g_hRgList, (int)i, 2, depth);
        }
        sprintf_s(status, sizeof(status), "Hidden Item: %lu suspicious registry keys", list.Count);
        SetWindowTextA(g_hRgStatus, status);
        FeFreeHiddenRegKeys(&list);
    }
}

/* ---- PageShow：frontend.c 的页面注册表在每次切页时调用（原 ShowPage 的 Registry 页段，逐字保留） ---- */
void FeRegistryPagePageShow(HWND hWnd, int page)
{
int isRegistry = (page == 5);    /* 第 6 个 Tab = Registry */
    if (g_hRgTabs)   ShowWindow(g_hRgTabs,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgList)   ShowWindow(g_hRgList,   isRegistry ? SW_SHOW : SW_HIDE);
    if (g_hRgStatus) ShowWindow(g_hRgStatus, isRegistry ? SW_SHOW : SW_HIDE);
    {
        HWND hRg = GetDlgItem(hWnd, IDC_RG_REFRESH);
        HWND hPath = GetDlgItem(hWnd, IDC_RG_PATH);
        HWND hGo = GetDlgItem(hWnd, IDC_RG_GO);
        if (hRg) ShowWindow(hRg, isRegistry ? SW_SHOW : SW_HIDE);
        /* 路径框只在 Key 子页出现 */
        if (hPath) ShowWindow(hPath, (isRegistry && g_RgTab == 0) ? SW_SHOW : SW_HIDE);
        if (hGo) ShowWindow(hGo, (isRegistry && g_RgTab == 0) ? SW_SHOW : SW_HIDE);
    }}
