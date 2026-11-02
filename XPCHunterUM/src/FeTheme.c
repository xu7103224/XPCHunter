// ============================================================================
// FeTheme.c — 第三步（表现层）：深色主题 / 状态色 / 列表自绘
//
// 只做"把颜色应用到既有控件"，不改任何控件的创建、布局、数据流。
// CLI 路径完全不经过本文件，因此 46 条 CLI 比对输出不受影响。
// ============================================================================
#include "FeTheme.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <string.h>

/* ---- 两套配色 ---- */

static const FE_THEME_COLORS kDark = {
    RGB(0x1E, 0x1E, 0x1E),   /* Bg         */
    RGB(0x25, 0x25, 0x26),   /* Panel      */
    RGB(0xD4, 0xD4, 0xD4),   /* Text       */
    RGB(0x9A, 0x9A, 0x9A),   /* TextDim    */
    RGB(0x2D, 0x2D, 0x30),   /* Header     */
    RGB(0xC8, 0xC8, 0xC8),   /* HeaderText */
    RGB(0x09, 0x40, 0x62),   /* Select     */
    RGB(0xFF, 0xFF, 0xFF),   /* SelectText */
    RGB(0x3A, 0x3A, 0x3D),   /* Grid       */
    RGB(0x6A, 0xC8, 0x7A),   /* Accent 绿  */
    RGB(0xE0, 0xB0, 0x50),   /* Warn   黄  */
    RGB(0xE0, 0x6C, 0x6C)    /* Danger 红  */
};

static const FE_THEME_COLORS kLight = {
    RGB(0xF0, 0xF0, 0xF0),   /* Bg         */
    RGB(0xFF, 0xFF, 0xFF),   /* Panel      */
    RGB(0x20, 0x20, 0x20),   /* Text       */
    RGB(0x60, 0x60, 0x60),   /* TextDim    */
    RGB(0xE8, 0xE8, 0xE8),   /* Header     */
    RGB(0x20, 0x20, 0x20),   /* HeaderText */
    RGB(0xCC, 0xE4, 0xFF),   /* Select     */
    RGB(0x00, 0x00, 0x00),   /* SelectText */
    RGB(0xD0, 0xD0, 0xD0),   /* Grid       */
    RGB(0x1B, 0x7A, 0x2E),   /* Accent 绿  */
    RGB(0x8A, 0x60, 0x00),   /* Warn   黄  */
    RGB(0xB0, 0x1C, 0x1C)    /* Danger 红  */
};

static BOOL g_Dark = TRUE;   /* 默认深色（本步的目标） */
static HBRUSH g_hbrBg = NULL;
static HBRUSH g_hbrPanel = NULL;

void FeThemeSetDark(BOOL Dark)
{
    if (g_Dark == !!Dark)
        return;
    g_Dark = !!Dark;
    if (g_hbrBg)    { DeleteObject(g_hbrBg);    g_hbrBg = NULL; }
    if (g_hbrPanel) { DeleteObject(g_hbrPanel); g_hbrPanel = NULL; }
}

BOOL FeThemeIsDark(void)
{
    return g_Dark;
}

const FE_THEME_COLORS *FeThemeColors(void)
{
    return g_Dark ? &kDark : &kLight;
}

HBRUSH FeThemeBgBrush(void)
{
    if (!g_hbrBg)
        g_hbrBg = CreateSolidBrush(FeThemeColors()->Bg);
    return g_hbrBg;
}

HBRUSH FeThemePanelBrush(void)
{
    if (!g_hbrPanel)
        g_hbrPanel = CreateSolidBrush(FeThemeColors()->Panel);
    return g_hbrPanel;
}

/* 语义色：把状态文本映射到 Accent / Warn / Danger。
   只做大小写无关的子串判断，避免依赖各页的枚举。 */
COLORREF FeThemeStatusColor(const char *Text)
{
    char low[256];
    size_t i;
    const FE_THEME_COLORS *c = FeThemeColors();

    if (!Text || !Text[0])
        return c->Text;
    for (i = 0; Text[i] && i + 1 < sizeof(low); i++) {
        char ch = Text[i];
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch - 'A' + 'a');
        low[i] = ch;
    }
    low[i] = 0;

    /* 危险：不可访问 / 隐藏 / 被改 / 失败 */
    if (strstr(low, "inaccessible") || strstr(low, "hidden") ||
        strstr(low, "modified") || strstr(low, "hooked") ||
        strstr(low, "failed") || strstr(low, "blocked"))
        return c->Danger;
    /* 可疑：需要人工看一眼 */
    if (strstr(low, "suspicious") || strstr(low, "unknown") ||
        strstr(low, "?"))
        return c->Warn;
    /* 正常 */
    if (strstr(low, "accessible") || strstr(low, "clean") ||
        strstr(low, "ok") || strstr(low, "running"))
        return c->Accent;
    return c->Text;
}

/* 给 ListView 打开自定义绘制的准备工作。
   LVS_EX_DOUBLEBUFFER 是防闪烁的关键（双缓冲），与 custom draw 配合使用。 */
void FeThemeApplyToList(HWND hList)
{
    if (!hList)
        return;
    ListView_SetExtendedListViewStyleEx(
        hList, LVS_EX_DOUBLEBUFFER, LVS_EX_DOUBLEBUFFER);

    /* 列表背景/文字底色走控件自身的 API。
       —— 不用 custom draw 的 POSTPAINT 去填空白区：POSTPAINT 在全部行绘制
       之后触发，那时 FillRect 整个客户区会把已经画好的行一起抹掉。 */
    ListView_SetBkColor(hList, FeThemeColors()->Panel);
    ListView_SetTextBkColor(hList, FeThemeColors()->Panel);
    ListView_SetTextColor(hList, FeThemeColors()->Text);

    /* 表头是独立的 SysHeader32 子窗口，ListView 的 BkColor 管不到它，
       只能靠 custom draw（见 FeThemeDrawHeader）。 */
}

/* 表头 custom draw：只有 NM_CUSTOMDRAW 才能改表头底色。
   返回 TRUE 表示已处理（调用方据此返回 CDRF_NEWFONT / NOTIFYITEMDRAW）。 */
BOOL FeThemeDrawHeader(HDC hdc, LPNMCUSTOMDRAW cd, BOOL *NeedItemDraw)
{
    const FE_THEME_COLORS *c = FeThemeColors();

    if (NeedItemDraw)
        *NeedItemDraw = FALSE;
    if (!cd)
        return FALSE;

    switch (cd->dwDrawStage) {
    case CDDS_PREPAINT:
        /* 表头整体底色（列间空隙也覆盖） */
        if (hdc)
            FillRect(hdc, &cd->rc, FeThemePanelBrush());
        if (NeedItemDraw)
            *NeedItemDraw = TRUE;
        return TRUE;

    case CDDS_ITEMPREPAINT:
        if (hdc) {
            FillRect(hdc, &cd->rc, FeThemePanelBrush());
            SetTextColor(hdc, c->HeaderText);
            SetBkColor(hdc, c->Panel);
        }
        return TRUE;

    default:
        break;
    }
    return FALSE;
}

/* ---- 状态图标 ----
   用 GDI 在内存里画 16x16 实心圆点，四色对应四种语义。
   这样不需要 .ico 资源、不需要外部文件，也天然跟随主题换色。 */
#define FE_ICON_CX 16
#define FE_ICON_CY 16

static HIMAGELIST g_himl = NULL;

static void FeDrawDot(HDC hdc, int cx, int cy, COLORREF Color)
{
    HBRUSH br = CreateSolidBrush(Color);
    HPEN pen = CreatePen(PS_SOLID, 1, Color);
    HGDIOBJ oldBr = SelectObject(hdc, br);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    /* 内缩 2px 留出边距，画成实心圆 */
    Ellipse(hdc, 2, 2, cx - 2, cy - 2);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBr);
    DeleteObject(pen);
    DeleteObject(br);
}

HIMAGELIST FeThemeIconList(void)
{
    const FE_THEME_COLORS *c = FeThemeColors();
    HDC hdc;
    HDC mem;
    HBITMAP bmp;
    HGDIOBJ old;
    HIMAGELIST himl;
    int i;
    COLORREF colors[4];

    if (g_himl)
        return g_himl;

    himl = ImageList_Create(FE_ICON_CX, FE_ICON_CY, ILC_COLOR24, 4, 4);
    if (!himl)
        return NULL;

    hdc = GetDC(NULL);
    mem = CreateCompatibleDC(hdc);

    colors[0] = c->Accent;   /* 正常 */
    colors[1] = c->Danger;   /* 异常 */
    colors[2] = c->Warn;     /* 可疑 */
    colors[3] = c->TextDim;  /* 其它 */

    for (i = 0; i < 4; i++) {
        /* 24 位 DIB：背景先刷成 Panel 色，再叠圆点，避免透明通道问题 */
        BITMAPINFO bi;
        void *bits = NULL;
        ZeroMemory(&bi, sizeof(bi));
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = FE_ICON_CX;
        bi.bmiHeader.biHeight = -FE_ICON_CY;   /* 自上而下 */
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        bmp = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        if (!bmp)
            continue;
        old = SelectObject(mem, bmp);

        {
            HBRUSH bg = CreateSolidBrush(c->Panel);
            RECT rc;
            SetRect(&rc, 0, 0, FE_ICON_CX, FE_ICON_CY);
            FillRect(mem, &rc, bg);
            DeleteObject(bg);
        }
        FeDrawDot(mem, FE_ICON_CX, FE_ICON_CY, colors[i]);

        SelectObject(mem, old);
        ImageList_Add(himl, bmp, NULL);
        DeleteObject(bmp);
    }

    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    g_himl = himl;
    return g_himl;
}

/* 状态文本 → 图标索引（纯函数，供自检断言） */
int FeThemeStatusIconIndex(const char *Text)
{
    COLORREF c = FeThemeStatusColor(Text);
    const FE_THEME_COLORS *p = FeThemeColors();

    if (c == p->Danger)  return 1;
    if (c == p->Warn)    return 2;
    if (c == p->Accent)  return 0;
    return 3;
}

void FeThemeAttachIcons(HWND hList)
{
    HIMAGELIST himl;

    if (!hList)
        return;
    himl = FeThemeIconList();
    if (!himl)
        return;
    ListView_SetImageList(hList, himl, LVSIL_SMALL);
    /* 让子项（不只是第 0 列）也能显示图标 */
    ListView_SetExtendedListViewStyleEx(
        hList, LVS_EX_SUBITEMIMAGES, LVS_EX_SUBITEMIMAGES);
}

/* NM_CUSTOMDRAW 处理：表头底色、行底色/文字色、网格线颜色。
   返回 FALSE 表示本次不接管，让系统默认绘制（自绘只覆盖颜色，不改布局）。 */
BOOL FeThemeDrawListViewItem(NMLVCUSTOMDRAW *cd)
{
    const FE_THEME_COLORS *c = FeThemeColors();

    if (!cd)
        return FALSE;

    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        /* 要求每个 item 都回一次通知 */
        return TRUE;   /* 调用方据此返回 CDRF_NOTIFYITEMDRAW */

    case CDDS_ITEMPREPAINT: {
        BOOL selected = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;

        cd->clrText = selected ? c->SelectText : c->Text;
        cd->clrTextBk = selected ? c->Select : c->Panel;

        /* 第三步-3：状态列逐行着色（语义状态约定在最后一列）。 */
        if (!selected) {
            HWND hList = cd->nmcd.hdr.hwndFrom;
            int nCol = Header_GetItemCount(
                           (HWND)SendMessageA(hList, LVM_GETHEADER, 0, 0));
            int iItem = (int)cd->nmcd.dwItemSpec;

            if (nCol > 0) {
                char txt[256];
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.iSubItem = nCol - 1;
                it.pszText = txt;
                it.cchTextMax = sizeof(txt);
                txt[0] = 0;
                SendMessageA(hList, LVM_GETITEMTEXTA, (WPARAM)iItem, (LPARAM)&it);
                if (txt[0])
                    cd->clrText = FeThemeStatusColor(txt);
            }
        }
        return TRUE;    /* 需要逐子项通知，否则子项底色仍是系统白 */
    }

    /* 逐子项（每一列）都要设一次底色。
       只设 ITEMPREPAINT 不够：ListView 的每个子项是独立绘制的，
       不在这里给 clrTextBk，列区域会露出系统白色背景。 */
    case CDDS_SUBITEM | CDDS_ITEMPREPAINT: {
        BOOL selected = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;

        cd->clrTextBk = selected ? c->Select : c->Panel;
        if (selected) {
            cd->clrText = c->SelectText;
        } else {
            HWND hList = cd->nmcd.hdr.hwndFrom;
            int nCol = Header_GetItemCount(
                           (HWND)SendMessageA(hList, LVM_GETHEADER, 0, 0));
            /* 只在状态列取语义色，其余列保持主文本色 */
            if (nCol > 0 && (int)cd->iSubItem == nCol - 1) {
                char txt[256];
                LVITEMA it;
                ZeroMemory(&it, sizeof(it));
                it.iSubItem = cd->iSubItem;
                it.pszText = txt;
                it.cchTextMax = sizeof(txt);
                txt[0] = 0;
                SendMessageA(hList, LVM_GETITEMTEXTA,
                             (WPARAM)cd->nmcd.dwItemSpec, (LPARAM)&it);
                cd->clrText = txt[0] ? FeThemeStatusColor(txt) : c->Text;
            } else {
                cd->clrText = c->Text;
            }
        }
        return FALSE;
    }

    case CDDS_POSTPAINT:
        /* 不在这里填背景：POSTPAINT 在全部行绘制之后触发，
           此时 FillRect 整个客户区会把已画好的行一起抹掉（曾是"整页全黑"的根因）。
           空白区底色由 ListView_SetBkColor 负责。 */
        return FALSE;

    default:
        break;
    }
    return FALSE;
}

/* 切主题/改 DPI 后让整窗重绘。子控件各自响应 WM_CTLCOLOR* 取新色。 */
void FeThemeRefreshWindow(HWND hWnd)
{
    if (!hWnd)
        return;
    InvalidateRect(hWnd, NULL, TRUE);
    {
        HWND child = GetWindow(hWnd, GW_CHILD);
        while (child) {
            InvalidateRect(child, NULL, TRUE);
            child = GetWindow(child, GW_HWNDNEXT);
        }
    }
    UpdateWindow(hWnd);
}
/* ---- 表头子类化 ----
   SysHeader32 的 NM_CUSTOMDRAW 不会冒泡到父窗口的 WM_NOTIFY
   （实测：父窗口收不到表头的 CDDS_*，表头始终保持系统白底）。
   只能在此处直接子类化表头窗口。 */
static LRESULT CALLBACK FeHeaderSubclass(HWND hWnd, UINT msg, WPARAM wParam,
                                         LPARAM lParam, UINT_PTR id,
                                         DWORD_PTR refData)
{
    if (msg == WM_ERASEBKGND) {
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect((HDC)wParam, &rc, FeThemePanelBrush());
        return 1;
    }
    if (msg == WM_PAINT) {
        /* 表头自己处理 WM_PAINT（在 DefSubclassProc 里画系统白底）。
           这里先刷主题底色，再让原过程画列文字/分隔线，
           最后再刷一次文字背景 —— 单纯拦 ERASEBKGND 不够。 */
        LRESULT r;
        RECT rc;
        HDC dc = GetDC(hWnd);
        GetClientRect(hWnd, &rc);
        FillRect(dc, &rc, FeThemePanelBrush());
        ReleaseDC(hWnd, dc);
        r = DefSubclassProc(hWnd, msg, wParam, lParam);
        /* 原过程画完后，把列文字区重刷成主题色并重画文字 */
        {
            int n = Header_GetItemCount(hWnd);
            int i;
            dc = GetDC(hWnd);
            for (i = 0; i < n; i++) {
                RECT ir;
                if (Header_GetItemRect(hWnd, i, &ir)) {
                    FillRect(dc, &ir, FeThemePanelBrush());
                    /* 用主题色重写列标题 */
                    {
                        HDITEMA hi;
                        char txt[128];
                        ZeroMemory(&hi, sizeof(hi));
                        hi.mask = HDI_TEXT | HDI_FORMAT;
                        hi.pszText = txt;
                        hi.cchTextMax = sizeof(txt);
                        if (Header_GetItem(hWnd, i, &hi)) {
                            SetTextColor(dc, FeThemeColors()->HeaderText);
                            SetBkMode(dc, TRANSPARENT);
                            DrawTextA(dc, txt, -1, &ir,
                                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                        }
                    }
                }
            }
            ReleaseDC(hWnd, dc);
        }
        return r;
    }
    if (msg == WM_NOTIFY) {
        LPNMCUSTOMDRAW cd = (LPNMCUSTOMDRAW)lParam;
        if (cd && cd->dwDrawStage == CDDS_PREPAINT) {
            FillRect(cd->hdc, &cd->rc, FeThemePanelBrush());
            return CDRF_NOTIFYITEMDRAW;
        }
        if (cd && (cd->dwDrawStage & CDDS_ITEM) == CDDS_ITEM &&
            cd->dwDrawStage == CDDS_ITEMPREPAINT) {
            FillRect(cd->hdc, &cd->rc, FeThemePanelBrush());
            SetTextColor(cd->hdc, FeThemeColors()->HeaderText);
            SetBkColor(cd->hdc, FeThemeColors()->Panel);
            return CDRF_NEWFONT;
        }
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

/* 给 ListView 的表头挂子类化（每个表头只需挂一次） */
void FeThemeSubclassHeader(HWND hList)
{
    HWND hHdr;

    if (!hList)
        return;
    hHdr = (HWND)SendMessageA(hList, LVM_GETHEADER, 0, 0);
    if (!hHdr)
        return;
    SetWindowSubclass(hHdr, FeHeaderSubclass, 1, 0);
    InvalidateRect(hHdr, NULL, TRUE);
}

/* ---- Tab 控件子类化 ----
   SysTabControl32 也是系统绘制，WM_CTLCOLORSTATIC 管不到它的标签区。

   【2026-11-02 修 Tab 标签不可见 / 标签条恒为浅灰，走过的三条路】
     (a) NM_CUSTOMDRAW —— 探针实测：整份通知日志里主 Tab（idFrom=1030）
         出现 0 次。SysTabControl32 **根本不发** NM_CUSTOMDRAW。
     (b) SetWindowTheme(h,"","") 关掉视觉样式 —— 关掉之后控件退回经典
         绘制路径，同样不发任何通知，标签条恒为 COLOR_BTNFACE 浅灰。
     (c) TCS_OWNERDRAWFIXED —— 这个样式不只是"让我自绘"，它同时把每个
         标签钉成**同一宽度**。14 个标签远超单格宽度，文字直接压叠。

   可行的是在子类里接管 WM_PAINT：用 TCM_GETITEMRECT 取系统算好的
   每个标签矩形（宽度随文字自适应），自己填色写字后不再交给原过程。
   见 FeTabPaint。 */

/* 【2026-11-02】标签全部装得下时把滚动箭头藏掉。
   SysTabControl32 在插入标签时若判定溢出就会创建并显示一对
   msctls_updown32，之后即使内边距收敛到能放下，它也不会自己收回去 ——
   表现为标签都看得见、右端却仍挂着 ◀ ▶。这里按实测结果显式同步。 */
static void FeTabSyncArrows(HWND hWnd, BOOL fits)
{
    HWND child = GetWindow(hWnd, GW_CHILD);
    while (child) {
        char cls[64];
        if (GetClassNameA(child, cls, sizeof(cls))
            && _stricmp(cls, "msctls_updown32") == 0) {
            ShowWindow(child, fits ? SW_HIDE : SW_SHOW);
        }
        child = GetWindow(child, GW_HWNDNEXT);
    }
}

/* 【2026-11-02】按控件实际宽度收紧标签内边距，避免 SysTabControl32 挂出
   滚动箭头把末尾标签挤出可视区。返回最终使用的内边距（1..6）。 */
static int FeTabFitPadding(HWND hWnd)
{
    RECT cli;
    int n, i, pad, lastRight;

    GetClientRect(hWnd, &cli);
    n = TabCtrl_GetItemCount(hWnd);
    if (n <= 0 || cli.right <= 0)
        return 6;

    for (pad = 6; pad > 1; pad--) {
        SendMessageA(hWnd, TCM_SETPADDING, 0, MAKELPARAM(pad, 2));
        lastRight = 0;
        for (i = 0; i < n; i++) {
            RECT r;
            if (TabCtrl_GetItemRect(hWnd, i, &r))
                lastRight = r.right;
        }
        if (lastRight <= cli.right)
            break;
    }
    FeTabSyncArrows(hWnd, lastRight > 0 && lastRight <= cli.right);
    return pad;
}

/* 【2026-11-02】在子类 WM_PAINT 里接管 Tab 标签绘制。
   保住控件自己的布局计算（TCM_GETITEMRECT 给出按文字自适应的矩形），
   只替换配色：未选中用主题底色 + 正常文字，选中用面板色 + 高亮文字，
   悬停用表头色。选中项下沿再画一条主题色细线做视觉锚点。 */
static void FeTabPaint(HWND hWnd)
{
    const FE_THEME_COLORS *C = FeThemeColors();
    HBRUSH bgBr = FeThemeBgBrush();
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hWnd, &ps);
    RECT cli, rc;
    POINT pt;
    BOOL hasPt;
    int n, i, sel, cliRight, cliBottom;

    GetClientRect(hWnd, &cli);
    cliRight = cli.right;
    cliBottom = cli.bottom;

    /* 【2026-11-02】标签由我们全权绘制，滚动箭头会让右端少画一块、
       并且它本身是浅色的，在深色条上很扎眼。既然所有标签都能放下
       （FeTabFitPadding 已收敛过内边距），这里每次绘制都确保它隐藏。 */
    FeTabSyncArrows(hWnd, TRUE);

    FillRect(dc, &cli, bgBr);

    /* 点是否在控件内：用来给悬停标签一个可见反馈。 */
    hasPt = GetCursorPos(&pt) && ScreenToClient(hWnd, &pt);

    n = TabCtrl_GetItemCount(hWnd);
    sel = TabCtrl_GetCurSel(hWnd);
    SetBkMode(dc, TRANSPARENT);

    for (i = 0; i < n; i++) {
        RECT tr;
        COLORREF face, text;
        HBRUSH br;
        HGDIOBJ oldFont = NULL;
        char buf[128];
        TCITEMA it;

        if (!TabCtrl_GetItemRect(hWnd, i, &tr))
            continue;
        /* 滚动/裁剪：只画落在客户区内的部分 */
        if (tr.left >= cliRight)
            continue;
        if (tr.right > cliRight)
            tr.right = cliRight;
        if (tr.bottom > cliBottom)
            tr.bottom = cliBottom;

        rc = tr;
        if (i == sel) {
            face = C->Panel;
            text = C->SelectText;
        } else if (hasPt && PtInRect(&tr, pt)) {
            face = C->Header;
            text = C->HeaderText;
        } else {
            face = C->Bg;
            text = C->Text;
        }

        br = CreateSolidBrush(face);
        FillRect(dc, &rc, br);
        DeleteObject(br);

        /* 选中项下沿画一条主题色细线，弥补没有立体边框的观感。 */
        if (i == sel) {
            RECT line = { rc.left + 2, rc.bottom - 2, rc.right - 2, rc.bottom };
            HBRUSH lb = CreateSolidBrush(C->Select);
            FillRect(dc, &line, lb);
            DeleteObject(lb);
        }

        ZeroMemory(&it, sizeof(it));
        it.mask = TCIF_TEXT;
        it.pszText = buf;
        it.cchTextMax = (int)sizeof(buf);
        if (!SendMessageA(hWnd, TCM_GETITEMA, (WPARAM)i, (LPARAM)&it))
            continue;

        SetTextColor(dc, text);
        oldFont = SelectObject(dc,
                               (HGDIOBJ)SendMessageA(hWnd, WM_GETFONT, 0, 0));
        {
            RECT tx = rc;
            tx.left += 3;
            tx.right -= 3;
            DrawTextA(dc, buf, -1, &tx,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        if (oldFont)
            SelectObject(dc, oldFont);
    }

    EndPaint(hWnd, &ps);
}

static LRESULT CALLBACK FeTabSubclass(HWND hWnd, UINT msg, WPARAM wParam,
                                      LPARAM lParam, UINT_PTR id,
                                      DWORD_PTR refData)
{
    static BOOL s_inFit = FALSE;

    if (msg == WM_ERASEBKGND) {
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect((HDC)wParam, &rc, FeThemeBgBrush());
        return 1;
    }
    if (msg == WM_PAINT) {
        FeTabPaint(hWnd);
        return 0;
    }
    if (msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_MOUSEMOVE
        || msg == WM_MOUSELEAVE) {
        /* 交给系统处理（选中切换、hot 追踪），然后重画。
           必须先转发：选中项由控件的默认过程更新。 */
        LRESULT r = DefSubclassProc(hWnd, msg, wParam, lParam);
        if (msg == WM_MOUSEMOVE) {
            TRACKMOUSEEVENT tme;
            ZeroMemory(&tme, sizeof(tme));
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hWnd;
            TrackMouseEvent(&tme);
        }
        InvalidateRect(hWnd, NULL, FALSE);
        return r;
    }
    /* 【2026-11-02 修子 Tab 溢出/滚动箭头】
       标签按创建时的字体和文本宽度累加，一旦超过控件宽度，SysTabControl32
       会挂出一对 msctls_updown32 箭头，末尾标签被推出可视区（Kernel 页 14 个
       子 Tab、主 Tab 栏 14 项都会这样）。这里在控件拿到实际宽度后自己量一遍：
       从默认内边距开始逐步收紧到 1px，直到最后一项的右边界落进客户区；
       只有确实放不下才保留滚动箭头。

       必须在本进程内做 —— TCM_GETITEMRECT 传的是 RECT 指针，
       USER32 不对该消息做跨进程编组，外部脚本读回来永远是全 0。

       s_inFit 防止 TCM_SETPADDING 再次触发 WM_SIZE 造成递归。 */
    if (msg == WM_SIZE) {
        LRESULT r = DefSubclassProc(hWnd, msg, wParam, lParam);
        if (!s_inFit) {
            s_inFit = TRUE;
            FeTabFitPadding(hWnd);
            s_inFit = FALSE;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        return r;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

void FeThemeSubclassTab(HWND hTabs)
{
    if (!hTabs)
        return;
    SetWindowSubclass(hTabs, FeTabSubclass, 2, 0);
    /* 父窗口 WM_SIZE 里的顺序是 MoveWindow 之后再调本函数，
       所以 Tab 的 WM_SIZE 早就发过了 —— 挂上子类时补做一次内边距收敛，
       否则要等下一次窗口缩放才会生效。 */
    FeTabFitPadding(hTabs);
    InvalidateRect(hTabs, NULL, TRUE);
}
