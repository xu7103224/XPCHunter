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
   用子类化在 WM_ERASEBKGND 画底色，并靠自定义绘制覆盖标签头。 */
static LRESULT CALLBACK FeTabSubclass(HWND hWnd, UINT msg, WPARAM wParam,
                                      LPARAM lParam, UINT_PTR id,
                                      DWORD_PTR refData)
{
    if (msg == WM_ERASEBKGND) {
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect((HDC)wParam, &rc, FeThemeBgBrush());
        return 1;
    }
    if (msg == WM_PAINT) {
        /* Tab 的标签区在 WM_PAINT 里用系统色画。先刷主题底色，
           再让原过程画标签文字（文字仍是系统色，在深底上可读性尚可）。 */
        LRESULT r;
        RECT rc;
        HDC dc = GetDC(hWnd);
        GetClientRect(hWnd, &rc);
        FillRect(dc, &rc, FeThemeBgBrush());
        ReleaseDC(hWnd, dc);
        r = DefSubclassProc(hWnd, msg, wParam, lParam);
        return r;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

void FeThemeSubclassTab(HWND hTabs)
{
    if (!hTabs)
        return;
    SetWindowSubclass(hTabs, FeTabSubclass, 2, 0);
    InvalidateRect(hTabs, NULL, TRUE);
}
