// ============================================================================
// FeTheme.h — 第三步（表现层）主题：集中配色 + 控件着色 + 状态色
//
// 设计原则：
//   - 颜色只在这一处定义，视图代码不出现字面量色值；
//   - 主题可切换（深色/浅色），切换后 InvalidateRect 全程重绘；
//   - 与 CLI 完全无关：所有 CLI 路径都不碰 UI 颜色，46 条比对不受影响。
// ============================================================================
#ifndef XPCH_FETHEME_H
#define XPCH_FETHEME_H

#include "XPCHunterUM.h"
#include <commctrl.h>

typedef struct _FE_THEME_COLORS {
    COLORREF Bg;            /* 窗口底色 */
    COLORREF Panel;         /* 控件区底色（列表/编辑框） */
    COLORREF Text;          /* 主文本 */
    COLORREF TextDim;       /* 次要文本（状态行提示） */
    COLORREF Header;        /* 列表表头底 */
    COLORREF HeaderText;    /* 列表表头文字 */
    COLORREF Select;        /* 选中行底 */
    COLORREF SelectText;    /* 选中行文字 */
    COLORREF Grid;          /* 网格线 */
    COLORREF Accent;        /* 强调色（可访问 / 正常） */
    COLORREF Warn;          /* 警告（可疑） */
    COLORREF Danger;        /* 危险（隐藏/不可访问/被改） */
} FE_THEME_COLORS;

/* 主题切换 */
void FeThemeSetDark(BOOL Dark);
BOOL FeThemeIsDark(void);

/* 取当前调色板 */
const FE_THEME_COLORS *FeThemeColors(void);

/* 供 WndProc 使用：按控件类别返回画刷（静态缓存，勿 delete） */
HBRUSH FeThemeBgBrush(void);
HBRUSH FeThemePanelBrush(void);

/* 状态文本 → 语义色（accessible/clean → Accent，INACCESSIBLE/hidden/FAILED → Danger，
   可疑/blocked → Warn，其它 → Text） */
COLORREF FeThemeStatusColor(const char *Text);

/* 列表自绘挂载：给 ListView 启用 custom draw 所需的扩展样式。
   实际绘制在 WndProc 的 NM_CUSTOMDRAW 分支里（见 FeThemeDrawListViewItem）。 */
void FeThemeApplyToList(HWND hList);
BOOL FeThemeDrawListViewItem(NMLVCUSTOMDRAW *cd);
/* 表头自绘（表头是独立 SysHeader32 子窗口，只能靠 custom draw 上色） */
BOOL FeThemeDrawHeader(HDC hdc, LPNMCUSTOMDRAW cd, BOOL *NeedItemDraw);
/* 表头子类化：SysHeader32 的 NM_CUSTOMDRAW 不冒泡到父窗口，必须直接子类化 */
void FeThemeSubclassHeader(HWND hList);
/* Tab 控件子类化（标签区系统绘制，需要背景接管） */
void FeThemeSubclassTab(HWND hTabs);

/* ---- 状态图标列 ----
   图标在运行时用 GDI 生成（16x16 实心圆点），不依赖外部资源文件：
     0 = Accent 绿（正常）  1 = Danger 红（异常）  2 = Warn 黄（可疑）
     3 = Text 灰（其它）
   FeThemeAttachIcons 给列表挂 IMAGELIST + LVS_EX_SUBITEMIMAGES；
   FeThemeStatusIconIndex 是纯函数（供自检断言）。 */
void FeThemeAttachIcons(HWND hList);
int  FeThemeStatusIconIndex(const char *Text);
HIMAGELIST FeThemeIconList(void);

/* 整个窗口链重绘（切主题/改 DPI 后调用） */
void FeThemeRefreshWindow(HWND hWnd);

#endif /* XPCH_FETHEME_H */