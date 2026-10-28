// ============================================================================
// FeDpi.h — 第三步（表现层）：Per-Monitor DPI 支持
//
// 设计：
//   - 所有像素常量走 FeDpiScale()（以 96 DPI 为基准），布局代码不再硬编码绝对值；
//   - 窗口响应 WM_DPICHANGED：按系统建议矩形调整窗口，并重算布局；
//   - 通过应用清单声明 PerMonitorV2，系统才会给 WM_DPICHANGED。
//
// 与 CLI 无关：CLI 路径不创建窗口、不调本模块。
// ============================================================================
#ifndef XPCH_FEDPI_H
#define XPCH_FEDPI_H

#include "XPCHunterUM.h"

/* 初始化：查询当前窗口所在显示器的 DPI（无窗口时用系统 DPI） */
void FeDpiInit(HWND hWnd);

/* 响应 WM_DPICHANGED：更新 DPI 并按建议矩形调整窗口 */
void FeDpiOnChanged(HWND hWnd, WPARAM wParam, LPARAM lParam);

/* 96 DPI 基准值 → 当前 DPI 的像素值 */
int FeDpiScale(int Value96);

/* 当前 DPI（默认 96） */
UINT FeDpiCurrent(void);

#endif /* XPCH_FEDPI_H */