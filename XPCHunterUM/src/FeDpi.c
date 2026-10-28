// ============================================================================
// FeDpi.c — Per-Monitor DPI：缩放基准与窗口切换
// ============================================================================
#include "FeDpi.h"
#include <windows.h>

static UINT g_Dpi = 96;

/* GetDpiForWindow 是 Win10 1607+ 的 API；这里动态取，避免在旧系统上无法加载。 */
typedef UINT (WINAPI *PFN_GetDpiForWindow)(HWND);

static PFN_GetDpiForWindow FeLoadGetDpiForWindow(void)
{
    static PFN_GetDpiForWindow fn = NULL;
    static BOOL tried = FALSE;

    if (!tried) {
        HMODULE hUser = GetModuleHandleA("user32.dll");
        tried = TRUE;
        if (hUser)
            fn = (PFN_GetDpiForWindow)(void *)GetProcAddress(hUser, "GetDpiForWindow");
    }
    return fn;
}

void FeDpiInit(HWND hWnd)
{
    PFN_GetDpiForWindow pfn = FeLoadGetDpiForWindow();

    if (pfn && hWnd) {
        UINT d = pfn(hWnd);
        if (d >= 48 && d <= 768)
            g_Dpi = d;
    }
}

void FeDpiOnChanged(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    RECT *rc = (RECT *)lParam;
    UINT newDpi = HIWORD(wParam);

    if (newDpi >= 48 && newDpi <= 768)
        g_Dpi = newDpi;

    /* 按系统建议矩形调整窗口（这是 Per-Monitor V2 的标准做法：
       让窗口在 DPI 切换后保持相同的物理尺寸观感）。 */
    if (rc)
        SetWindowPos(hWnd, NULL, rc->left, rc->top,
                     rc->right - rc->left, rc->bottom - rc->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);

    /* 重算布局：WM_SIZE 会走一遍完整的控件摆放，这里的尺寸变化足以触发 */
    {
        RECT client;
        GetClientRect(hWnd, &client);
        SendMessageA(hWnd, WM_SIZE, SIZE_RESTORED,
                     MAKELPARAM(client.right, client.bottom));
    }
    InvalidateRect(hWnd, NULL, TRUE);
}

int FeDpiScale(int Value96)
{
    if (g_Dpi == 96)
        return Value96;
    /* 四舍五入，避免 1px 累积误差 */
    return (Value96 * (int)g_Dpi + 48) / 96;
}

UINT FeDpiCurrent(void)
{
    return g_Dpi;
}