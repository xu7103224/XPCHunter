/* ============================================================================
 * XpchInjTarget.c —— 注入测试 DLL（无导入依赖版）
 *
 * 不调用任何 Win32 API：DllMain 把基址写入 PEB->ProcessParameters 之外的
 * 一块自留内存不可行，因此改为纯计算 + 返回，供上层用「进程是否存活 +
 * 后续读内存验证」判断执行结果。
 *
 * 同时提供 g_Set 导出：DllMain 会把魔法值写进自身的 .data，
 * 测试端经 0x023 读回该值即可确认 DllMain 真的执行了。
 * ==========================================================================*/
#include <windows.h>

/* 可被外部读取的标记（位于 .data 段） */
volatile unsigned __int64 g_XpchInjected = 0;
volatile unsigned long    g_XpchPid = 0;

BOOL WINAPI DllMain(HINSTANCE Inst, DWORD Reason, LPVOID Reserved)
{
    (void)Inst;
    (void)Reserved;
    if (Reason == DLL_PROCESS_ATTACH) {
        g_XpchInjected = 0x58504348494E4A31ULL;   /* "XPCHINJ1" */
        g_XpchPid = (unsigned long)(ULONG_PTR)&g_XpchPid;  /* 差异化哨兵 */
    }
    return TRUE;
}