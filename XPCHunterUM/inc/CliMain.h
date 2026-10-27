// ============================================================================
// CliMain.h — CLI 分发接口（由 frontend.c 机械拆分产出，2026-10-28）
// ============================================================================
#ifndef XPCH_CLIMAIN_H
#define XPCH_CLIMAIN_H

/* CLI 处理函数的哨兵返回值：
 *   FE_CLI_NEXT  本条命令行不匹配该处理器，继续走链
 *   FE_CLI_NONE  全链无命中，调用方（WinMain）落入 GUI 路径
 * 其余返回值 = 该 CLI 入口的进程退出码（与拆分前一致） */
#define FE_CLI_NEXT  (-2)
#define FE_CLI_NONE  (-1)

/* 按 frontend.c 原 WinMain if 链的源码顺序分发；返回退出码或 FE_CLI_NONE */
int FeCliDispatch(const char *lpCmdLine);

#endif /* XPCH_CLIMAIN_H */
