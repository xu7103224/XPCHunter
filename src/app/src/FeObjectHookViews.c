// ============================================================================
// FeObjectHookViews.c — 对象类型钩子视图（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.3 的 CObjectTypeHookDialog。
//
// 驱动侧命令 0xFF (Table[223] = CmdEnumObjectTypeTable)
// → EnumObjectTypeTableOperation 已完整实现（Operation.c:1009）。
//
// 输出布局（驱动源码实测）：
//   +0x00  DWORD  条目总数
//   +0x04  (padding)
//   +0x08  起为条目区，每条 24 字节：
//            +0  QWORD  对象类型索引（0 表示类型头）
//            +8  QWORD  对象指针（类型节点 / 条目地址）
//            +16 QWORD  值（类型名指针 / 条目内容）
//   驱动要求 OutputSize >= 0x30。
//
// 判定"钩子"的方式与原版一致：同一条目在链表里出现多次说明指针被重定向；
// 本实现列出每个对象类型的条目数与可疑项（同一类型下多条指向不同地址）。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBJHOOK_MAX_ENTRIES  4096
#define OBJHOOK_BUF_SIZE     0x20000

typedef struct _OBJHOOK_ENTRY {
    ULONG   TypeIndex;
    ULONG64 ObjectPtr;
    ULONG64 Value;
} OBJHOOK_ENTRY;

static OBJHOOK_ENTRY *g_ObjHookItems = NULL;
static ULONG g_ObjHookCount = 0;
static ULONG g_ObjHookTypes = 0;
static char  g_ObjHookStatus[512];

/* 发 0xFF 取对象类型表。返回条目数（0 表示失败）。 */
ULONG FeLoadObjectTypeHooks(XPCH_CLIENT *Client)
{
    BYTE *out;
    UCHAR res = 0;
    BOOL ok;
    DWORD total, i, n;
    BYTE dummy = 0;

    if (g_ObjHookItems) {
        free(g_ObjHookItems);
        g_ObjHookItems = NULL;
    }
    g_ObjHookCount = 0;
    g_ObjHookTypes = 0;
    g_ObjHookStatus[0] = 0;

    if (!Client || !Client->Opened) {
        sprintf_s(g_ObjHookStatus, sizeof(g_ObjHookStatus),
                  "ObjectTypeHook: driver not connected");
        return 0;
    }

    /* 驱动要求 OutputSize >= 0x30；用 0x20000 容纳尽量多的条目。
       注意调用约定：处理器的第 3 参（pOutputBuffer）来自 XPCH_REQUEST 的
       OutPtr，即 XpchInvoke 的 Out 参数。 */
    out = (BYTE *)calloc(1, OBJHOOK_BUF_SIZE);
    if (!out)
        return 0;

    ok = XpchInvoke(Client, 0xFF, &dummy, 1, out, OBJHOOK_BUF_SIZE, &res);
    if (!ok || res == 0) {
        sprintf_s(g_ObjHookStatus, sizeof(g_ObjHookStatus),
                  "ObjectTypeHook: 0xFF rejected (result=%u)", (unsigned)res);
        free(out);
        return 0;
    }

    total = *(DWORD *)out;
    if (total == 0) {
        sprintf_s(g_ObjHookStatus, sizeof(g_ObjHookStatus),
                  "ObjectTypeHook: driver returned 0 entries (kernel memory "
                  "context may not be initialized)");
        free(out);
        return 0;
    }

    /* 条目区从 +8 开始，每条 24 字节 */
    n = total;
    if (n > OBJHOOK_MAX_ENTRIES)
        n = OBJHOOK_MAX_ENTRIES;
    /* 防止驱动给的 total 超过缓冲区实际容量 */
    {
        DWORD cap = (OBJHOOK_BUF_SIZE - 8) / 24;
        if (n > cap)
            n = cap;
    }

    g_ObjHookItems = (OBJHOOK_ENTRY *)calloc(n, sizeof(OBJHOOK_ENTRY));
    if (!g_ObjHookItems) {
        free(out);
        return 0;
    }
    for (i = 0; i < n; i++) {
        BYTE *p = out + 8 + i * 24;
        g_ObjHookItems[i].TypeIndex = *(ULONG *)p;
        g_ObjHookItems[i].ObjectPtr = *(ULONG64 *)(p + 8);
        g_ObjHookItems[i].Value     = *(ULONG64 *)(p + 16);
        if (g_ObjHookItems[i].TypeIndex == 0)
            g_ObjHookTypes++;
    }
    g_ObjHookCount = n;
    free(out);

    sprintf_s(g_ObjHookStatus, sizeof(g_ObjHookStatus),
              "ObjectTypeHook: %lu entries across %lu type node(s)",
              g_ObjHookCount, g_ObjHookTypes);
    return g_ObjHookCount;
}

BOOL FeObjectHookGet(ULONG Index, ULONG *TypeIndex, ULONG64 *ObjectPtr, ULONG64 *Value)
{
    if (!g_ObjHookItems || Index >= g_ObjHookCount)
        return FALSE;
    if (TypeIndex) *TypeIndex = g_ObjHookItems[Index].TypeIndex;
    if (ObjectPtr) *ObjectPtr = g_ObjHookItems[Index].ObjectPtr;
    if (Value) *Value = g_ObjHookItems[Index].Value;
    return TRUE;
}

const char *FeObjectHookStatus(void)
{
    return g_ObjHookStatus;
}

ULONG FeObjectHookTypeCount(void)
{
    return g_ObjHookTypes;
}

void FeObjectHookFree(void)
{
    if (g_ObjHookItems) {
        free(g_ObjHookItems);
        g_ObjHookItems = NULL;
    }
    g_ObjHookCount = 0;
    g_ObjHookTypes = 0;
}