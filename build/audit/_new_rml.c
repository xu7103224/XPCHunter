// RemoveFromModuleLinkedList — 从模块链表摘除节点
// 对应原始驱动 0x140045A38（212 字节）
// 【⚠ 修正记录 2026-10-13】原用宏组合 `GtDisableHookProtectionAddr2 |
//   GtEprocessField123`，原始实为**按 ListType 二选一**：
//   `mov ecx,0x89d; cmp dl,1; je +1; mov ecx,0x89c`（见 0x140045A56 / 0A60）
//   ——即 ListType==1 用 **0x89D**，否则用 **0x89C**。
// 【原始流程】
//   ① rdi = GT(0x89D 或 0x89C)；为空返回 0；
//   ② CheckMemoryValid(rdi) 须为 1；
//   ③ 从 *rdi 起遍历（上限 0x1000）：节点须 > MmSystemRangeStart 且
//      CheckMemoryValid(节点)==1；若 节点 == 目标(r14) 则找到；
//      否则 节点 = *(节点) 继续；
//   ④ 找到后：MmIsAddressValid(节点) 须为 1 → ObfDereferenceObject(目标[+0x10])
//      （即 "目标[0x10]" 是待解引用的对象）→ 双向摘链
//      （*(节点)[8] = 节点[1]；*(节点[1]) = *(节点)[0]）
//      → ExFreePoolWithTag(目标, 'IoRi' = 0x69526F49) → 返回 1。
// 【被调函数（由导入表 rip 目标解析）】
//   MmIsAddressValid ×3（0x14008D090）、ObfDereferenceObject（0x14008D088）、
//   ExFreePoolWithTag（0x14008D110）。
char RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    char    Result = 0;
    PVOID **pListHead;
    PVOID  *pCurrentNode;
    PVOID  *pPreviousNode;
    int     IterationCount;

    pListHead = (PVOID **)GtRead((GLOBAL_TABLE_INDEX)(ListType == 1 ? 0x89D : 0x89C));  // 0x140045A65
    if (!pListHead)                                                                    // 0x140045A6D
        return Result;
    if ((char)CheckMemoryValid(pListHead) != 1)                                        // 0x140045A75
        return Result;

    pCurrentNode = *pListHead;                                                         // 0x140045A7F
    IterationCount = 0;
    while (pCurrentNode != (PVOID *)pListHead)                                         // 0x140045AB1
    {
        if ((ULONG64)pCurrentNode <= *(ULONG64 *)MmSystemRangeStart)                   // 0x140045A8D
            return Result;
        if ((char)CheckMemoryValid(pCurrentNode) != 1)                                 // 0x140045A95
            return Result;
        if ((ULONG)++IterationCount > 0x1000)                                          // 0x140045AA1
            return Result;
        if (pCurrentNode == pTargetEntry)                                              // 0x140045AA9
            break;
        pCurrentNode = (PVOID *)*pCurrentNode;                                         // 0x140045AAE
    }
    if (pCurrentNode != pTargetEntry)
        return Result;

    /* 找到：先校验节点与目标[+0x10] */
    if (MmIsAddressValid((PVOID)*pCurrentNode) != 1)                                   // 0x140045ABB
        return Result;
    ObfDereferenceObject(pTargetEntry[2]);                                             // 0x140045AC9

    /* 双向摘链 */
    pPreviousNode = (PVOID *)pCurrentNode[0];                                          // 0x140045ACF
    {
        PVOID *pNext = (PVOID *)pCurrentNode[1];                                       // 0x140045AD2
        pPreviousNode[1] = pNext;                                                      // 0x140045AD6
        *pNext = pPreviousNode;                                                        // 0x140045ADA
    }

    /* 释放该条目（标签 'IoRi' = 0x69526F49 = 'IoRi'） */
    ExFreePoolWithTag(pTargetEntry, 0x69526F49);                                       // 0x140045AE5

    Result = 1;
    return Result;
}