// EnumProcessObjectTypes — 枚举进程对象类型表，逐类型遍历对象链并扫描 VAD 树
// 对应原始驱动 0x1400892A0（1346 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
// 【原型】原始是可变参（表, 类型数, 输出缓冲, 计数指针, 上限）；此处按实际用到的
//   5 个具名参数给出，与调用点 DispatchEnumObjectTypes 的实参一一对应。
// 【说明】原始在每个"候选对象"处都用同一段 inline 查重（输出游标 -2 起、步长 4 qword
//   向前回扫计数次），此处抽成文件内静态辅助 `VadEntryAlreadyStored` ——
//   它是对**同一段原始指令**的忠实提取（不含任何原始没有的语义），仅消除重复书写。
static BOOL VadEntryAlreadyStored(const int *pEntryCount, _OWORD *pOutputStart, ULONG64 Value)
{
    int     n = *pEntryCount;
    _OWORD *cur = pOutputStart - 2;
    while (n)
    {
        if (*(ULONG64 *)cur == Value)
            return TRUE;
        cur -= 4;
        if (--n == 0)
            break;
    }
    return FALSE;
}

void __fastcall EnumProcessObjectTypes(_QWORD *pObjectTypeTable, unsigned int ObjectTypeCount,
                                       _OWORD *OutputBuffer, int *pEntryCount, int MaxEntries)
{
    UCHAR (__fastcall *pCheck)(ULONG64);
    ULONG   ObjectTypeCheckBase;
    ULONG   Build;
    ULONG   TypeIndex;

    pCheck = (UCHAR (__fastcall *)(ULONG64))GtRead(GtObjectTypeCheckFlag);   // 0x1400892D5
    ObjectTypeCheckBase = (ULONG)GtRead(GtCallbackField74);                  // 0x1400892DC

    if (!pCheck || !ObjectTypeCheckBase || !pObjectTypeTable                  // 0x140089301
        || pCheck((ULONG64)pObjectTypeTable) == 0)
        return;

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                             // 0x14008931E

    if (Build >= 0x23F0)
    {
        if (Build == 9200)                                                   // 0x1400893D3
        {
            for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)    // 0x1400893CF
            {
                _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[10 * (ULONG64)TypeIndex + 1];
                ULONG    guard = 0;
                _QWORD   *pObj = *pSlot;

                while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                       && MaxEntries && guard <= 0x10000)                    // 0x140089418
                {
                    ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;      // 0x140089427
                    if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                    {
                        if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                               &OutputBuffer, (_DWORD *)pEntryCount))
                        {
                            TypeIndex = ObjectTypeCount;                     // 0x140089464
                            break;
                        }
                    }
                    pObj = (_QWORD *)*pObj;                                  // 0x140089457
                    ++guard;
                }
                if (ObjectTypeCount == TypeIndex)                            // 0x140089468
                    break;
            }
        }
        else
        {
            for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)    // 0x14008947F
            {
                _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[88 * (ULONG64)TypeIndex + 1];
                ULONG    guard = 0;
                _QWORD   *pObj = *pSlot;

                while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                       && MaxEntries && guard <= 0x10000)                    // 0x1400894BD
                {
                    ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;      // 0x1400894CC
                    if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                    {
                        if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                               &OutputBuffer, (_DWORD *)pEntryCount))
                        {
                            TypeIndex = ObjectTypeCount;                     // 0x140089509
                            break;
                        }
                    }
                    pObj = (_QWORD *)*pObj;                                  // 0x1400894FC
                    ++guard;
                }
                if (ObjectTypeCount == TypeIndex)                            // 0x14008950D
                    break;
            }
        }
    }
    else
    {
        for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)        // 0x140089328
        {
            _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[11 * (ULONG64)TypeIndex + 1];
            ULONG    guard = 0;
            _QWORD   *pObj = *pSlot;

            while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                   && MaxEntries && guard <= 0x10000)                        // 0x140089363
            {
                ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;          // 0x140089372
                if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                {
                    if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                           &OutputBuffer, (_DWORD *)pEntryCount))
                    {
                        TypeIndex = ObjectTypeCount;                         // 0x1400893AF
                        break;
                    }
                }
                pObj = (_QWORD *)*pObj;                                      // 0x1400893A2
                ++guard;
            }
            if (ObjectTypeCount == TypeIndex)                                // 0x1400893B3
                break;
        }
    }

    /* ---- 第二段：由进程列表反查类型槽 → 类型下标（0x140089528 起） ---- */
    {
        __int64 *pTypeInfo = (__int64 *)GtRead(GtObjectTypeInfoPtr);         // 0x140089528
        ULONG    EprocF30  = (ULONG)GtRead(GtEprocessField30);               // 0x140089535
        ULONG    CbF76     = (ULONG)GtRead(GtCallbackField76);               // 0x140089538
        ULONG64  Step      = CbF76;
        ULONG64 *ProcBuf;
        ULONG    ProcCount, ProcIdx;
        char     Ctx[8];

        if (!pTypeInfo) return;                                              // 0x140089544
        if (EprocF30 == 0xFFFFFFFF) return;                                  // 0x14008954D
        if (Step == 0) return;                                               // 0x140089555

        ProcBuf = (ULONG64 *)ExAlloc(1 /*PagedPool*/, 0x44610);              // 0x140089569
        if (!ProcBuf) return;

        Ctx[0] = 1;                                                          // 0x140089599
        if (EnumProcessInformationWorker(Ctx, (__int64)ProcBuf, 0x44610))     // 0x14008959D
        {
            ProcCount = *((ULONG *)ProcBuf + 4);                              // 0x1400895AA
            ProcIdx = 0;
            if (ProcCount)
            {
                ULONG64 *p = ProcBuf + 4;                                     // 0x1400895BA
                for (;;)
                {
                    ULONG64 ProcAddr = *p;                                    // 0x1400895C2

                    if (pCheck(ProcAddr) == 1                                 // 0x1400895E2
                        && pCheck(ProcAddr + Step + 7) == 1)
                    {
                        __int64 *SlotPtr = *(__int64 **)(Step + ProcAddr);    // 0x1400895E8
                        if (SlotPtr)                                          // 0x1400895EF
                        {
                            ULONG Inner = (ULONG)GtRead(GtWindowsBuildNumber);
                            int   TypeIdx = -1;

                            if (Inner >= 0x23F0)                              // 0x140089604
                            {
                                if (Inner == 9200)                            // 0x14008964E
                                {
                                    if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                    else if (SlotPtr == pObjectTypeTable + 10)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 20)      TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 30)      TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 40)      TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 50)      TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 60)      TypeIdx = 6;
                                }
                                else
                                {
                                    if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                    else if (SlotPtr == pObjectTypeTable + 88)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 176)     TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 264)     TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 352)     TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 440)     TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 528)     TypeIdx = 6;
                                    else if (SlotPtr == pObjectTypeTable + 90)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 180)     TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 270)     TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 360)     TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 450)     TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 540)     TypeIdx = 6;
                                }
                            }
                            else
                            {
                                if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                else if (SlotPtr == pObjectTypeTable + 11)      TypeIdx = 1;
                                else if (SlotPtr == pObjectTypeTable + 22)      TypeIdx = 2;
                            }

                            if (TypeIdx >= 0)                                 // LABEL_100
                            {
                                if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, ProcAddr))
                                {
                                    if (!ScanProcessVadTree(ProcAddr, TypeIdx,
                                                           &OutputBuffer, (_DWORD *)pEntryCount))
                                        goto L_DONE;                      // LABEL_105
                                }
                            }
                        }
                    }

                    ++ProcIdx;                                                // 0x1400897AE
                    p += 7;                                                   // 0x1400897B1
                    if (ProcIdx >= ProcCount)                                 // 0x1400897B8
                        break;
                }
            }
        }

    L_DONE:
        ExFree(ProcBuf);                                                      // 0x1400897C2
    }
}

// DispatchEnumObjectTypes — 取当前进程对象类型表并按构建号选择枚举量后分发
// 对应原始驱动 0x14008A3F8（189 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
void __fastcall DispatchEnumObjectTypes(__int64 OutputBuffer, __int64 pEntryCount, int MaxEntries)
{
    char   *CurrentFiber;
    int     FiberOffset;
    __int64 ProcessPtr;
    _QWORD *pObjectTypeTable;
    ULONG   Build;
    ULONG   EnumCount;

    CurrentFiber = (char *)j_GetCurrentFiber();                                  // 0x14008A41F
    FiberOffset = (int)GtRead((GLOBAL_TABLE_INDEX)(0x4000 | 0x01 | 0x100));      // Gt821|GtEprocessField02
    if (FiberOffset == -1)                                                       // 0x14008A42A
        return;

    ProcessPtr = *(ULONG64 *)&CurrentFiber[FiberOffset];                         // 0x14008A42F
    if (!ProcessPtr)                                                             // 0x14008A436
        return;

    pObjectTypeTable = (_QWORD *)(ProcessPtr + 192);                             // 0x14008A43D

    if ((ULONG)GtRead(GtWindowsBuildNumber) == 9600                              // 0x14008A46E
        && (ULONG64)pObjectTypeTable > (ULONG64)MmSystemRangeStart
        && ((ULONG64)pObjectTypeTable[2] <= (ULONG64)MmSystemRangeStart
            || (ULONG64)pObjectTypeTable[1] <= (ULONG64)MmSystemRangeStart
            || (ULONG64)*pObjectTypeTable >= (ULONG64)MmSystemRangeStart))
    {
        pObjectTypeTable = (_QWORD *)*pObjectTypeTable;                          // 0x14008A470
    }

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                                 // 0x14008A478
    EnumCount = 7;                                                               // 0x14008A48A
    if (Build != 9200)                                                           // 0x14008A494
        EnumCount = 1;

    EnumProcessObjectTypes(pObjectTypeTable, EnumCount,                           // 0x14008A49B
                           (_OWORD *)OutputBuffer, (int *)pEntryCount, MaxEntries);
}