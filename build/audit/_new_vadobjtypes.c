// ScanProcessVadForObjectTypes — 枚举进程并对匹配目标对象类型的进程扫描其 VAD 内存
// 对应原始驱动 0x14008A278（383 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整），按伪代码 1:1 转写。
//   该函数是 _FINAL_GAP.json 的 D_need_review（源码中此前完全缺失）。
// 【功能】分配 0x44610 字节缓冲 → 调 EnumProcessInformationWorker 取进程列表 →
//   逐个进程用"对象类型校验函数"验证（自身、+CallbackField76+7）、且
//   *(QWORD*)(proc + CallbackField76) 非零 → 在已输出条目中查重（按 proc 地址，
//   步长 4 qword 向前回扫，计数 pEntryCount）→ 未重复则调 ScanProcessVadMemory
//   继续扫描；其返回 0 则中断循环。最后释放缓冲。
void __fastcall ScanProcessVadForObjectTypes(_OWORD *OutputBuffer,
                                            int *pEntryCount,
                                            int MaxEntries)
{
    _OWORD *pOutputPos;
    UCHAR (__fastcall *pCheckObjectTypeFunc)(ULONG64);
    __int64 *pObjectTypeInfo;
    ULONG   EprocessField30;
    ULONG64 CallbackField76;
    ULONG64 *ProcessInfoBuffer;
    ULONG   ProcessCount;
    ULONG   ProcessIndex;
    ULONG64 *pEntry;
    ULONG64 ProcAddr;
    char    CtxByte[8];
    __int64 v19, v20;
    _OWORD *OutputCursor;
    int    *pCount;
    int     Max;

    (void)MaxEntries;
    OutputCursor = OutputBuffer;
    pCount = pEntryCount;
    Max = MaxEntries;

    pOutputPos = OutputBuffer;
    pCheckObjectTypeFunc = (UCHAR (__fastcall *)(ULONG64))GtRead(GtObjectTypeCheckFlag);
    if (!pCheckObjectTypeFunc)                                              // 0x14008A2AA
        return;

    pObjectTypeInfo = (__int64 *)GtRead(GtObjectTypeInfoPtr);               // 0x14008A2BF
    EprocessField30 = (ULONG)GtRead(GtEprocessField30);                      // 0x14008A2CC
    CallbackField76 = (ULONG64)GtRead(GtCallbackField76);                    // 0x14008A2CF

    if (!pObjectTypeInfo)                                                   // 0x14008A2DF
        return;
    if (EprocessField30 == 0xFFFFFFFF)                                      // 0x14008A2E8
        return;
    if ((ULONG)CallbackField76 == 0)                                        // 0x14008A2F0
        return;

    ProcessInfoBuffer = (ULONG64 *)ExAlloc(1 /*PagedPool*/, 0x44610);       // 0x14008A302
    if (!ProcessInfoBuffer)                                                 // 0x14008A312
        return;

    v20 = *pObjectTypeInfo;                                                 // 0x14008A320
    v19 = *(ULONG64 *)(EprocessField30 + v20);                              // 0x14008A32E
    CtxByte[0] = 1;                                                          // 0x14008A336

    if (EnumProcessInformationWorker(CtxByte, (__int64)ProcessInfoBuffer, 0x44610))  // 0x14008A33B
    {
        ProcessCount = *((ULONG *)ProcessInfoBuffer + 4);                    // 0x14008A348
        ProcessIndex = 0;
        if (ProcessCount)                                                    // 0x14008A351
        {
            ULONG64 *p = ProcessInfoBuffer + 4;                              // 0x14008A357
            ULONG64 Step = CallbackField76;                                  // 0x14008A35B

            do
            {
                ProcAddr = *p;                                               // 0x14008A363
                if (pCheckObjectTypeFunc(ProcAddr) == 1                      // 0x14008A380
                    && pCheckObjectTypeFunc(ProcAddr + Step + 7) == 1
                    && *(ULONG64 *)(ProcAddr + Step) != 0)
                {
                    ULONG64 *cur = (ULONG64 *)pOutputPos - 2;                // 0x14008A38F
                    int cnt = *pCount;                                       // 0x14008A393
                    if (cnt)
                    {
                        // 已在输出中的进程跳过（步长 4 qword 向前回扫）
                        while (*cur != ProcAddr)                             // 0x14008A39D
                        {
                            cur -= 4;                                        // 0x14008A39F
                            if (--cnt == 0)                                  // 0x14008A3A5
                                goto L_DO_SCAN;
                        }
                    }
                    else
                    {
                    L_DO_SCAN:                                               // 0x14008A3C4
                        if (!ScanProcessVadMemory(ProcAddr, &OutputCursor, (_DWORD *)pCount))
                            break;                                           // 0x14008A3C4
                        pOutputPos = OutputCursor;                           // 0x14008A3C6
                    }
                }
                ++ProcessIndex;                                              // 0x14008A3CE
                p += 7;                                                      // 0x14008A3D0
            } while (ProcessIndex < ProcessCount);                           // 0x14008A3D7
        }
    }

    ExFree(ProcessInfoBuffer);                                               // 0x14008A3E1
    (void)v19; (void)Max;
}