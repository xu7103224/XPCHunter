// ScanProcessVadMemory — 扫描目标进程的 VAD 内存，定位进程对象在 VAD 中的地址
// 对应原始驱动 0x1400897E4（2707 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整，含地址注释），
//   故按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 A_definite_missing，源码中此前完全缺失。
//
// 【功能】对给定进程对象：取 VAD 根与结束地址，按**构建号**选择对应的 VAD 条目
//   结构布局，在 VAD 表区间内扫描匹配该进程对象的条目，取出其中记录的地址；
//   若结果小于 MmSystemRangeStart 则置 0；把
//   { 进程对象, 创建时间, [VAD 中查得的地址], 0 } 写入输出缓冲并递增计数。
//
// 【构建号分档（自伪代码逐个 if 提取）】
//   10240 / 10586 / 14393  → VAD 项从 +0x50 起、每项 0xA0 字节（步长 20 qword）
//   15063                  → 步长 15 qword
//   16299 / 17134 / 17763 / 18362 / 18363 → 步长 15 qword，且按 16299/17134/17763/其余 细分
//   197xx（0x4A61..0x4A65）→ 步长 15 qword（与 20348 共用同一组判定）
//   20348                  → 步长 15 qword
//   22000 / 22621 / 22631  → 步长 15 qword
char __fastcall ScanProcessVadMemory(unsigned __int64 ObjectAddress,
                                     _OWORD **ppOutputBuffer,
                                     _DWORD *pEntryCount)
{
    __int64 FnGetProcess;        // GtEprocessField140|GtTotalSize|0x100 (0x4196)
    __int64 KernelSize;          // GtNtoskrnlImageSize
    __int64 MinAddressPtr;       // GtEprocessField104|GtTotalSize|0x100 (0x4168)
    __int64 ObjectTypeCheckBase; // GtObjectTypeCheckFlag
    ULONG   VadRootOffset;       // GtEprocessField191 (201)
    ULONG   VadTableOffset;      // GtEprocessField193 (203)
    ULONG   CreateTimeOffset;    // GtProcessCreateTime (60)
    __int64 KernelBase;          // GtNtoskrnlModuleBase
    UCHAR   Result;              // 返回标志
    ULONG64 FoundAddress;
    __int64 TargetProcess;       // _KPROCESS*
    ULONG64 VadEndAddress;       // *(QWORD*)(VadRootOffset + ObjectAddress)
    __int64 *VadRoot;            // *(QWORD*)(VadTableOffset + ObjectAddress)
    UCHAR   IsReferenced;
    ULONG64 MinAddress;
    ULONG   Build;
    __int128 OutStruct1;         // 输出槽 1（进程对象）
    __int128 OutStruct2;         // 输出槽 2（创建时间 + 地址）
    _KAPC_STATE ApcState;

    FnGetProcess        = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4196);   // 0x140089826
    KernelBase          = (__int64)GtRead(GtNtoskrnlModuleBase);         // 0x140089835
    KernelSize          = (__int64)GtRead(GtNtoskrnlImageSize);          // 0x140089842
    MinAddressPtr       = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4168);   // 0x14008984F
    ObjectTypeCheckBase = (__int64)GtRead(GtObjectTypeCheckFlag);        // 0x14008985E
    VadRootOffset       = (ULONG)GtRead(GtEprocessField191);             // 0x14008986B (201)
    VadTableOffset      = (ULONG)GtRead(GtEprocessField193);             // 0x140089878 (203)
    CreateTimeOffset    = (ULONG)GtRead(GtProcessCreateTime);            // 0x140089885 (60)

    if (!FnGetProcess || !KernelBase || !KernelSize || !MinAddressPtr      // 0x1400898D1
        || !ObjectTypeCheckBase || !VadRootOffset || !VadTableOffset
        || !CreateTimeOffset)
        return 0;

    Result = 1;
    if (!ObjectAddress || !ValidateKernelObject(ObjectAddress, 0, 0, 0))    // 0x1400898F4
        return Result;

    MinAddress = *(ULONG64 *)MinAddressPtr;                                 // [rbp-0xB8] 解引用

    OutStruct1 = ObjectAddress;                                             // 0x140089901
    OutStruct2 = *(ULONG64 *)(CreateTimeOffset + ObjectAddress);            // 0x14008990C（低 64 位）
    FoundAddress = 0;                                                       // 0x140089911
    ((ULONG *)&OutStruct2)[2] = 0;                                          // 0x140089919（DWORD2）

    TargetProcess = FnGetProcess(ObjectAddress);                            // 0x140089925
    IsReferenced = (UCHAR)ReferenceObjectSafe(TargetProcess);               // 0x140089930
    KeStackAttachProcess((void *)TargetProcess, &ApcState);                 // 0x14008993C

    if ((UCHAR)CheckProcessObjectFlag(ObjectAddress) == 1)                  // 0x14008994C
    {
        VadEndAddress = *(ULONG64 *)(VadRootOffset + ObjectAddress);        // 0x140089954
        VadRoot = (__int64 *)(*(ULONG64 *)(VadTableOffset + ObjectAddress)); // 0x14008995B

        if (CheckMemoryValid((void *)(VadEndAddress - 1)) == 1              // 0x140089985
            && CheckMemoryValid(VadRoot) == 1)
        {
            Build = (ULONG)GtRead(GtWindowsBuildNumber);

            if (Build == 10240 || Build == 10586 || Build == 14393)          // 0x1400899C4
            {
                __int64 *p = VadRoot + 10;                                  // 0x14008A0F4
                if ((ULONG64)p < VadEndAddress)                             // 0x14008A0FB
                {
                    while ((ULONG64)(p + 20) <= VadEndAddress)              // 0x14008A11D
                    {
                        __int64 tag = *(p - 1);                             // 0x14008A123
                        if (tag == 128)                                     // 0x14008A12A
                        {
                            if (ObjectAddress == (ULONG64)*p)               // 0x14008A132
                            {
                                ULONG64 v33 = p[1], v16;
                                if (v33 > (ULONG64)MmSystemRangeStart     // 0x14008A148
                                    && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart)
                                {
                                    v16 = p[3];                         // 0x14008A14E
                                    if (v16 > (ULONG64)MmSystemRangeStart
                                        && v33 > v16 && v33 - v16 < 0x1000)   // 0x14008A162
                                    {
                                        FoundAddress = v16;             // LABEL_45
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                ULONG64 v34 = p[2];                     // 0x14008A16A
                                if ((ULONG64)*p == v34)                 // 0x14008A171
                                {
                                    ULONG64 v35 = p[1], v36;
                                    if (v35 > (ULONG64)MmSystemRangeStart
                                        && v34 > (ULONG64)MmSystemRangeStart)  // 0x14008A182
                                    {
                                        v36 = p[3];                     // 0x14008A184
                                        if (v36 > (ULONG64)MmSystemRangeStart
                                            && v35 > v36 && v35 - v36 < 0x1000)  // 0x14008A198
                                        {
                                            FoundAddress = p[3];        // 0x14008A1DC
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            __int64 v37 = *p;                               // 0x14008A19C
                            if (ObjectAddress == (ULONG64)*p
                                && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart)  // 0x14008A1AB
                            {
                                ULONG64 v38 = p[2];                         // 0x14008A1AD
                                if (v38 > (ULONG64)MmSystemRangeStart)      // 0x14008A1B4
                                {
                                    ULONG64 v39 = p[3];                     // 0x14008A1B6
                                    if (v39 > (ULONG64)MmSystemRangeStart
                                        && (tag == (__int64)v39 || v37 == (__int64)v39)
                                        && v37 != (__int64)v38)             // 0x14008A1CC
                                    {
                                        FoundAddress = *(ULONG64 *)(p - 1); // 0x14008A1E1
                                        break;
                                    }
                                }
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                  // 0x14008A1D5
                            break;
                    }
                }
            }
            else if (Build == 15063)                                        // 0x1400899D7
            {
                __int64 *p = VadRoot + 10;                                  // 0x1400899DD
                if ((ULONG64)p < VadEndAddress)
                {
                    while ((ULONG64)(p + 15) <= VadEndAddress)              // 0x1400899FD
                    {
                        if (*p == 128)                                      // 0x140089A09
                        {
                            ULONG64 v16 = *(ULONG64 *)(p - 1);              // 0x140089A0B
                            if (v16 > (ULONG64)MmSystemRangeStart)          // 0x140089A15
                            {
                                ULONG64 v17 = *(ULONG64 *)(p - 2);          // 0x140089A17
                                if (v17 > (ULONG64)MmSystemRangeStart)      // 0x140089A1E
                                {
                                    __int64 v18 = p[1];                     // 0x140089A20
                                    if (v17 == (ULONG64)v18 && v18 == p[3]) // 0x140089A2D
                                    {
                                        ULONG64 v19 = p[2];                 // 0x140089A2F
                                        if (v19 > v16 && v19 - v16 < 0x200) // 0x140089A42
                                        {
                                            FoundAddress = v16;             // LABEL_45
                                            break;
                                        }
                                    }
                                }
                            }
                            if (v16 == 0                                        // 0x140089A6B
                                && *(ULONG64 *)(p - 2) == 0
                                && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                                && ObjectAddress == (ULONG64)p[2])
                            {
                                FoundAddress = v16;                         // LABEL_45
                                break;
                            }
                        }
                        if ((*p & 0xFFFFFFFFFFFFFF7FULL) == 0                   // 0x140089A86
                            && *(ULONG64 *)(p - 3) == 0
                            && *(ULONG64 *)(p - 2) == 0
                            && p[8] == 0)
                        {
                            __int64 v20 = p[3];                                 // 0x140089A8C
                            if (ObjectAddress == (ULONG64)v20                  // 0x140089AB4
                                && v20 == p[12]
                                && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[6] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[11] > (ULONG64)MmSystemRangeStart)
                            {
                                FoundAddress = p[11];                       // 0x140089AD0
                                break;
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                      // 0x140089ABD
                            break;
                    }
                }
            }
            else
            {
                goto L_OTHER_BUILDS;
            }

            goto L_STORE_RESULT;
        }

        Result = 1;
        goto L_EPILOGUE;
    }
    goto L_EPILOGUE;

L_OTHER_BUILDS:                                                             // 0x140089B32 起
    if (Build == 16299 || Build == 17134 || Build == 17763
        || Build == 18362 || Build == 18363)
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089DBD
        Result = 1;
        if ((ULONG64)p < VadEndAddress)                                     // 0x140089DC9
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089DDC
            {
                ULONG   Inner = (ULONG)GtRead(GtWindowsBuildNumber);        // 0x140089DF1
                if (Inner == 16299)                                         // 0x140089DF1
                {
                    __int64 v23 = *p;                                       // 0x140089DF7
                    if (ObjectAddress == (ULONG64)*p && ObjectAddress == (ULONG64)p[1])  // 0x140089E03
                    {
                        if (*(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart  // 0x140089E2F
                            && p[3] == 0 && p[4] == 0
                            && (ULONG64)p[5] > (ULONG64)MmSystemRangeStart
                            && p[6] == 128 && p[8] == 0)
                        {
                            ULONG64 v25 = p[10];                            // 0x140089E35
                            if (v25 == (ULONG64)p[12]                        // 0x140089E48
                                && v25 > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[11] > (ULONG64)MmSystemRangeStart)
                            {
                                FoundAddress = p[11];                       // LABEL_211 0x14008A0C7
                                goto L_STORE_RESULT;
                            }
                        }
                    }
                    if (v23 == 128)                                         // 0x140089E5C
                    {
                        if (*(ULONG64 *)(p - 2) == 0 && *(ULONG64 *)(p - 3) == 0)  // 0x140089E64
                        {
                            ULONG64 base = *(ULONG64 *)MmSystemRangeStart;  // v24 = *MmSystemRangeStart
                            if (base < (ULONG64)p[1] && ObjectAddress == (ULONG64)p[2]
                                && (ULONG64)p[3] > base && (ULONG64)p[4] > base)   // 0x140089E83
                            {
                                FoundAddress = p[11];                       // LABEL_211
                                goto L_STORE_RESULT;
                            }
                            if (base < (ULONG64)p[1] && (ULONG64)p[4] > base
                                && (ULONG64)p[5] > base && ObjectAddress == (ULONG64)p[6]
                                && (ULONG64)p[7] > base)                    // 0x140089EBB
                            {
                                FoundAddress = p[5];                        // 0x14008A0D0
                                goto L_STORE_RESULT;
                            }
                        }
                    }
                    if ((v23 & 0xFFFFFFFFFFFF00FFULL) == 0 && *(ULONG64 *)(p - 1) == 0)  // 0x140089ED1
                    {
                        ULONG64 base = *(ULONG64 *)MmSystemRangeStart;
                        if (*(ULONG64 *)(p - 4) > base && *(ULONG64 *)(p - 3) > base
                            && (ULONG64)p[1] > base)                        // 0x140089EF6
                        {
                            ULONG64 v29 = p[2];                             // 0x140089EFC
                            if (v29 > base && (ULONG64)p[3] > base
                                && ObjectAddress == (ULONG64)p[4]
                                && (ULONG64)p[5] > base)                    // 0x140089F21
                            {
                                ULONG64 v30 = p[6];                         // 0x140089F27
                                if (v30 > base && (ULONG64)p[7] > base
                                    && (ULONG64)p[8] > base && v29 == v30)  // 0x140089F4B
                                {
                                    FoundAddress = p[3];                    // LABEL_213
                                    goto L_STORE_RESULT;
                                }
                            }
                        }
                    }
                }
                else if (Inner == 17134)                                    // 0x140089F65
                {
                    if (ObjectAddress == (ULONG64)*p)                       // 0x140089F74
                    {
                        if ((ULONG64)p[1] > (ULONG64)MmSystemRangeStart     // 0x140089FC8
                            && (p[2] & 0xFFFFFFFFFFFF00FFULL) == 0
                            && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 3) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                            && p[8] == 0
                            && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart)
                        {
                            FoundAddress = *(ULONG64 *)(p - 1);             // LABEL_215 0x14008A0EB
                            goto L_STORE_RESULT;
                        }
                        if (ObjectAddress == (ULONG64)*p                     // 0x14008A023
                            && ObjectAddress == (ULONG64)p[2]
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                            && *((ULONG *)p - 2) == 1
                            && p[3] == 128
                            && p[6] == 0
                            && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart)
                        {
                            FoundAddress = p[4];                            // 0x14008A0E2
                            goto L_STORE_RESULT;
                        }
                    }
                }
                else if (Inner == 17763)                                    // 0x14008A03D
                {
                    if (ObjectAddress == (ULONG64)*p                        // 0x14008A078
                        && ObjectAddress == (ULONG64)p[2]
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                        && *((ULONG *)p - 2) == 1
                        && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 3) == 0
                        && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = p[3];                                // LABEL_213 0x14008A0D9
                        goto L_STORE_RESULT;
                    }
                }
                else                                                        // 18362/18363
                {
                    if (ObjectAddress == (ULONG64)*p                        // 0x14008A0B3
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 3) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 5) == 0
                        && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = *(ULONG64 *)(p - 1);                  // LABEL_215
                        goto L_STORE_RESULT;
                    }
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x14008A0BC
                    goto L_STORE_RESULT;
            }
        }
        goto L_STORE_RESULT;
    }
    else if (Build >= 0x4A61 && Build <= 0x4A65)                            // 0x140089B58
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089B5E
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089B79
            {
                if (ObjectAddress == (ULONG64)*p                            // 0x140089BE7
                    && (((ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 4) == 0 && *(ULONG64 *)(p - 6) == 0)
                        || (ObjectAddress == (ULONG64)*p
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                            && p[3] == 0
                            && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)))
                {
                    FoundAddress = p[1];                                    // LABEL_74 0x140089BFB
                    break;
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089BF0
                    break;
            }
        }
    }
    else if (Build == 20348)                                                // 0x140089C11
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089C17
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089C32
            {
                if (ObjectAddress == (ULONG64)*p                            // 0x140089CA0
                    && (((ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 4) == 0 && *(ULONG64 *)(p - 6) == 0)
                        || (ObjectAddress == (ULONG64)*p
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                            && p[3] == 0
                            && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)))
                {
                    FoundAddress = p[1];                                    // LABEL_74
                    break;
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089CAD
                    break;
            }
        }
    }
    else if (Build == 22000 || Build == 22621 || Build == 22631)            // 0x140089CE3
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089CE9
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089D04
            {
                if (ObjectAddress == (ULONG64)*p)                           // 0x140089D13
                {
                    if ((ULONG64)p[1] > (ULONG64)MmSystemRangeStart         // 0x140089D4E
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 4) == 0
                        && *(ULONG64 *)(p - 6) == 0
                        && (*(ULONG64 *)(p - 8) || *(ULONG64 *)(p - 9)
                            || *(ULONG64 *)(p - 10) || *(ULONG64 *)(p - 11)))
                    {
                        FoundAddress = *(ULONG64 *)(p - 3);                 // 0x140089DA2
                        Result = 1;
                        if (FoundAddress <= (ULONG64)MmSystemRangeStart)    // 0x140089DAE
                            FoundAddress = p[1];                            // 0x140089DB4
                        goto L_STORE_RESULT;
                    }
                    if (ObjectAddress == (ULONG64)*p                        // 0x140089D8A
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                        && p[3] == 0
                        && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 4) == 0
                        && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = p[1];                                // LABEL_74
                        break;
                    }
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089D97
                    break;
            }
        }
    }

L_STORE_RESULT:
    Result = 1;                                                             // 0x14008A1E4
    if (FoundAddress < MinAddress)                                          // 0x14008A1F6
        FoundAddress = 0;
    *((ULONG64 *)&OutStruct2 + 1) = FoundAddress;                           // 0x14008A1FA

L_EPILOGUE:                                                                 // 0x14008A206
    KeUnstackDetachProcess(&ApcState);
    if (IsReferenced == 1)                                                  // 0x14008A215
        DereferenceObjectSafe(TargetProcess);

    {
        _OWORD *p = *ppOutputBuffer;                                        // 0x14008A225
        *p = OutStruct1;                                                    // 0x14008A22D
        p[1] = OutStruct2;                                                  // 0x14008A235
        *ppOutputBuffer += 2;                                               // 0x14008A239
        ++*pEntryCount;                                                     // 0x14008A242
    }
    return Result;                                                          // 0x14008A254
}