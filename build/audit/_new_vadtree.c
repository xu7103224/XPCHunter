// ScanProcessVadTree — 扫描目标进程 VAD 树，按对象类型索引定位 VAD 记录地址
// 对应原始驱动 0x140088B74（1834 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 A_definite_missing，源码中此前完全缺失。
//
// 【与 ScanProcessVadMemory(0x1400897E4) 的关系】同族：同样的 GT 前置校验、
//   ValidateKernelObject → ReferenceObjectSafe → KeStackAttachProcess 骨架、
//   以及同样的"输出 {进程对象, 创建时间, 地址, 对象类型索引} 并递增计数"收尾。
//   差异：本函数**多一个入参 ObjectTypeIndex**（写入 ResultStruct2 的第 2 个 DWORD，
//   即"类型索引"字段），且构建号分档更多（2600/7600-7601/9200/9600/3790/其他）。
char __fastcall ScanProcessVadTree(unsigned __int64 ObjectAddress,
                                   int ObjectTypeIndex,
                                   _OWORD **ppOutputBuffer,
                                   _DWORD *pEntryCount)
{
    __int64 (__fastcall *pGetProcessFunc)(unsigned __int64);
    ULONG64 KernelBase;
    ULONG   KernelSize;
    ULONG64 *pMinAddress;
    __int64 ObjectTypeCheckBase;
    ULONG   VadRootOffset;
    ULONG   VadTableOffset;
    ULONG   CreateTimeOffset;
    UCHAR   Result;
    ULONG64 FoundAddress;
    __int64 TargetProcess;
    ULONG64 VadEndAddress;
    ULONG   Build;
    UCHAR   IsReferenced;
    ULONG64 OutS1Lo, OutS1Hi, OutS2Lo, OutS2Hi;
    struct _KAPC_STATE ApcState;

    Result = 0;
    pGetProcessFunc = (__int64 (__fastcall *)(unsigned __int64))GtRead((GLOBAL_TABLE_INDEX)0x4196);
    KernelBase      = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    KernelSize      = (ULONG)GtRead(GtNtoskrnlImageSize);
    pMinAddress     = (ULONG64 *)GtRead((GLOBAL_TABLE_INDEX)0x4168);
    ObjectTypeCheckBase = (__int64)GtRead(GtObjectTypeCheckFlag);
    VadRootOffset   = (ULONG)GtRead(GtEprocessField191);
    VadTableOffset  = (ULONG)GtRead(GtEprocessField193);
    CreateTimeOffset= (ULONG)GtRead(GtProcessCreateTime);

    if (!pGetProcessFunc) return Result;
    if (!KernelBase) return Result;
    if (!KernelSize) return Result;
    if (!pMinAddress) return Result;
    if (!ObjectTypeCheckBase) return Result;
    if (!VadRootOffset) return Result;
    if (!VadTableOffset) return Result;
    if (!CreateTimeOffset) return Result;

    Result = 1;
    if (!ObjectAddress) return Result;
    if (!ValidateKernelObject(ObjectAddress, 0, 0, 0)) return Result;

    OutS1Lo = ObjectAddress;
    OutS1Hi = 0;
    OutS2Lo = *(ULONG64 *)(CreateTimeOffset + ObjectAddress);
    OutS2Hi = (ULONG64)(ULONG)ObjectTypeIndex;      // DWORD2(ResultStruct2) = ObjectTypeIndex
    FoundAddress = 0;

    TargetProcess = pGetProcessFunc(ObjectAddress);
    IsReferenced = (UCHAR)ReferenceObjectSafe(TargetProcess);
    KeStackAttachProcess((void *)TargetProcess, &ApcState);

    if (CheckProcessObjectFlag(ObjectAddress))
    {
        __int64 *VadRoot;
        VadEndAddress = *(ULONG64 *)(VadRootOffset + ObjectAddress);
        VadRoot = (__int64 *)(*(ULONG64 *)(VadTableOffset + ObjectAddress));

        if (CheckMemoryValid((void *)(VadEndAddress - 1)) == 1
            && CheckMemoryValid(VadRoot) == 1)
        {
            Build = (ULONG)GtRead(GtWindowsBuildNumber);

            if (Build == 2600)                                          // 0x140088D2F
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress; ++p)
                {
                    if ((ULONG64)(p + 12) > VadEndAddress)              // 0x140088D4B
                        break;
                    if (ObjectAddress == (ULONG64)*p && p[1] == 0)      // 0x140088D56
                    {
                        ULONG64 v18 = p[3];                             // 0x140088D5B
                        if (v18 > (ULONG64)VadRoot && v18 < VadEndAddress)   // 0x140088D67
                        {
                            ULONG64 v19 = p[4];                         // 0x140088D69
                            if (v19 > KernelBase && v19 < KernelBase + KernelSize)  // 0x140088D7C
                            {
                                FoundAddress = p[2];                    // LABEL_112
                                break;
                            }
                        }
                    }
                }
            }
            else if (Build == 7600 || Build == 7601)                    // 0x140088DA8
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress && (ULONG64)(p + 20) <= VadEndAddress; ++p)
                {
                    if ((ULONG)GtRead(GtWindowsBuildNumber) == 7600)    // 0x140089120
                    {
                        if (ObjectAddress == (ULONG64)*p)               // 0x140089129
                        {
                            ULONG64 v46 = p[7], v47 = p[8];             // 0x14008912F/133
                            if (v46 == v47 && v47 >= (ULONG64)MmSystemRangeStart)  // 0x14008914B
                            {
                                ULONG64 v48 = p[10];                    // 0x14008914D
                                ULONG64 v49 = KernelBase + KernelSize;  // 0x140089159
                                if (v48 > KernelBase && v48 < v49)      // 0x140089154/15F
                                {
                                    ULONG64 v50 = p[11];                // 0x140089161
                                    if (v50 > KernelBase && v50 < v49)  // 0x14008916D
                                    {
                                        FoundAddress = p[13];           // 0x14008920B
                                        break;
                                    }
                                }
                            }
                            if (p[5] >= (__int64)MmSystemRangeStart)    // 0x140089181
                            {
                                ULONG64 v51 = p[1];                     // 0x140089183
                                ULONG64 v52 = KernelBase + KernelSize;
                                if (v51 > KernelBase && v51 < v52)      // 0x14008918A/195
                                {
                                    ULONG64 v53 = p[2];                 // 0x140089197
                                    if (v53 > KernelBase && v53 < v52   // 0x1400891B3
                                        && v46 > (ULONG64)VadRoot && v46 < VadEndAddress
                                        && p[9] >= (__int64)MmSystemRangeStart)
                                    {
                                        FoundAddress = p[4];            // 0x140089211
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else if (p[1] == 0 && p[3] == 0)                    // 0x1400891BF
                    {
                        ULONG64 v54 = p[4];                             // 0x1400891C5
                        if (v54 >= (ULONG64)MmSystemRangeStart          // 0x1400891FD
                            && p[5] >= (__int64)MmSystemRangeStart
                            && p[6] == 1
                            && ObjectAddress == (ULONG64)p[9]
                            && p[10] >= (__int64)MmSystemRangeStart
                            && p[11] >= (__int64)MmSystemRangeStart
                            && p[18] == (__int64)v54)
                        {
                            FoundAddress = p[5];                        // LABEL_145
                            break;
                        }
                    }
                }
            }
            else if (Build == 9200)                                     // 0x140088DBA
            {
                __int64 *p = VadRoot + 10;
                if ((ULONG64)p < VadEndAddress)
                {
                    while ((ULONG64)(p + 20) <= VadEndAddress)          // 0x140088DDE
                    {
                        if (ObjectAddress == (ULONG64)*p && p[-1] == (__int64)-6000000000LL)  // 0x140088DF7
                        {
                            ULONG64 v21 = p[1];                             // 0x140088DF9
                            ULONG64 v22 = KernelBase + KernelSize;
                            if (v21 > KernelBase && v21 < v22)              // 0x140088E00/0C
                            {
                                ULONG64 v23 = p[2];                         // 0x140088E0E
                                if (v23 > KernelBase && v23 < v22)          // 0x140088E1A
                                {
                                    ULONG64 v24 = p[-2];                    // 0x140088E1C
                                    if (v24 > KernelBase && v24 < v22       // 0x140088E31
                                        && p[9] >= (__int64)MmSystemRangeStart)
                                    {
                                        FoundAddress = p[-6];               // 0x140088E42
                                        break;
                                    }
                                }
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                  // 0x140088E3A
                            break;
                    }
                }
            }
            else if (Build == 9600)                                     // 0x140088E57
            {
                __int64 *p = VadRoot + 10;
                for (; (ULONG64)p < VadEndAddress && (ULONG64)(p + 20) <= VadEndAddress; ++p)
                {
                    if (ObjectAddress != (ULONG64)*p)                       // 0x140088E7D
                        continue;

                    {
                        __int64 HookFlag = (__int64)GtRead(GtNtCreateThreadHookSuccess);  // 0x140088E88
                        ULONG64 v27 = p[1];                                 // 0x140088E8F
                        if (HookFlag)                                       // 0x140088E96
                        {
                            if (v27 > KernelBase && v27 < KernelBase + KernelSize)  // 0x140088EEF
                            {
                                __int64 v28 = p[2];                         // 0x140088EF1
                                if (v28 == 1)                               // 0x140088EF8
                                {
                                    if (p[3] > (__int64)MmSystemRangeStart
                                        && *p == p[4])                      // 0x140088F11
                                    {
                                        FoundAddress = p[3];                // 0x140088F92
                                        break;
                                    }
                                }
                                else if (v28 == 0 && p[3] == 0 && p[4] == 0  // 0x140088F3D
                                    && p[7] > (__int64)MmSystemRangeStart
                                    && *p == p[6])
                                {
                                    FoundAddress = p[7];                // 0x140088F9B
                                    break;
                                }
                            }
                            else if (v27 == 1 && p[6] == 0)                // 0x140088F46
                            {
                                __int64 v29 = *p;                          // 0x140088F4C
                                if (*p == p[3])                            // 0x140088F53
                                {
                                    ULONG64 v30 = p[5];                    // 0x140088F55
                                    if (v30 > (ULONG64)MmSystemRangeStart  // 0x140088F7A
                                        && (ULONG64)v29 != v30
                                        && ((v29 ^ (__int64)v30) & 0xFFFFFFFF00000000LL) != 0)
                                    {
                                        FoundAddress = p[5];               // LABEL_145
                                        break;
                                    }
                                }
                            }
                        }
                        else if (v27 > KernelBase                          // 0x140088ED5
                            && v27 < KernelBase + KernelSize
                            && p[2] > (__int64)MmSystemRangeStart
                            && p[3] == 2
                            && p[7] == 40)
                        {
                            FoundAddress = p[2];                        // 0x140088F89
                            break;
                        }
                    }
                }
            }
            else if (Build < 0x1770 || Build > 0x1772)                  // 0x140088FBE
            {
                ULONG   v36 = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140089033
                __int64 *p = VadRoot;
                if (v36 == 3790)                                        // 0x140089043
                {
                    for (; (ULONG64)p < VadEndAddress; ++p)
                    {
                        if ((ULONG64)(p + 12) > VadEndAddress)          // 0x140089059
                            break;
                        if (ObjectAddress == (ULONG64)*p && p[1] == 0)  // 0x140089064
                        {
                            ULONG64 v39 = p[7];                         // 0x140089069
                            if (v39 > (ULONG64)VadRoot && v39 < VadEndAddress)  // 0x140089075
                            {
                                ULONG64 v40 = p[8];                     // 0x140089077
                                if (v40 > KernelBase && v40 < KernelBase + KernelSize)  // 0x14008908A
                                {
                                    FoundAddress = p[6];                // 0x140089094
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    for (; (ULONG64)p < VadEndAddress; ++p)
                    {
                        if ((ULONG64)(p + 12) > VadEndAddress)          // 0x1400890B1
                            break;
                        if (ObjectAddress == (ULONG64)*p && p[1] == 0)  // 0x1400890BC
                        {
                            ULONG64 v43 = p[4];                         // 0x1400890C1
                            if (v43 > (ULONG64)VadRoot && v43 < VadEndAddress)  // 0x1400890CD
                            {
                                ULONG64 v44 = p[5];                     // 0x1400890CF
                                if (v44 > KernelBase && v44 < KernelBase + KernelSize)  // 0x1400890E2
                                {
                                    FoundAddress = p[2];                // LABEL_112
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else                                                        // 0x1770..0x1772
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress; ++p)
                {
                    if ((ULONG64)(p + 12) > VadEndAddress)              // 0x140088FDA
                        break;
                    if (ObjectAddress == (ULONG64)*p && p[1] == 0)      // 0x140088FE5
                    {
                        ULONG64 v34 = p[10];                            // 0x140088FEA
                        if (v34 > (ULONG64)VadRoot && v34 < VadEndAddress)   // 0x140088FF6
                        {
                            ULONG64 v35 = p[11];                        // 0x140088FF8
                            if (v35 > KernelBase && v35 < KernelBase + KernelSize)  // 0x14008900B
                            {
                                FoundAddress = p[8];                    // 0x140089015
                                if (FoundAddress < (ULONG64)MmSystemRangeStart)  // 0x140089023
                                    FoundAddress = 0;
                                break;
                            }
                        }
                    }
                }
            }

            if (FoundAddress < *pMinAddress)                            // 0x140089226
                FoundAddress = 0;
            OutS2Hi = FoundAddress;                                     // 0x14008922A
        }
    }

    KeUnstackDetachProcess(&ApcState);                                 // 0x140089239
    if (IsReferenced == 1)                                             // 0x140089243
        DereferenceObjectSafe(TargetProcess);

    {
        ULONG64 *o = (ULONG64 *)*ppOutputBuffer;                       // 0x140089253
        o[0] = OutS1Lo; o[1] = OutS1Hi;
        o[2] = OutS2Lo; o[3] = OutS2Hi;
        *ppOutputBuffer += 2;                                          // 0x140089267
        ++*pEntryCount;                                                // 0x140089270
    }
    return Result;                                                     // 0x14008927B
}