// InitCallbackContextHookTable — 初始化回调上下文 Hook 表（补全空壳）
// 对应原始驱动 0x14003E5BC（239 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（50 行伪代码），按伪代码实现
// 【逻辑】GtAlloc(0x3BC6) 取表 + GtRead(0x8D3) 取镜像基址；
//   ReadNtoskrnlForCallbackContext 读 msfs.sys → ParseNtFileForCallbackContext 填表
//   → ParseNtExportDir(...,0) 修正重定位；
//   然后遍历 28 项（步长 0x30）：+4 为 RVA，置 +0 为命中标志；
//   若 RVA 非 0 且 RVA+32 <= 文件大小，则置 +0=1 并从文件缓冲拷贝 **32 字节**
//   （注意：本表每项拷贝 32 字节节头，比同族的 16 字节多）；
//   成功则 GtWrite(0x8D5, 1)，ExFree，最后 FillExportEntrySlot。
void InitCallbackContextHookTable(void)
{
    char IsReady = 0;
    __int64 *pExportTable;
    __int64 NtoskrnlBase;
    unsigned int *pSlot;
    __int64 EntryCount;
    __int64 RvaValue;
    char *pFileBuffer = NULL;
    unsigned int FileSize = 0;

    pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3BC6);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8D3);
    if (!NtoskrnlBase || !ReadNtoskrnlForCallbackContext((_QWORD *)&pFileBuffer, &FileSize))
        return;

    if (ParseNtFileForCallbackContext((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1 &&
        ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
    {
        pSlot = (unsigned int *)pExportTable + 1;
        EntryCount = 28;
        do
        {
            RvaValue = *pSlot;
            *(pSlot - 1) = 0;
            if ((_DWORD)RvaValue && (int)RvaValue + 32 <= (int)FileSize)
            {
                *(pSlot - 1) = 1;
                memcpy(pSlot + 3, &pFileBuffer[RvaValue], 32);   // 32 字节节头（同族为 16）
            }
            pSlot += 12;                                          // 0x30/4
            --EntryCount;
        } while (EntryCount);
        IsReady = 1;
        GtWrite((GLOBAL_TABLE_INDEX)0x8D5, 1);
    }
    ExFree(pFileBuffer);
    if (IsReady == 1)
        FillExportEntrySlot((__int64)pExportTable);
}

// BuildCallbackContextHookTargets — 构建回调上下文 Hook 目标表（补全空壳）
// 对应原始驱动 0x140035EE0（231 字节）
// 【逆向来源】同上（可反编译，43 行伪代码）
// 【逻辑】GtAlloc(0x3FE6) + GtRead(GtNtoskrnlFileSize)；
//   ReadNtoskrnlForCallbackCtx 读 volmgr.sys/ftdisk.sys → ParseNtExportSectionsV3
//   → ParseNtExportDir(...,0)；遍历 28 项（+4 为 RVA），命中则置 +0=1 并拷 **16 字节**；
//   成功则 GtWrite(0x904, 1)，ExFree，FillExportEntrySlot。
void BuildCallbackContextHookTargets(void)
{
    char Result = 0;
    __int64 *pTargetTable;
    __int64 SectionBase;
    unsigned int *pRvaEntry;
    __int64 EntryCount;
    __int64 TargetRva;
    unsigned int FileSize = 0;
    char *pFileBuffer = NULL;

    pTargetTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3FE6);
    SectionBase = (__int64)GtRead(GtNtoskrnlFileSize);
    if (SectionBase && ReadNtoskrnlForCallbackCtx((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseNtExportSectionsV3((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1 &&
            ParseNtExportDir((__int64)pFileBuffer, FileSize, SectionBase, 0) == 1)
        {
            pRvaEntry = (unsigned int *)pTargetTable + 1;
            EntryCount = 28;
            do
            {
                TargetRva = *pRvaEntry;
                *(pRvaEntry - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= (int)FileSize)
                {
                    *(pRvaEntry - 1) = 1;
                    memcpy(pRvaEntry + 3, &pFileBuffer[TargetRva], 16);
                }
                pRvaEntry += 12;
                --EntryCount;
            } while (EntryCount);
            Result = 1;
            GtWrite((GLOBAL_TABLE_INDEX)0x904, 1);
        }
        ExFree(pFileBuffer);
        if (Result == 1)
            FillExportEntrySlot((__int64)pTargetTable);
    }
}

// BuildContextTableFromNtFile — 从 NT 文件构建上下文表（补全空壳）
// 对应原始驱动 0x1400473A0（211 字节）
// 【逆向来源】同上（可反编译，44 行伪代码）
// 【逻辑】GtRead(0x8E0) 取镜像基址；ReadNtFileForContextTable 读 partmgr.sys
//   → GtAlloc(0x3F32) → ParseNtSectionsForContextTable → ParseNtExportDir(...,0)；
//   遍历 28 项（+4 为 RVA），命中则置 +0=1 并拷 16 字节；
//   成功后 GtWrite(0x8E2, 1) 并 ExFree。
//   注：本函数**不调用** FillExportEntrySlot（与同族另两个不同）。
void BuildContextTableFromNtFile(void)
{
    __int64 NtoskrnlBase;
    __int64 *pExportTable;
    unsigned int *pIndexPtr;
    __int64 EntryCount;
    __int64 TargetRva;
    unsigned int FileSize = 0;
    char *pRawData = NULL;

    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8E0);
    if (NtoskrnlBase && ReadNtFileForContextTable((_QWORD *)&pRawData, &FileSize))
    {
        pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3F32);
        if (ParseNtSectionsForContextTable((__int64)pRawData, FileSize, (__int64)pExportTable) == 1 &&
            ParseNtExportDir((__int64)pRawData, FileSize, NtoskrnlBase, 0) == 1)
        {
            pIndexPtr = (unsigned int *)pExportTable + 1;
            EntryCount = 28;
            do
            {
                TargetRva = *pIndexPtr;
                *(pIndexPtr - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= (int)FileSize)
                {
                    *(pIndexPtr - 1) = 1;
                    memcpy(pIndexPtr + 3, &pRawData[TargetRva], 16);
                }
                pIndexPtr += 12;
                --EntryCount;
            } while (EntryCount);
            GtWrite((GLOBAL_TABLE_INDEX)0x8E2, 1);
        }
        ExFree(pRawData);
    }
}