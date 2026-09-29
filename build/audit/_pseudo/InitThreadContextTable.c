// InitThreadContextTable  0x1400570C8  231 bytes
// 初始化线程上下文表。分配 GT 16538 的全局表项，读取卷驱动文件，调用 ParseNtDebugSection 解析调试节区，从 PE 导出目录复制 16 字节原始代码到服务表条目，调用 FillExportEntrySlot 填充导出条目槽。
// 初始化线程上下文表（Win10 线程系统调用表）。分配全局表空间，读取卷驱动（volume.sys）文件，解析其调试节区和导出表，填充线程上下文服务条目并注册到导出条目槽中。
// 初始化线程上下文表
// 初始化线程上下文表：初始化线程上下文表
void InitThreadContextTable()
{
  char Result; // bl
  __int64 *pSyscallTable; // rdi
  __int64 SectionBase; // rsi
  unsigned int *pExportEntry; // rdx
  __int64 EntryCount; // r8
  __int64 FuncRva; // rcx
  unsigned int FileSize; // [rsp+30h] [rbp+8h] BYREF
  char *pFileBuffer; // [rsp+38h] [rbp+10h] BYREF

  Result = 0;
  pSyscallTable = GtAlloc(GtTotalSize|GtEprocessField144);
  SectionBase = GtRead(GtProcessProtectTable);
  if ( SectionBase && ReadVolumeSysFile(&pFileBuffer, &FileSize) )
  {
    if ( ParseNtDebugSection((__int64)pFileBuffer, FileSize, (__int64)pSyscallTable) == 1
      && ParseNtExportDir((__int64)pFileBuffer, FileSize, SectionBase, 0) == 1 )
    {
      pExportEntry = (unsigned int *)pSyscallTable + 1;
      EntryCount = 28;
      do
      {
        FuncRva = *pExportEntry;
        *(pExportEntry - 1) = 0;
        if ( (_DWORD)FuncRva && (int)FuncRva + 16 <= FileSize )
        {
          *(pExportEntry - 1) = 1;
          *(_OWORD *)(pExportEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRva];
        }
        pExportEntry += 12;
        --EntryCount;
      }
      while ( EntryCount );
      Result = 1;
      GtWrite(GtRegCallbackTable, 1);
    }
    ExFree(pFileBuffer);
    if ( Result == 1 )
      FillExportEntrySlot((__int64)pSyscallTable);
  }
}
