// InitProcessContextExportTableWin7  0x140039FF4  231 bytes
// 初始化进程上下文导出表（Win7）。从 GT 2241 获取 ntoskrnl 基址，分配 GT 14954 作为目标表，读取 ipsec.sys 文件。通过 ParseRsdsDebugInfo 解析 RSDS 调试信息 + ParseNtExportDir 解析导出目录，备份原始字节。标记 GT 0x8C3 为 1。
void InitProcessContextExportTableWin7()
{
  char IsReady; // bl
  __int64 *pExportTable; // rdi
  __int64 NtoskrnlBase; // rsi
  unsigned int *pEntry; // rdx
  __int64 EntryCount; // r8
  __int64 RvaValue; // rcx
  unsigned int FileSize; // [rsp+30h] [rbp+8h] BYREF
  char *pFileBuffer; // [rsp+38h] [rbp+10h] BYREF

  IsReady = 0;
  pExportTable = GtAlloc(GtFwpsDispatchTableBase|GtObjectTypeField38|GtNtoskrnlImageSize|0x3000);
  NtoskrnlBase = GtRead(GtFwpsDispatchTableCount|GtEprocessField182);
  if ( NtoskrnlBase && ReadIpsecSysFile(&pFileBuffer, &FileSize) )
  {
    if ( ParseRsdsDebugInfo((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1
      && ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1 )
    {
      pEntry = (unsigned int *)pExportTable + 1;
      EntryCount = 28;
      do
      {
        RvaValue = *pEntry;
        *(pEntry - 1) = 0;
        if ( (_DWORD)RvaValue && (int)RvaValue + 16 <= FileSize )
        {
          *(pEntry - 1) = 1;
          *(_OWORD *)(pEntry + 3) = *(_OWORD *)&pFileBuffer[RvaValue];
        }
        pEntry += 12;
        --EntryCount;
      }
      while ( EntryCount );
      IsReady = 1;
      GtWrite(GtFwpsDispatchTableCount|GtEprocessField184, 1);
    }
    ExFree(pFileBuffer);
    if ( IsReady == 1 )
      FillExportEntrySlot((__int64)pExportTable);
  }
}
