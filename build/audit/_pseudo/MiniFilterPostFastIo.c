// MiniFilterPostFastIo  0x14001BC08  316 bytes
char __fastcall MiniFilterPostFastIo(
        __int64 FilterObject,
        __int64 CallbackData,
        unsigned int *OutputBuffer,
        unsigned int a4)
{
  SIZE_T BufferSize; // r15
  char Result; // bl
  void **TablePtr; // r14
  unsigned int TableCount; // eax
  unsigned int EntryCount; // edi
  char *TableData; // r14

  BufferSize = a4;
  Result = 0;
  if ( !GtRead(GtFwpsDispatchTableBase) )
    InitFwpsDispatchTables();
  TablePtr = (void **)GtRead(GtFwpsDispatchTableBase);
  TableCount = GtRead(GtFwpsDispatchTableCount);
  EntryCount = TableCount;
  if ( TablePtr )
  {
    if ( TableCount )
    {
      if ( TablePtr > MmSystemRangeStart && TableCount < 0x100 )
      {
        TableData = (char *)*TablePtr;
        if ( TableData > MmSystemRangeStart
          && CheckMemoryValid(TableData) == 1
          && CheckMemoryValid(&TableData[8 * EntryCount - 1]) == 1
          && OutputBuffer
          && BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16
          && (unsigned __int64)OutputBuffer < MmUserProbeAddress
          && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress )
        {
          ProbeForWrite(OutputBuffer, BufferSize, 8u);
          memset(OutputBuffer, 0, BufferSize);
          *OutputBuffer = EntryCount;
          memmove(OutputBuffer + 2, TableData, 8LL * EntryCount);
          return 1;
        }
      }
    }
  }
  return Result;
}
