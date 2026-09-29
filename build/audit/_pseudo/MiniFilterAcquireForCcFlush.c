// MiniFilterAcquireForCcFlush  0x14001C130  129 bytes
char __fastcall MiniFilterAcquireForCcFlush(int ProcessorNumber, __int64 ContextBuffer)
{
  char Result; // bl
  __int64 SelectorIndex; // rcx
  unsigned __int16 GdtrValue; // [rsp+20h] [rbp-28h] BYREF
  __int64 GdtrBase; // [rsp+22h] [rbp-26h]

  Result = 1;
  if ( ProcessorNumber == *(_DWORD *)ContextBuffer )
  {
    ReadGdtr(&GdtrValue);
    if ( !(unsigned int)MemoryCompare((__int64)&GdtrValue, (char *)(ContextBuffer + 4), 0xAu) )
    {
      SelectorIndex = *(unsigned int *)(ContextBuffer + 16);
      if ( (unsigned int)SelectorIndex < GdtrValue >> 3 )
      {
        *(_WORD *)(GdtrBase + 8 * SelectorIndex + 4) &= ~0x8000u;
        *(_BYTE *)(ContextBuffer + 20) = 1;
      }
    }
    return 0;
  }
  return Result;
}
