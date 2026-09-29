// MiniFilterPreFastIo  0x14001B2B4  176 bytes
char __fastcall MiniFilterPreFastIo(__int64 FilterObject, __int64 CallbackData, _DWORD *OutputBuffer, unsigned int a4)
{
  char Result; // bl
  __int64 BufferSize; // rsi

  Result = 0;
  if ( OutputBuffer )
  {
    if ( a4 >= 0x278 && (unsigned __int64)OutputBuffer < MmUserProbeAddress )
    {
      BufferSize = a4;
      if ( (unsigned __int64)OutputBuffer + a4 < MmUserProbeAddress )
      {
        ProbeForWrite(OutputBuffer, a4, 8u);
        memset(OutputBuffer, 0, (unsigned int)BufferSize);
        *OutputBuffer = 0;
        EnumerateAleEndpointLayers(OutputBuffer, (__int64)(OutputBuffer + 2), (BufferSize - 632) / 0x270uLL + 1);
        return 1;
      }
    }
  }
  return Result;
}
