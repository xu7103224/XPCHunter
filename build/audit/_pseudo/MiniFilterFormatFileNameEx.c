// MiniFilterFormatFileNameEx  0x14001A130  110 bytes
char __fastcall MiniFilterFormatFileNameEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
  int Result; // ebx

  Result = 0;
  if ( (unsigned __int64)OutputBuffer < MmUserProbeAddress
    && OutputBuffer
    && (unsigned __int64)(OutputBuffer + 1) < MmUserProbeAddress
    && BufferSize == 4 )
  {
    ProbeForWrite(OutputBuffer, 4u, 4u);
    LOBYTE(Result) = (unsigned int)GtRead(GtMiniFilterFormatNameReady) != 0;
    *OutputBuffer = Result;
    LOBYTE(Result) = 1;
  }
  return Result;
}
