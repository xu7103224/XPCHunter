// MiniFilterAcquireForSectionSync  0x14001C274  181 bytes
bool __fastcall MiniFilterAcquireForSectionSync(
        __int64 FilterObject,
        __int64 CallbackData,
        _DWORD *OutputBuffer,
        unsigned int BufferSize)
{
  char Result; // bl
  _DWORD *ContextPtr; // [rsp+28h] [rbp-20h] BYREF
  unsigned int ContextSize; // [rsp+30h] [rbp-18h]

  Result = 0;
  if ( OutputBuffer
    && BufferSize >= 0x10018
    && (unsigned __int64)OutputBuffer < MmUserProbeAddress
    && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress )
  {
    ProbeForWrite(OutputBuffer, BufferSize, 1u);
    memset(OutputBuffer, 0, BufferSize);
    *OutputBuffer = 0;
    ContextSize = BufferSize;
    ContextPtr = OutputBuffer;
    ForEachProcessor((__int64 (__fastcall *)(_QWORD, __int64))MiniFilterReleaseForModWrite, (__int64)&ContextPtr);
    return *OutputBuffer != 0;
  }
  return Result;
}
