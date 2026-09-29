// MiniFilterInstanceQuery  0x140012B78  175 bytes
// Minifilter 实例查询回调。验证输入缓冲区，检查地址有效性，调用 RemoveMiniFilterContextNode 移除指定的上下文节点。
bool __fastcall MiniFilterInstanceQuery(__int128 *InputBuffer, int BufferSize)
{
  char Result; // bl
  __int128 ContextPair; // [rsp+28h] [rbp-20h] BYREF

  Result = 0;
  if ( InputBuffer )
  {
    if ( BufferSize == 16
      && (unsigned __int64)InputBuffer < MmUserProbeAddress
      && (unsigned __int64)(InputBuffer + 1) < MmUserProbeAddress )
    {
      ProbeForRead(InputBuffer, 0x10u, 1u);
      ContextPair = *InputBuffer;
      if ( (unsigned __int64)ContextPair > (unsigned __int64)MmSystemRangeStart
        && *((_QWORD *)&ContextPair + 1) > (unsigned __int64)MmSystemRangeStart
        && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1771 )
      {
        return RemoveMiniFilterContextNode(&ContextPair) == 1;
      }
    }
  }
  return Result;
}
