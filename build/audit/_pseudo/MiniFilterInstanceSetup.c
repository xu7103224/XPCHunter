// MiniFilterInstanceSetup  0x1400129CC  179 bytes
// Minifilter 实例设置回调。检查缓冲区有效性，调用 OpenMiniFilterVolumeFile 打开卷文件并枚举上下文。
bool __fastcall MiniFilterInstanceSetup(
        __int64 Reserved,
        __int64 Reserved2,
        _DWORD *OutputBuffer,
        unsigned int BufferSize)
{
  char Result; // bl

  Result = 0;
  if ( OutputBuffer )
  {
    if ( BufferSize > 0x70
      && (unsigned __int64)OutputBuffer < MmUserProbeAddress
      && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress )
    {
      ProbeForWrite(OutputBuffer, BufferSize, 1u);
      memset(OutputBuffer, 0, BufferSize);
      *OutputBuffer = 0;
      if ( (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1771 )
      {
        OpenMiniFilterVolumeFile(OutputBuffer, BufferSize);
        return *OutputBuffer != 0;
      }
    }
  }
  return Result;
}
