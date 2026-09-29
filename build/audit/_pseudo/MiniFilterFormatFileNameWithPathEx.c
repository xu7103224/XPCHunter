// MiniFilterFormatFileNameWithPathEx  0x14001A1A0  110 bytes
// MiniFilter 带路径扩展格式化文件名。验证输出缓冲区位于用户空间且大小为 4，将全局表 2289 的值写入输出缓冲区。
char __fastcall MiniFilterFormatFileNameWithPathEx(
        __int64 Unknown,
        __int64 Unknown2,
        _DWORD *OutputBuffer,
        int BufferSize)
{
  int Result; // ebx

  Result = 0;
  if ( (unsigned __int64)OutputBuffer < MmUserProbeAddress
    && OutputBuffer
    && (unsigned __int64)(OutputBuffer + 1) < MmUserProbeAddress
    && BufferSize == 4 )
  {
    ProbeForWrite(OutputBuffer, 4u, 4u);
    LOBYTE(Result) = (unsigned int)GtRead(GtMiniFilterFormatNameExReady) != 0;
    *OutputBuffer = Result;
    LOBYTE(Result) = 1;
  }
  return Result;
}
