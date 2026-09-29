// MiniFilterFormatFileNameWithContext  0x14001A0E8  69 bytes
char MiniFilterFormatFileNameWithContext()
{
  char v0; // bl
  void (__fastcall *v1)(__int64 *(__fastcall *)(__int64, __int64, char)); // rax

  v0 = 0;
  if ( !(unsigned int)GtRead(GtMiniFilterFormatNameExReady) )
  {
    v1 = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char)))GtRead(GtTotalSize|GtEprocessField155|0x100);
    if ( v1 )
    {
      v1(MiniFilterFilterUnload);
      GtWrite(GtMiniFilterFormatNameExReady, 1);
      return 1;
    }
  }
  return v0;
}
