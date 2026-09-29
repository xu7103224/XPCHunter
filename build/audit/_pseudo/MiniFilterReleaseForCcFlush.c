// MiniFilterReleaseForCcFlush  0x14001C1B4  192 bytes
bool __fastcall MiniFilterReleaseForCcFlush(__int128 *Address, int ContextSize)
{
  char Result; // bl
  __int128 ContextData; // [rsp+30h] [rbp-28h] BYREF
  int FlagsValue; // [rsp+40h] [rbp-18h]
  char SuccessFlag; // [rsp+44h] [rbp-14h]

  Result = 0;
  if ( Address
    && ContextSize == 20
    && (unsigned __int64)Address < MmUserProbeAddress
    && (unsigned __int64)Address + 20 < MmUserProbeAddress )
  {
    ProbeForRead(Address, 0x14u, 1u);
    ContextData = *Address;
    FlagsValue = *((_DWORD *)Address + 4);
    SuccessFlag = 0;
    ForEachProcessor((__int64 (__fastcall *)(_QWORD, __int64))MiniFilterAcquireForCcFlush, (__int64)&ContextData);
    return SuccessFlag == 1;
  }
  return Result;
}
