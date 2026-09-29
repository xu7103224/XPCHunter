// MiniFilterStreamHandle  0x14001AB5C  289 bytes
bool __fastcall MiniFilterStreamHandle(__m128i *Address, int a2)
{
  bool Result; // di
  __m128i InputData; // xmm2
  struct _KPROCESS *TargetProcess; // rbx
  NTSTATUS Status; // eax
  int Status2; // esi
  PEPROCESS Process; // [rsp+28h] [rbp-40h] BYREF
  struct _KPROCESS *v10; // [rsp+30h] [rbp-38h]
  __m128i StreamData; // [rsp+48h] [rbp-20h]
  __int64 StreamContext; // [rsp+58h] [rbp-10h]

  Result = 0;
  if ( Address
    && a2 == 40
    && (unsigned __int64)Address < MmUserProbeAddress
    && (unsigned __int64)&Address[2].m128i_u64[1] < MmUserProbeAddress )
  {
    ProbeForRead(Address, 0x28u, 4u);
    InputData = *Address;
    StreamData = Address[1];
    StreamContext = Address[2].m128i_i64[0];
    TargetProcess = (struct _KPROCESS *)_mm_srli_si128(InputData, 8).m128i_u64[0];
    v10 = TargetProcess;
    Status = PsLookupProcessByProcessId((HANDLE)InputData.m128i_i64[0], &Process);
    Status2 = Status;
    if ( !TargetProcess )
    {
      if ( Status >= 0 )
        TargetProcess = Process;
      v10 = TargetProcess;
    }
    if ( ValidateProcessObject(TargetProcess, 0) == 1
      && StreamData.m128i_i64[0] < MmUserProbeAddress
      && StreamData.m128i_i64[1] < MmUserProbeAddress )
    {
      Result = MiniFilterStreamHandleEx(TargetProcess, StreamData.m128i_i64[0], StreamData.m128i_u64[1], StreamContext);
    }
    if ( Status2 >= 0 )
      ObfDereferenceObject(Process);
  }
  return Result;
}
