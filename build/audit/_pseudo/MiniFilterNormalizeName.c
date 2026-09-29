// MiniFilterNormalizeName  0x140019DD8  199 bytes
// MiniFilter 文件名规范化。获取 ZwCreateFile、ZwSetInformationFile、ZwClose 函数指针，创建文件并设置重命名信息，用于规范化文件名。
__int64 *__fastcall MiniFilterNormalizeName(__int64 Unknown, __int64 FilePath, char IsAddOperation)
{
  int (__fastcall *CreateFileFunc)(__int64 *, __int64, int *, _QWORD *); // rsi
  void (__fastcall *SetInfoFunc)(__int64, _QWORD); // rbx
  __int64 CloseFuncPtr; // rax
  void (__fastcall *CloseFunc)(__int64); // rdi
  _QWORD v10[2]; // [rsp+20h] [rbp-40h] BYREF
  int v11; // [rsp+30h] [rbp-30h] BYREF
  __int64 v12; // [rsp+38h] [rbp-28h]
  __int64 v13; // [rsp+40h] [rbp-20h]
  int v14; // [rsp+48h] [rbp-18h]
  __int128 v15; // [rsp+50h] [rbp-10h]
  __int64 v16; // [rsp+98h] [rbp+38h] BYREF

  AcquireMiniFilterMutexEx();
  if ( IsAddOperation == 1 )
  {
    CreateFileFunc = (int (__fastcall *)(__int64 *, __int64, int *, _QWORD *))GtRead(GtUninstallHookSyscallPeOffset|GtPathBuffer02|0x100);
    SetInfoFunc = (void (__fastcall *)(__int64, _QWORD))GtRead(GtEprocessField201|GtTotalSize);
    CloseFuncPtr = GtRead(GtExFreePoolFunc);
    CloseFunc = (void (__fastcall *)(__int64))CloseFuncPtr;
    if ( CreateFileFunc )
    {
      if ( SetInfoFunc )
      {
        if ( CloseFuncPtr )
        {
          v10[1] = 0;
          v12 = 0;
          v13 = 0;
          v15 = 0;
          v10[0] = FilePath;
          v11 = 48;
          v14 = 512;
          if ( CreateFileFunc(&v16, 1, &v11, v10) >= 0 )
          {
            SetInfoFunc(v16, 0);
            CloseFunc(v16);
          }
        }
      }
    }
  }
  return AcquireMiniFilterMutex();
}
