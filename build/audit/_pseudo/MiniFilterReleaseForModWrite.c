// MiniFilterReleaseForModWrite  0x14001C048  229 bytes
char __fastcall MiniFilterReleaseForModWrite(int ProcessorNumber, unsigned int **ContextBuffer)
{
  char Result; // bl
  _DWORD *EntryPtr; // rdi
  __int64 EntryIndex; // rdx
  _TBYTE GdtrValue; // [rsp+28h] [rbp-20h] BYREF

  Result = 1;
  ReadGdtr(&GdtrValue);                         // MiniFilter 释放修改写回调。读取 GDTR 值，将 GDT 条目信息写入缓冲区：段选择子、GDT 极限值和 GDT 表数据。
  EntryPtr = *ContextBuffer;
  EntryIndex = 16389LL * **ContextBuffer;
  if ( EntryIndex * 4 + 65560 > (unsigned __int64)*((unsigned int *)ContextBuffer + 2) )
    return 0;
  EntryPtr[EntryIndex + 1] = ProcessorNumber;
  *(_TBYTE *)&EntryPtr[16389 * *EntryPtr + 2] = GdtrValue;
  EntryPtr[16389 * *EntryPtr + 5] = (unsigned __int64)LOWORD(GdtrValue) >> 3;
  memmove(&EntryPtr[16389 * *EntryPtr + 6], *(const void **)((char *)&GdtrValue + 2), LOWORD(GdtrValue));
  ++*EntryPtr;
  return Result;
}
