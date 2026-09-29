// FindPESectionByNameReturnVa  0x140005CB4  151 bytes
// 按名称查找 PE 节返回 VA。遍历节表，返回匹配节名的虚拟地址。
__int64 __fastcall FindPESectionByNameReturnVa(__int64 PeBase, unsigned int PeSize, __int64 SectionName)
{
  __int64 PeSignature; // r9
  unsigned int Result; // ebx
  unsigned int NumberOfSections; // ebp
  __int64 SectionHeaderStart; // r14
  unsigned int SectionIndex; // edi
  unsigned int SectionVa; // eax
  unsigned int SectionSize; // ecx

  PeSignature = *(int *)(PeBase + 60);
  Result = 0;
  NumberOfSections = *(unsigned __int16 *)(PeSignature + PeBase + 6);
  SectionHeaderStart = *(unsigned __int16 *)(PeSignature + PeBase + 20) + PeSignature + PeBase + 24;
  SectionIndex = 0;
  if ( *(_WORD *)(PeSignature + PeBase + 6) )
  {
    while ( (unsigned int)StringCompareCaseInsensitiveV2(SectionName, SectionHeaderStart + 40LL * SectionIndex) )
    {
      if ( ++SectionIndex >= NumberOfSections )
        return Result;
    }
    SectionVa = *(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 8);
    if ( SectionVa < PeSize )
    {
      SectionSize = *(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 12);
      if ( SectionSize < PeSize && SectionVa + SectionSize < PeSize )
        return *(unsigned int *)(SectionHeaderStart + 40LL * SectionIndex + 8);
    }
  }
  return Result;
}
