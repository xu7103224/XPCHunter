// FindPESectionByName  0x140005C28  137 bytes
// 按名称查找 PE 节。遍历节表，返回匹配节名的节在文件中的偏移。
__int64 __fastcall FindPESectionByName(__int64 PeBase, unsigned int PeSize, __int64 SectionName)
{
  __int64 PeHeaderRva; // r9
  unsigned int Result; // ebx
  unsigned int NumberOfSections; // esi
  __int64 SectionHeaderStart; // r14
  unsigned int SectionIndex; // edi

  PeHeaderRva = *(int *)(PeBase + 60);
  Result = 0;
  NumberOfSections = *(unsigned __int16 *)(PeHeaderRva + PeBase + 6);
  SectionHeaderStart = *(unsigned __int16 *)(PeHeaderRva + PeBase + 20) + PeHeaderRva + PeBase + 24;
  SectionIndex = 0;
  if ( *(_WORD *)(PeHeaderRva + PeBase + 6) )
  {
    while ( (unsigned int)StringCompareCaseInsensitiveV2(SectionName, SectionHeaderStart + 40LL * SectionIndex) )
    {
      if ( ++SectionIndex >= NumberOfSections )
        return Result;
    }
    if ( *(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 12) < PeSize )
      return *(unsigned int *)(SectionHeaderStart + 40LL * SectionIndex + 12);
  }
  return Result;
}
