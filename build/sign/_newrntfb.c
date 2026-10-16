// ReadNtFileToBuffer — 读取 PE 文件到缓冲区（0x140005D4C，699 字节）
// 【⚠ 修正记录 2026-10-16】原实现把三个 OptionalHeader 字段**用错**：
//   原始字段映射（由 IDA 反编译 + 偏移反推双重确认）：
//     v8 = Src + e_lfanew（PE 签名处），v8[6..] 即 OptionalHeader 的 DWORD 数组
//     v16 = v8[14] = OptionalHeader+0x20 = **SectionAlignment**（作 VA 对齐掩码）
//     v15 = v8[15] = OptionalHeader+0x24 = **FileAlignment**（作 Raw 对齐掩码）
//     v17 = v8[20] = OptionalHeader+0x38 = **SizeOfImage**
//     v14 = v8[21] = OptionalHeader+0x3C = **SizeOfHeaders**
//   我方原实现：只取了 SectionAlignment/SizeOfImage/SizeOfHeaders 三者，
//   **完全漏掉 FileAlignment**，并把 SizeOfImage/SizeOfHeaders 的用途混淆，
//   导致节校验与展开逻辑与原始不一致 → 实机 ReadNtoskrnlFile 因此返回失败
//   （sc start 错误 31）。
// 【实机定位】用跨编译单元探针（保持产物 644096 字节健康）逐段二分：
//   跳过 ReadNtoskrnlFile 调用 → RUNNING；令其入口 return 1 → RUNNING；
//   让其走内部流程则失败；把各失败点打上不同 NTSTATUS 后 SCM 报
//   err 34 = 0xC0000013 = 本函数(ReadNtFileToBuffer) 的失败标记。
// 【语义】解析 PE：校验 DOS/NT 签名与节表边界，用 SectionAlignment 对齐各节 VA、
//   用 FileAlignment 对齐 SizeOfRawData，按边界调整节尺寸，
//   然后 ExAlloc(对齐后镜像大小+256)、memset 清零、拷头、逐节 memmove 展开。
// 【返回值】1 = 成功（*OutBuffer/*OutSize 有效）；0 = 失败。
char ReadNtFileToBuffer(PUCHAR Src, ULONG MaxCount, PUCHAR *OutBuffer, PULONG OutSize)
{
    ULONG  SrcSize = MaxCount;          // v4
    char   Result = 0;                  // v5
    PUCHAR pBase = Src;                 // v6
    ULONG  eLfanew;                     // v7
    ULONG *pNt;                         // v8
    ULONG  SectionCount;                // v9
    ULONG  OptSize;                     // v10
    PUCHAR pSection0;                   // v11
    PUCHAR pSectionLast;                // v12
    ULONG  HeaderEnd;                   // v13
    ULONG  SizeOfHeaders;               // v14 = v8[21]
    ULONG  FileAlignment;               // v15 = v8[15]
    ULONG  SectionAlignment;            // v16 = v8[14]
    ULONG  SizeOfImage;                 // v17 = v8[20]
    ULONG  VaMask, RawMask;             // v19 / v22
    ULONG  ImageLimit, RawLimit;        // v20 / (v18+v21 限制)
    ULONG  i;                           // v23
    PUCHAR pSect;                       // v24
    PUCHAR Buffer;                      // v34/v35

    /* ① 长度与 DOS 签名（原始：`(MaxCount-513) <= 0x6FFFFDFE && *(WORD*)Src == 0x5A4D`） */
    if ((ULONG)(SrcSize - 513) > 0x6FFFFDFE || *(WORD *)pBase != IMAGE_DOS_SIGNATURE)
        return Result;

    eLfanew = *(ULONG *)(pBase + 0x3C);                              // Src[15]
    if (eLfanew >= SrcSize || (unsigned __int64)eLfanew + 24 >= SrcSize)
        return Result;

    pNt = (ULONG *)(pBase + eLfanew);                                // v8
    SectionCount  = *(WORD *)(pBase + eLfanew + 6);                  // v9  = FileHeader.NumberOfSections
    OptSize       = *(WORD *)(pBase + eLfanew + 20);                 // v10 = FileHeader.SizeOfOptionalHeader
    pSection0     = pBase + eLfanew + OptSize + 24;                  // v11 = 第一个节表项
    pSectionLast  = pSection0 + 40 * SectionCount - 40;              // v12
    HeaderEnd     = eLfanew + 40 * SectionCount + OptSize + 24;      // v13

    if (*pNt != IMAGE_NT_SIGNATURE || (SectionCount - 1) > 0x4E ||
        HeaderEnd >= SrcSize || OptSize >= SrcSize)
        return Result;

    SectionAlignment = pNt[14];   // OptionalHeader + 0x20
    FileAlignment    = pNt[15];   // OptionalHeader + 0x24
    SizeOfImage      = pNt[20];   // OptionalHeader + 0x38
    SizeOfHeaders    = pNt[21];   // OptionalHeader + 0x3C

    if (HeaderEnd > SizeOfImage || FileAlignment > 0x10000 || SectionAlignment > 0x10000)
        return Result;

    VaMask  = SectionAlignment - 1;                                  // v19
    RawMask = FileAlignment - 1;                                     // v22
    ImageLimit = ~VaMask & (VaMask + SizeOfImage);                   // v20：SizeOfImage 按 SectionAlignment 上对齐
    RawLimit   = *((ULONG *)pSectionLast + 3);                       // v18 = 最后一项 +0x0C = SizeOfRawData

    if (RawLimit > ImageLimit)
        return Result;
    {
        ULONG LastVa = *((ULONG *)pSectionLast + 2);                 // v21 = 最后一项 +0x08 = VirtualAddress
        if (LastVa >= ImageLimit || RawLimit + LastVa > ImageLimit)
            return Result;
    }
    if (RawMask > VaMask)
        return Result;

    /* ② 逐节校验：VA 须按 SectionAlignment 对齐、Raw 须按 FileAlignment 对齐且不越界 */
    i = 0;
    pSect = pSection0;
    if (SectionCount)
    {
        do
        {
            ULONG Va      = *(ULONG *)(pSect + 0x0C);   // v26 = VirtualAddress
            ULONG RawSize = *(ULONG *)(pSect + 0x10);   // v27 = SizeOfRawData
            ULONG RawPtr  = *(ULONG *)(pSect + 0x14);   // v28 = PointerToRawData

            if (Va > ImageLimit || (Va & VaMask) != 0)
                break;
            if (RawSize > SrcSize)
                break;
            if (RawPtr > SrcSize || RawPtr + RawSize > SrcSize)
                break;

            /* 非最后一项：还要求下一节的 VA 落在本节 VA+VirtualSize 之内（原始对 +0x10 与 +0x08 的比较） */
            if (pSect != pSectionLast)
            {
                ULONG NextVa = *(ULONG *)(pSect + 40 + 0x0C);          // v30 = 下一节 VirtualAddress
                if (Va > NextVa || Va + *(ULONG *)(pSect + 0x08) > NextVa)
                    break;
            }

            /* 用 FileAlignment 上对齐 SizeOfRawData，越界则回退为剩余空间 */
            {
                ULONG AlignedRaw = ~RawMask & (RawMask + RawSize);
                if (AlignedRaw > SrcSize)
                {
                    ULONG Adj = RawSize;
                    if (AlignedRaw > SrcSize - AlignedRaw)
                        Adj = SrcSize - AlignedRaw;
                    *(ULONG *)(pSect + 0x10) = Adj;
                }
                else
                    *(ULONG *)(pSect + 0x10) = AlignedRaw;
            }

            /* 用 SectionAlignment 上对齐 VirtualSize（+0x08） */
            {
                ULONG VirtSize = *(ULONG *)(pSect + 0x08);
                ULONG AlignedVirt = ~VaMask & (VaMask + VirtSize);
                if (i == 0)
                {
                    if (AlignedVirt > ImageLimit - Va)
                        AlignedVirt = ImageLimit - Va;
                    *(ULONG *)(pSect + 0x08) = AlignedVirt;
                }
                else
                {
                    PUCHAR pPrev = pSect - 40;
                    if (AlignedVirt > (*(ULONG *)(pPrev + 0x0C) + *(ULONG *)(pPrev + 0x10)) - Va)
                        break;
                    *(ULONG *)(pSect + 0x08) = AlignedVirt;
                }
            }

            ++i;
            pSect += 40;
        } while (i < SectionCount);

        if (i < SectionCount)
            return Result;
    }

    /* ③ 分配按 SectionAlignment 对齐的镜像缓冲，清零后拷头、逐节展开 */
    Buffer = (PUCHAR)ExAlloc(PagedPool, ImageLimit + 256);
    if (!Buffer)
        return Result;

    memset(Buffer, 0, ImageLimit + 256);

    {
        ULONG HeaderSize = SizeOfHeaders;
        if (SrcSize < HeaderSize)
            HeaderSize = SrcSize;
        memmove(Buffer, pBase, HeaderSize);
    }

    for (i = 0; i < SectionCount; i++)
    {
        PUCHAR p = pSection0 + 40 * i;
        memmove(Buffer + *(ULONG *)(p + 0x0C),
                pBase   + *(ULONG *)(p + 0x14),
                *(ULONG *)(p + 0x10));
    }

    Result = 1;
    *OutBuffer = Buffer;
    *OutSize = ImageLimit;
    return Result;
}