// ParseUSBPortSyscallStubs — 通过导出名 USBPORT_RegisterUSBPortDriver 定位节区并登记偏移表
// 对应原始驱动 0x140055610（590 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— 该函数是 _FINAL_GAP.json 的
//   A_definite_missing（源码中此前完全缺失，导致 InitUSBPortSyscallTable 装入后
//   LNK2001）。代码内标注 `L_<地址>`。
//
// 【帧定基（序言 + 描述符锚点交叉验证）】
//   push rbp,rbx,rsi,r12,r13,r14,r15(0x38) → lea rbp,[rsp-0x130] → sub rsp,0x230
//   故 rbp = 入口 rsp - 0x168。
//   - 节区描述符基址 = rbp-0x60（0x140055718 `lea rdx,[rbp-0x60]` 作第 2 参）
//     故 desc+N ≡ rbp+(N-0x60)。实测锚点自洽：
//       desc+0xF0(推进量)=rbp+0x90   desc+0x118(类型指针)=rbp+0xB8
//       desc+0x50=rbp-0x10           desc+0x58=rbp-0x08
//       desc+0x88=rbp+0x28           desc+0x40=rbp-0x20   desc+0x8C=rbp+0x2C?
//       （0x1400557c7 读 [rbp+0x7c] 与 0x1400557d8 读 [rbp-0x20] 亦在该布局内）
//   - 索引表 = rbp+0xE0（0x140055705 memset 0x40；0x14005578a `[rbp+rax*4+0xe0]`）
//   - 读取上下文 = rsp+0x50；读指针 = rsp+0x58 = ctx+8
//   - 输出表（第 3 实参 r15）= 第 3 参 r8；文件缓冲 = [rsp+0x40]
//
// 【算法】
//   ① Loaded = GtRead(0x8DA)，为 0 即返回；
//   ② 调 FindExportByNameInPeBody(ImageBase, ImageSize, L"USBPORT_RegisterUSBPortDriver")
//      → 返回该导出的 RVA；要求非 0 且 < ImageSize；
//   ③ 以 (ImageBase+rva, ImageSize-(ImageBase+rva)+rva) 初始化读取上下文；
//      memset(IndexTable, 0, 0x40)；
//   ④ 循环最多 0x1F4 轮 ReadPESectionEntry：
//      · 类型 0x545 → 立即结束；
//      · 类型 0x512 且 desc+0x88==0x40000、desc+0x18!=0、desc+0x50==0x40、
//        算出的 RVA 非 0 且 < ImageSize → IndexTable[desc+0x58] = RVA；
//      · 类型 0x473 → memset(IndexTable, 0, 0x40)；
//      · 类型 0x50E 且 desc+0x50 的 bit14/bit6 置位、(desc+0x8C & 0xF) != 4、
//        desc+0x88==0x40、(desc+0x40-0x70) <= 0xD8 且 4 字节对齐、k<=0x1B、
//        IndexTable[desc+0x90] 非零、输出表槽为空 → 写入 (rva, rva+Loaded) 并置 Found。
//   ⑤ 返回 Found。
UCHAR ParseUSBPortSyscallStubs(PUCHAR ImageBase, ULONG ImageSize, __int64 OutTable)
{
    UCHAR   Desc[0x120];         // rbp-0x60
    PE_DECODE_CONTEXT ReadContext;   // rsp+0x50
    ULONG   IndexTable[16];      // rbp+0xE0（0x40 字节）
    ULONG64 Loaded;              // r12 = GtRead(0x8DA)
    ULONG64 FileBuf;             // [rsp+0x40]
    ULONG   Rva;
    ULONG   i;
    UCHAR   Found;               // r12b

    Loaded = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8DA);      // 0x14005564C
    Found = 0;
    if (!Loaded)                                             // 0x140055656
        return Found;

    // 0x14005565F~6B1：栈上构造 L"USBPORT_RegisterUSBPortDriver"
    {
        UCHAR SecName[0x20];
        *(ULONG *)&SecName[0x00] = 0x50425355;   // "USBP"
        *(ULONG *)&SecName[0x04] = 0x5f54524f;   // "ORT_"
        *(ULONG *)&SecName[0x08] = 0x69676552;   // "Regi"
        *(ULONG *)&SecName[0x0C] = 0x72657473;   // "ster"
        *(ULONG *)&SecName[0x10] = 0x50425355;   // "USBP"
        *(ULONG *)&SecName[0x14] = 0x4474726f;   // "ortD"
        *(ULONG *)&SecName[0x18] = 0x65766972;   // "rive"
        *(ULONG *)&SecName[0x1C] = 0x00000072;   // "r\0\0\0"

        Rva = (ULONG)FindExportByNameInPeBody(ImageBase, ImageSize,   // 0x1400556BB
                                              (PCHAR)SecName, 0);
        if (Rva == 0 || Rva >= ImageSize)                    // 0x1400556C0/C8
            return Found;

        // 0x1400556D0~6FE：初始化读取上下文
        {
            ULONG Base = (ULONG)(ULONG_PTR)ImageBase + Rva;  // 0x1400556D8
            ULONG Size = ImageSize - Base + Rva;             // 0x1400556FA/6FC
            InitPESectionReadContext((__int64)Base, Size,
                                     2, 0, -1, 0, 0, (__int64)&ReadContext);
        }
        FileBuf = (ULONG64)ImageBase;                        // [rsp+0x40]（0x140055651 存的是 GtRead 结果）
    }

    memset(IndexTable, 0, sizeof(IndexTable));               // 0x140055710（0x40 字节）

    for (i = 0; i < 0x1F4; ++i)                              // 0x14005582C cmp r14d,1F4h
    {
        ULONG   Type;
        ULONG64 Chk50;

        if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc) != 0)   // 0x140055721
            return Found;                                    // 0x140055728

        // 0x14005572E~743：上下文读指针 += 指令长度
        ReadContext.ReadPtr += *(ULONG *)(Desc + 0xF0);

        Type  = *(USHORT *)(*(ULONG64 *)(Desc + 0x118) + 6);  // 0x140055748
        Chk50 = *(ULONG64 *)(Desc + 0x50);                    // 0x140055775 用

        if (Type == 0x545)                                   // 0x140055751
            return Found;

        if (Type == 0x512                                  // 0x14005575F
            && *(ULONG64 *)(Desc + 0x88) == 0x40000UL      // 0x140055764
            && *(ULONG *)(Desc + 0x18) != 0                // 0x14005576E/771
            && Chk50 == 0x40)                              // 0x140055775
        {
            ULONG r = *(ULONG *)(Desc + 0x18) - (ULONG)(ULONG_PTR)ImageBase
                      + (ULONG)ReadContext.ReadPtr;        // 0x14005577C/77F
            if (r != 0 && r < ImageSize)                   // 0x140055781/783
                IndexTable[*(ULONG *)(Desc + 0x58)] = r;   // 0x140055787/78A（原始无掩码）
        }

        if (Type == 0x473)                                 // 0x140055796
            memset(IndexTable, 0, sizeof(IndexTable));     // 0x1400557A8

        if (Type == 0x50E                                   // 0x1400557B2
            && (Chk50 & 0x14000ULL) != 0                    // 0x1400557B7
            && (Chk50 & 0x40ULL) != 0                       // 0x1400557C1
            && (*(ULONG *)(Desc + 0x8C) & 0xF) != 4         // 0x1400557C7~7CF
            && *(ULONG64 *)(Desc + 0x88) == 0x40UL          // 0x1400557D1
            && (*(ULONG *)(Desc + 0x40) - 0x70) <= 0xD8     // 0x1400557D8~7E4
            && (*(ULONG *)(Desc + 0x40) & 7) == 0           // 0x1400557E6/7E9
            && ((*(ULONG *)(Desc + 0x40) - 0x70) >> 3) <= 0x1B)   // 0x1400557ED/7F0
        {
            ULONG k = (*(ULONG *)(Desc + 0x40) - 0x70) >> 3;   // 0x1400557ED
            ULONG v = IndexTable[*(ULONG *)(Desc + 0x90)];     // 0x1400557F5/7F8
            if (v != 0                                          // 0x140055800
                && *(ULONG *)(OutTable + (ULONG64)k * 0x30 + 4) == 0)   // 0x14005580C
            {
                Found = 1;                                      // 0x140055817
                *(ULONG  *)(OutTable + (ULONG64)k * 0x30 + 4) = v;       // 0x14005581A
                *(ULONG64*)(OutTable + (ULONG64)k * 0x30 + 8) =
                    (ULONG64)v + (ULONG64)ImageBase;            // 0x14005581F/824
            }
        }
    }

    (void)FileBuf;
    return Found;                                             // 0x140055839
}