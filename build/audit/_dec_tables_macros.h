// ============================================================
// PE 解码表偏移宏 — 由 build/audit/extract_dec_tables.py 生成，禁止手改。
// 所有表都是原始驱动 .data 段主表区 0x96A30~0xA3710 的**切片**，
// 用统一镜像数组 + 偏移宏表达，保证逐字节保真且无切片/重叠错误。
// ============================================================
extern const UCHAR g_PeDecodeTableRegion[];    /* RVA 0x96A30, 52448 字节 */
extern const UCHAR g_PeDecodeTableSubGroup[];  /* RVA 0xA3790, 1600 字节 */

#define g_PeDecodeTableDefault  (&g_PeDecodeTableRegion[0x00000])   /* RVA 0x96A30, 320 字节 */
#define g_PeLegacyDescrambleTable  (&g_PeDecodeTableRegion[0x00020])   /* RVA 0x96A50, 5120 字节 */
#define g_PeDataDescrambleTable  (&g_PeDecodeTableRegion[0x01420])   /* RVA 0x97E50, 5120 字节 */
#define g_PeDecodeTableLegacy2  (&g_PeDecodeTableRegion[0x02820])   /* RVA 0x99250, 5120 字节 */
#define g_PeDecodeTableMode0  (&g_PeDecodeTableRegion[0x03C20])   /* RVA 0x9A650, 5120 字节 */
#define g_PeDecodeTableMode3  (&g_PeDecodeTableRegion[0x05020])   /* RVA 0x9BA50, 5120 字节 */
#define g_PeDecodeTableMode4  (&g_PeDecodeTableRegion[0x06420])   /* RVA 0x9CE50, 5120 字节 */
#define g_PeDecodeTablePrefixPtrA  (&g_PeDecodeTableRegion[0x07820])   /* RVA 0x9E250, 128 字节 */
#define g_PeDecodeTablePrefixPtrB  (&g_PeDecodeTableRegion[0x078A0])   /* RVA 0x9E2D0, 128 字节 */
#define g_PeDecodeTableGrp1  (&g_PeDecodeTableRegion[0x07BA0])   /* RVA 0x9E5D0, 960 字节 */
#define g_PeDecodeTableGrp2  (&g_PeDecodeTableRegion[0x07F60])   /* RVA 0x9E990, 320 字节 */
#define g_PeDecodeTableGrp3  (&g_PeDecodeTableRegion[0x080A0])   /* RVA 0x9EAD0, 320 字节 */
#define g_PeDecodeTableGrp4  (&g_PeDecodeTableRegion[0x081E0])   /* RVA 0x9EC10, 160 字节 */
#define g_PeDecodeTablePrefixM0  (&g_PeDecodeTableRegion[0x08280])   /* RVA 0x9ECB0, 160 字节 */
#define g_PeDecodeTablePrefixM1  (&g_PeDecodeTableRegion[0x08320])   /* RVA 0x9ED50, 160 字节 */
#define g_PeDecodeTablePrefixM3  (&g_PeDecodeTableRegion[0x083C0])   /* RVA 0x9EDF0, 160 字节 */
#define g_PeDecodeTableGrp5  (&g_PeDecodeTableRegion[0x08460])   /* RVA 0x9EE90, 160 字节 */
#define g_PeDecodeTableGrp6  (&g_PeDecodeTableRegion[0x08500])   /* RVA 0x9EF30, 160 字节 */
#define g_PeDecodeTableOneByte  (&g_PeDecodeTableRegion[0x085A0])   /* RVA 0x9EFD0, 160 字节 */
#define g_PeDecodeTableTwoByte0F  (&g_PeDecodeTableRegion[0x08640])   /* RVA 0x9F070, 320 字节 */
#define g_PeDecodeTableTwoByte38  (&g_PeDecodeTableRegion[0x08780])   /* RVA 0x9F1B0, 320 字节 */
#define g_PeDecodeTableTwoByte3A  (&g_PeDecodeTableRegion[0x088C0])   /* RVA 0x9F2F0, 320 字节 */
#define g_PeDecodeTableModrmReg  (&g_PeDecodeTableRegion[0x08A00])   /* RVA 0x9F430, 160 字节 */
#define g_PeDecodeTableModrmMem  (&g_PeDecodeTableRegion[0x08AA0])   /* RVA 0x9F4D0, 160 字节 */
#define g_PeDecodeTableOpcodeByte  (&g_PeDecodeTableRegion[0x08B40])   /* RVA 0x9F570, 160 字节 */
#define g_PeDecodeTableModrmOpcode  (&g_PeDecodeTableRegion[0x08BE0])   /* RVA 0x9F610, 5120 字节 */
#define g_PeDecodeTableMultiByte  (&g_PeDecodeTableRegion[0x09FE0])   /* RVA 0xA0A10, 11520 字节 */

/* 子表区 5 × 320 字节 */
#define g_PeDecodeTableSubGroup0  (&g_PeDecodeTableSubGroup[0x000])  /* RVA 0xA3790 */
#define g_PeDecodeTableSubGroup1  (&g_PeDecodeTableSubGroup[0x140])  /* RVA 0xA38D0 */
#define g_PeDecodeTableSubGroup2  (&g_PeDecodeTableSubGroup[0x280])  /* RVA 0xA3A10 */
#define g_PeDecodeTableSubGroup3  (&g_PeDecodeTableSubGroup[0x3C0])  /* RVA 0xA3B50 */
#define g_PeDecodeTableSubGroup4  (&g_PeDecodeTableSubGroup[0x500])  /* RVA 0xA3C90 */

/* 指针表（原始为 RVA 数组，本移植用本方地址重建） */
extern const ULONG64 g_PeDecodeTablePrefixPtrA[16];  /* 原 RVA 0x9E250 */
extern const ULONG64 g_PeDecodeTablePrefixPtrB[16];  /* 原 RVA 0x9E2D0 */
extern const ULONG64 g_PeMultiByteTable1[8];          /* 原 RVA 0xA3710 */
extern const ULONG64 g_PeMultiByteTable2[8];          /* 原 RVA 0xA3750 */
extern const ULONG64 g_PeDecodeTableSubtypePtr[16];   /* 原 RVA 0xCCEC0（全 0）*/
extern const ULONG64 g_PeDecodeTableDirectPtr[16];    /* 原 RVA 0xCCF40（全 0）*/
extern const ULONG64 g_PeDecodeFunctionTable[8];      /* 原 RVA 0xA3DD0 */
extern const ULONG g_PeDataTypeSizeTable[8];
extern const ULONG g_PeDataTypeSubTypeTable[4];

