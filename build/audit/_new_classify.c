// ClassifyDataTypeV1 — 按数据类型编号(1..38)分类操作数并设置标志/大小/偏移
// 对应原始驱动 0x14008ABB8（321 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（见下），按伪代码 1:1 转写。
// 【结构映射（与同族 FinalizeDataType/GetDataElementSize/SetDecoderStateFlags 一致）】
//   Context        = PE_DECODE_CONTEXT*
//   Context[3]     = Context+24 = 数据项指针 DataEntry（v1）
//   Context[4]     = Context+32 = 输出上下文 OutputContext（v3/v7）
//   Context[2]     = Context+16 = 上层上下文（校验 +16 的 bit23）
//   DataEntry+0    = 数据类型编号 v2
//   DataEntry+24   = 元素大小
//   DataEntry+32   = 标志位（QWORD）
//   DataEntry+40   = 偏移量
// 【逻辑】v2 == 0 → 返回 0；
//   v2 <= 8：偏移 = v2-1；若 OutputContext[0]==2 && (上层+16)&0x800000 &&
//     DataEntry == OutputContext+48 && (OutputContext[8]&0x40) && (OutputContext[11]&1)
//     则偏移 += 8；再按 OutputContext[2]（= *(DWORD*)(Context[4]+8)）分派：
//       1 → 标志 |= 0x20，大小 = 4
//       2 → 标志 |= 0x40，大小 = 8
//       其他 → 标志 |= 0x10，大小 = 2，且把类型号改为 v2+14
//   9..14 → 标志 |= 0x1000，偏移 = v2-9，大小 = 2
//   15..22 → 标志 |= 0x10，偏移 = v2-15，大小 = 2
//   23..30 → 标志 |= 8，   偏移 = v2-23，大小 = 1
//   31..38 → 标志 |= 0x80，偏移 = v2-31，大小 = 10
//   （15..38 各支在写入偏移前，还会做同一组 OutputContext 校验，
//     通过则偏移 += 8；>38 直接返回 0）
//   恒返回 0。
__int64 __fastcall ClassifyDataTypeV1(_QWORD *Context)
{
    __int64 DataEntry = Context[3];                 // v1 = Context+24
    int Type = *(_DWORD *)DataEntry;                // v2
    int Ofs;

    if (Type == 0)
        return 0;

    if (Type > 8)
    {
        _DWORD *OutCtx;
        int idx;

        if (Type <= 14)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x1000uLL;
            Ofs = Type - 9;
            *(_DWORD *)(DataEntry + 24) = 2;
            goto L_WRITE_OFS;
        }
        if (Type > 22)
        {
            if (Type > 30)
            {
                if (Type > 38)
                    return 0;
                *(_QWORD *)(DataEntry + 32) |= 0x80uLL;
                Ofs = Type - 31;
                *(_DWORD *)(DataEntry + 24) = 10;
                goto L_WRITE_OFS;
            }
            *(_QWORD *)(DataEntry + 32) |= 8uLL;
            idx = Type - 23;
            *(_DWORD *)(DataEntry + 24) = 1;
        }
        else
        {
            *(_QWORD *)(DataEntry + 32) |= 0x10uLL;
            idx = Type - 15;
            *(_DWORD *)(DataEntry + 24) = 2;
        }

        *(_DWORD *)(DataEntry + 40) = idx;
        OutCtx = (_DWORD *)Context[4];
        if (*OutCtx != 2
            || (*(_DWORD *)(Context[2] + 16) & 0x800000) == 0
            || (_DWORD *)DataEntry != OutCtx + 12
            || (OutCtx[8] & 0x40) == 0
            || (OutCtx[11] & 1) == 0)
            return 0;
        Ofs = idx + 8;

    L_WRITE_OFS:
        *(_DWORD *)(DataEntry + 40) = Ofs;
        return 0;
    }

    // ---- Type <= 8 ----
    *(_DWORD *)(DataEntry + 40) = Type - 1;
    {
        _DWORD *OutCtx = (_DWORD *)Context[4];
        if (*OutCtx == 2
            && (*(_DWORD *)(Context[2] + 16) & 0x800000) != 0
            && (_DWORD *)DataEntry == OutCtx + 12
            && (OutCtx[8] & 0x40) != 0
            && (OutCtx[11] & 1) != 0)
        {
            *(_DWORD *)(DataEntry + 40) = Type - 1 + 8;
        }
    }

    {
        int Mode = *(_DWORD *)(Context[4] + 8);     // v4
        if (Mode == 1)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x20uLL;
            *(_DWORD *)(DataEntry + 24) = 4;
        }
        else if (Mode == 2)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x40uLL;
            *(_DWORD *)(DataEntry + 24) = 8;
        }
        else
        {
            *(_QWORD *)(DataEntry + 32) |= 0x10uLL;
            *(_DWORD *)(DataEntry + 24) = 2;
            *(_DWORD *)DataEntry = Type + 14;
        }
    }
    return 0;
}

// ClassifyDataTypeV2 — 同 V1，但 64 位模式下偏移量处理略有不同
// 对应原始驱动 0x14008ACFC（325 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写。
// 【与 V1 的唯一差异】Type <= 8 且 Mode == 2 时，V1 只设 标志|=0x40/大小=8；
//   V2 **额外**把偏移量覆盖为 (Type-1)（即取消上面可能的 +8）。
__int64 __fastcall ClassifyDataTypeV2(_QWORD *Context)
{
    __int64 DataEntry = Context[3];
    int Type = *(_DWORD *)DataEntry;
    int Ofs;

    if (Type == 0)
        return 0;

    if (Type > 8)
    {
        _DWORD *OutCtx;
        int idx;

        if (Type <= 14)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x1000uLL;
            Ofs = Type - 9;
            *(_DWORD *)(DataEntry + 24) = 2;
            goto L_WRITE_OFS;
        }
        if (Type > 22)
        {
            if (Type > 30)
            {
                if (Type > 38)
                    return 0;
                *(_QWORD *)(DataEntry + 32) |= 0x80uLL;
                Ofs = Type - 31;
                *(_DWORD *)(DataEntry + 24) = 10;
                goto L_WRITE_OFS;
            }
            *(_QWORD *)(DataEntry + 32) |= 8uLL;
            idx = Type - 23;
            *(_DWORD *)(DataEntry + 24) = 1;
        }
        else
        {
            *(_QWORD *)(DataEntry + 32) |= 0x10uLL;
            idx = Type - 15;
            *(_DWORD *)(DataEntry + 24) = 2;
        }

        *(_DWORD *)(DataEntry + 40) = idx;
        OutCtx = (_DWORD *)Context[4];
        if (*OutCtx != 2
            || (*(_DWORD *)(Context[2] + 16) & 0x800000) == 0
            || (_DWORD *)DataEntry != OutCtx + 12
            || (OutCtx[8] & 0x40) == 0
            || (OutCtx[11] & 1) == 0)
            return 0;
        Ofs = idx + 8;

    L_WRITE_OFS:
        *(_DWORD *)(DataEntry + 40) = Ofs;
        return 0;
    }

    // ---- Type <= 8 ----
    Ofs = Type - 1;                                  // v3（V2 单独保存）
    *(_DWORD *)(DataEntry + 40) = Type - 1;
    {
        _DWORD *OutCtx = (_DWORD *)Context[4];
        if (*OutCtx == 2
            && (*(_DWORD *)(Context[2] + 16) & 0x800000) != 0
            && (_DWORD *)DataEntry == OutCtx + 12
            && (OutCtx[8] & 0x40) != 0
            && (OutCtx[11] & 1) != 0)
        {
            *(_DWORD *)(DataEntry + 40) = Ofs + 8;
        }
    }

    {
        int Mode = *(_DWORD *)(Context[4] + 8);
        if (Mode == 1)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x20uLL;
            *(_DWORD *)(DataEntry + 24) = 4;
        }
        else if (Mode == 2)
        {
            *(_QWORD *)(DataEntry + 32) |= 0x40uLL;
            *(_DWORD *)(DataEntry + 40) = Ofs;       // 覆盖偏移（V2 特有）
            *(_DWORD *)(DataEntry + 24) = 8;
        }
        else
        {
            *(_QWORD *)(DataEntry + 32) |= 0x10uLL;
            *(_DWORD *)(DataEntry + 24) = 2;
            *(_DWORD *)DataEntry = Type + 14;
        }
    }
    return 0;
}