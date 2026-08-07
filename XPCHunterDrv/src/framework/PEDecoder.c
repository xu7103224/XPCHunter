// PEDecoder.c — PE 指令解码器
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动地址范围 0x14008A4B8-0x14008C7C4
//
// 功能：自定义 x86/x64 指令解码器，用于解析 PE 节区字节流，
// 支持 16/32/64 位模式、ModRM 寻址、前缀解码、多字节操作码等

#include "XPCHunterDrv.h"

// 前向声明
__int64 ClassifyPESectionType(PUCHAR Context);

// ============================================================
// 辅助宏定义
// ============================================================
#define CTX_Q(Base, Offs)     (*(ULONG64 *)((PUCHAR)(Base) + (Offs)))
#define CTX_D(Base, Offs)     (*(ULONG *)((PUCHAR)(Base) + (Offs)))
#define CTX_W(Base, Offs)     (*(USHORT *)((PUCHAR)(Base) + (Offs)))
#define CTX_B(Base, Offs)     (*(UCHAR *)((PUCHAR)(Base) + (Offs)))
#define SET_Q(Base, Offs, V)  (*(ULONG64 *)((PUCHAR)(Base) + (Offs)) = (ULONG64)(V))
#define SET_D(Base, Offs, V)  (*(ULONG *)((PUCHAR)(Base) + (Offs)) = (ULONG)(V))
#define SET_W(Base, Offs, V)  (*(USHORT *)((PUCHAR)(Base) + (Offs)) = (USHORT)(V))
#define SET_B(Base, Offs, V)  (*(UCHAR *)((PUCHAR)(Base) + (Offs)) = (UCHAR)(V))

// ============================================================
// 上下文偏移常量（基于 PE_DECODE_CONTEXT 结构）
// ============================================================
#define DEC_CTX_DECODE_TABLE_PTR    0x00  // QWORD: 解码表指针
#define DEC_CTX_BUFFER_BASE         0x08  // QWORD: 缓冲区基址
#define DEC_CTX_BUFFER_END          0x10  // QWORD: 缓冲区结束
#define DEC_CTX_MODE                0x18  // DWORD: 模式
#define DEC_CTX_MODE_DUP            0x1C  // DWORD: 模式副本
#define DEC_CTX_ADDR_SIZE           0x20  // DWORD: 地址大小模式
#define DEC_CTX_OPERAND_SIZE        0x24  // DWORD: 操作数大小模式
#define DEC_CTX_STATE_FLAGS         0x28  // DWORD: 状态标志
#define DEC_CTX_LAST_OPCODE_BYTE    0x2C  // BYTE: 最后操作码字节
#define DEC_CTX_OPERANDS            0x30  // 操作数数组 (3 * 56 = 168 字节)
#define DEC_CTX_OPERAND_COUNT       0xD8  // DWORD: 操作数计数
#define DEC_CTX_EXTRA_FIELD         0xDC  // DWORD: 额外字段
#define DEC_CTX_INSTRUCTION_COUNT   0xE0  // DWORD: 指令计数
#define DEC_CTX_PARAM4              0xE8  // QWORD: 参数 4
#define DEC_CTX_PARAM5              0xF0  // QWORD: 参数 5
#define DEC_CTX_PARAM6              0xF8  // QWORD: 参数 6
#define DEC_CTX_PARAM7              0x100 // QWORD: 参数 7
#define DEC_CTX_FUNC_TABLE          0x108 // QWORD: 解码函数表指针 (由 ReadPESectionEntry 设置)
#define DEC_CTX_EXTRA_ENTRY         0x110 // QWORD: 额外条目
#define DEC_CTX_CUR_TABLE_ENTRY     0x118 // QWORD: 当前解码表条目 (由 DispatchInstructionDecode 设置)
#define DEC_CTX_SUB_DECODE_TABLE    0x160 // QWORD: 子解码表指针 (MultiByte 子表)

// 输出上下文额外偏移
#define DEC_CTX_LAST_OPCODE_SAVE    0xE4  // BYTE: 保存的最后操作码字节
#define DEC_CTX_INSTR_IDX           0xEA  // WORD: 指令索引
#define DEC_CTX_RESULT_PTR          0xE8  // QWORD: 结果指针 (与 PARAM4 重叠)

// 操作数字段偏移 (每个 56 字节)
#define DEC_OP_DECODED_VALUE        0x00  // QWORD: 解码后的值
#define DEC_OP_FLAGS                0x08  // QWORD: 标志位
#define DEC_OP_REG_INDEX            0x10  // DWORD: 寄存器索引
#define DEC_OP_SIZE                 0x14  // DWORD: 大小
#define DEC_OP_DATA_TYPE            0x18  // DWORD: 数据类型
#define DEC_OP_SUB_TYPE             0x1C  // DWORD: 子类型
#define DEC_OP_EXTRA_FLAGS          0x20  // DWORD: 额外标志
#define DEC_OP_VALUE                0x30  // QWORD: 实际值
#define DEC_OP_VALUE_SIZE           0x38  // DWORD: 值大小

// 操作数 0 基址
#define DEC_OP0_BASE                0x30
#define DEC_OP1_BASE                0x68
#define DEC_OP2_BASE                0xA0

// 状态标志位
#define DEC_SF_ADDR16      0x01  // 16 位地址模式
#define DEC_SF_OP16        0x02  // 16 位操作数模式
#define DEC_SF_REX         0x04  // REX 前缀存在
#define DEC_SF_SEG_CS      0x08  // CS 段前缀
#define DEC_SF_SEG_SS      0x10  // SS 段前缀
#define DEC_SF_SEG_DS      0x20  // DS 段前缀
#define DEC_SF_SEG_ES      0x40  // ES 段前缀
#define DEC_SF_LOCK        0x80  // LOCK 前缀

// ============================================================
// InitPESectionReadContext — 初始化 PE 节区读取上下文
// 对应原始驱动 sub_14008A7E4
// ============================================================
void InitPESectionReadContext(
    __int64 Base,
    ULONG Size,
    INT Mode,
    LONG64 Param5,
    INT ExtraField,
    LONG64 Param6,
    LONG64 Param7,
    __int64 Context)
{
    SET_Q(Context, DEC_CTX_BUFFER_BASE, Base);
    SET_D(Context, DEC_CTX_MODE, Mode);
    SET_Q(Context, DEC_CTX_BUFFER_END, (ULONG64)(Base + Size));
    SET_D(Context, DEC_CTX_MODE_DUP, Mode);
    SET_D(Context, DEC_CTX_EXTRA_FIELD, ExtraField);
    SET_Q(Context, DEC_CTX_PARAM5, Param5);
    SET_Q(Context, DEC_CTX_PARAM6, Param6);
    SET_Q(Context, DEC_CTX_PARAM7, Param7);

    if (Mode == 2)
    {
        SET_D(Context, DEC_CTX_ADDR_SIZE, 1);
        SET_Q(Context, DEC_CTX_DECODE_TABLE_PTR, (ULONG64)g_PeDataDescrambleTable);
    }
    else
    {
        SET_D(Context, DEC_CTX_ADDR_SIZE, Mode);
        SET_Q(Context, DEC_CTX_DECODE_TABLE_PTR, (ULONG64)g_PeLegacyDescrambleTable);
    }
}

// ============================================================
// ReadPESectionEntry — 读取 PE 节区条目
// 对应原始驱动 sub_14008A54C
// 解析 PE 文件中的节区指令字节，初始化结果结构体，
// 遍历指令字节流并分发到指令解码器
// ============================================================
__int64 ReadPESectionEntry(PUCHAR Context, PULONG SectionInfo)
{
    ULONG Result = (ULONG)-1;
    ULONG ByteIndex = 0;
    PUCHAR BufferPos;
    ULONG64 DecodeTablePtr;
    ULONG64 TableEntry;
    USHORT TypeField;
    ULONG NewFlags;
    int DispatchResult;

    RtlZeroMemory(SectionInfo, 0x120);

    // 初始化输出结构体
    SET_B(SectionInfo, DEC_CTX_LAST_OPCODE_BYTE, 0xFF);
    SET_D(SectionInfo, DEC_CTX_OPERAND_SIZE, 3);
    SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, 0);

    SET_D(SectionInfo, DEC_CTX_MODE, CTX_D(Context, DEC_CTX_MODE));
    SET_D(SectionInfo, DEC_CTX_MODE_DUP, CTX_D(Context, DEC_CTX_MODE_DUP));
    SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, CTX_D(Context, DEC_CTX_ADDR_SIZE));
    SET_D(SectionInfo, DEC_CTX_EXTRA_FIELD, CTX_D(Context, DEC_CTX_EXTRA_FIELD));
    SET_Q(SectionInfo, DEC_CTX_PARAM5, CTX_Q(Context, DEC_CTX_PARAM5));
    SET_Q(SectionInfo, DEC_CTX_PARAM6, CTX_Q(Context, DEC_CTX_PARAM6));
    SET_Q(SectionInfo, DEC_CTX_FUNC_TABLE, (ULONG64)g_PeDecodeFunctionTable);

    BufferPos = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    DecodeTablePtr = CTX_Q(Context, DEC_CTX_DECODE_TABLE_PTR);

    if (BufferPos >= (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END))
        return Result;

    ByteIndex = 0;

    while (1)
    {
        UCHAR OpcodeByte = *BufferPos;
        TableEntry = DecodeTablePtr + 20 * OpcodeByte;
        TypeField = *(USHORT *)(TableEntry + 4);

        if (TypeField > 6)
            break;

        ++ByteIndex;

        if ((CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) & 0x40) != 0)
            goto LABEL_ERROR;

        if (TypeField == 5)
        {
            // Type 5: 设置 64 位标志
            SET_D(SectionInfo, DEC_CTX_STATE_FLAGS,
                  CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) | 0x40);
            CTX_D(SectionInfo, DEC_CTX_LAST_OPCODE_BYTE) = *(USHORT *)(TableEntry + 8) - 50;
            if ((CTX_D(SectionInfo, DEC_CTX_LAST_OPCODE_BYTE) & 8) != 0)
                SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, 2);
            goto LABEL_CONTINUE;
        }

        NewFlags = CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) & 0xFFFFFFBF;
        SET_B(SectionInfo, DEC_CTX_LAST_OPCODE_BYTE, (UCHAR)TypeField);
        SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags);

        if (TypeField)
        {
            switch (TypeField)
            {
                case 1:  // 操作数大小切换
                    if ((NewFlags & 1) != 0)
                        goto LABEL_ERROR;
                    SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 1);
                    if (CTX_D(SectionInfo, DEC_CTX_MODE))
                        SET_D(SectionInfo, DEC_CTX_MODE_DUP,
                              CTX_D(SectionInfo, DEC_CTX_MODE) != 1);
                    else
                        SET_D(SectionInfo, DEC_CTX_MODE_DUP, 1);
                    break;

                case 4:  // SS 段前缀
                    if ((NewFlags & 0x30) != 0)
                        goto LABEL_ERROR;
                    SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 0x10);
                    break;

                case 3:  // DS 段前缀
                    if ((NewFlags & 0x30) != 0)
                        goto LABEL_ERROR;
                    SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 0x20);
                    break;

                case 2:  // 地址大小切换
                    if ((NewFlags & 8) != 0)
                        goto LABEL_ERROR;
                    CTX_D(SectionInfo, DEC_CTX_OPERAND_SIZE) = *(USHORT *)(TableEntry + 8) - 9;
                    if (CTX_D(SectionInfo, DEC_CTX_MODE) != 2 ||
                        CTX_D(SectionInfo, DEC_CTX_OPERAND_SIZE) >= 4)
                    {
                        SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 8);
                    }
                    break;

                default:  // REX 前缀
                    if ((NewFlags & 4) != 0)
                        goto LABEL_ERROR;
                    SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 4);
                    break;
            }
        }
        else
        {
            // Type 0: 操作数大小切换（16/32 位）
            if ((NewFlags & 2) != 0)
                goto LABEL_ERROR;
            SET_D(SectionInfo, DEC_CTX_STATE_FLAGS, NewFlags | 2);
            SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, !CTX_D(SectionInfo, DEC_CTX_MODE));
        }

LABEL_CONTINUE:
        ++BufferPos;
        if (BufferPos >= (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END))
        {
            CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD) |= 4;
            break;
        }
    }

    // 循环结束后的处理
    if (CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD))
    {
        if (CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD) == 2)
        {
            ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                          CTX_Q(Context, DEC_CTX_PARAM5);
            SET_D(SectionInfo, DEC_CTX_EXTRA_FIELD, 0);
            SET_D(SectionInfo, DEC_CTX_INSTRUCTION_COUNT, 1);
            SET_Q(SectionInfo, DEC_CTX_PARAM4, ResultBase);
            SET_Q(SectionInfo, 0x118, DecodeTablePtr + 2880);
            return 0;
        }
    }
    else
    {
        // 正常完成：分发到指令解码器
        SET_B(SectionInfo, DEC_CTX_LAST_OPCODE_SAVE, *BufferPos);
        ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                      CTX_Q(Context, DEC_CTX_PARAM5);
        SET_W(SectionInfo, DEC_CTX_INSTR_IDX, ByteIndex);
        SET_Q(SectionInfo, DEC_CTX_PARAM4, ResultBase);

        DispatchResult = (int)DispatchInstructionDecode(
            (ULONG64)(BufferPos + 1),
            CTX_Q(Context, DEC_CTX_BUFFER_END),
            DecodeTablePtr + 20 * (UCHAR)*BufferPos,
            (ULONG64)SectionInfo);

        if (DispatchResult == -1)
        {
            CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD) |= 4;
        }
        else
        {
            SET_D(SectionInfo, DEC_CTX_INSTRUCTION_COUNT,
                  ByteIndex + DispatchResult + 1);
            if ((CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) & 4) != 0)
                ClassifyPESectionType((ULONG64)SectionInfo);
            return 0;
        }
    }

    return Result;

LABEL_ERROR:
    CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD) |= 2;
    // 继续执行到函数末尾的错误处理
    if (CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD))
    {
        if (CTX_D(SectionInfo, DEC_CTX_EXTRA_FIELD) == 2)
        {
            ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                          CTX_Q(Context, DEC_CTX_PARAM5);
            SET_D(SectionInfo, DEC_CTX_EXTRA_FIELD, 0);
            SET_D(SectionInfo, DEC_CTX_INSTRUCTION_COUNT, 1);
            SET_Q(SectionInfo, DEC_CTX_PARAM4, ResultBase);
            SET_Q(SectionInfo, 0x118, DecodeTablePtr + 2880);
            return 0;
        }
    }
    return Result;
}

// ============================================================
// ClassifyPESectionType — 分类 PE 节区类型
// 对应原始驱动 sub_14008A4B8
// 根据节区的特征标志和类型描述符判断节区所属的类型类别
// ============================================================
__int64 ClassifyPESectionType(PUCHAR Context)
{
    ULONG64 TableEntry = CTX_Q(Context, DEC_CTX_CUR_TABLE_ENTRY);
    USHORT TypeField = *(USHORT *)(TableEntry + 4);
    ULONG StateFlags;
    ULONG Result;

    if (TypeField <= 0xDA)
    {
        if (TypeField != 218)
        {
            // 检查是否在 bitmask 集合中 (0-0x30 中的特定值, 或 100-101)
            if (TypeField <= 0x30)
            {
                ULONG64 BitMask = 0x1400000061580LL;
                if ((BitMask >> TypeField) & 1)
                    goto CHECK_STATE_FLAGS;
            }
            if (TypeField - 100 <= 1)
                goto CHECK_STATE_FLAGS;

            goto SET_DEFAULT_TYPE;
        }
        goto CHECK_64BIT_MODE;
    }

    Result = TypeField - 221;
    if (Result <= 0xC)
    {
        INT BitTest = 4357;
        if ((BitTest >> Result) & 1)
        {
CHECK_64BIT_MODE:
            Result = CTX_D(Context, DEC_CTX_EXTRA_FIELD) & 0x300;
            if (Result == 0x300)
                goto CHECK_STATE_FLAGS;
            return Result;
        }
    }

    if (TypeField <= 0x1ED)
        goto SET_DEFAULT_TYPE;
    if (TypeField <= 0x1EF)
        goto CHECK_STATE_FLAGS;
    if (TypeField != 512)
        goto SET_DEFAULT_TYPE;
    return Result;

CHECK_STATE_FLAGS:
    StateFlags = CTX_D(Context, 0x50);  // offset 0x50 = 操作数 0 的 Flags
    if (StateFlags & 0x7C003)
        return StateFlags;
    // fall through

SET_DEFAULT_TYPE:
    SET_Q(Context, DEC_CTX_CUR_TABLE_ENTRY, (ULONG64)&g_PeDecodeTableMode0[0x190]);  // unk_14009932C
    return (ULONG64)&g_PeDecodeTableMode0[0x190];
}

// ============================================================
// CalcPESectionFieldSize — 计算 PE 节区字段大小
// 对应原始驱动 sub_14008A844
// 根据数据类型(1=32位,2=64位)返回对应的字段大小
// ============================================================
__int64 CalcPESectionFieldSize(PUCHAR Context)
{
    INT OperandSize = CTX_D(Context, DEC_CTX_OPERAND_SIZE);
    ULONG64 Result;

    if (OperandSize == 1)
        Result = 4;
    else if (OperandSize == 2)
        Result = 8;
    else
        Result = 2;

    // 缓冲区边界检查
    if (CTX_Q(Context, DEC_CTX_BUFFER_BASE) + (INT)Result >
        CTX_Q(Context, DEC_CTX_BUFFER_END))
        return (ULONG64)-1;

    return Result;
}

// ============================================================
// CalcPESectionFieldSizeAlt — 计算 PE 节区字段大小(备选)
// 对应原始驱动 sub_14008A9E8
// 根据数据类型非零/零返回 4 或 2 字节字段大小
// ============================================================
__int64 CalcPESectionFieldSizeAlt(PUCHAR Context)
{
    ULONG64 Result = CTX_D(Context, DEC_CTX_OPERAND_SIZE) != 0 ? 4 : 2;

    if (CTX_Q(Context, DEC_CTX_BUFFER_BASE) + (INT)Result >
        CTX_Q(Context, DEC_CTX_BUFFER_END))
        return (ULONG64)-1;

    return Result;
}

// ============================================================
// ReadPESectionField — 读取 PE 节区数据字段
// 对应原始驱动 sub_14008A87C
// 根据类型指示字(word 或 dword)从节区中读取相应大小的数据值
// ============================================================
__int64 ReadPESectionField(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM5);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    INT OperandSize = CTX_D(DecodeContext, DEC_CTX_OPERAND_SIZE);
    ULONG64 Value;
    ULONG FieldSize;
    ULONG64 Flags;

    if (!OperandSize)
    {
        // word 模式 (2 字节)
        if (BufferBase + 1 >= BufferEnd)
            return (ULONG64)-1;

        FieldSize = 2;
        SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 2);
        Value = *(USHORT *)BufferBase;
        Flags = 0x200000;
    }
    else
    {
        // dword 或 qword 模式
        if (BufferBase + 3 >= BufferEnd)
            return (ULONG64)-1;

        FieldSize = 4;
        SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 4);

        if (OperandSize != 2)
        {
            // dword
            Value = *(ULONG *)BufferBase;
            Flags = 0x800000;
        }
        else
        {
            // qword
            Value = *(ULONG64 *)BufferBase;
            Flags = 0x2000000;
            FieldSize = 8;
        }
    }

    CTX_Q(OutputContext, 0x20) |= Flags;  // 输出标志
    SET_D(OutputContext, 6, FieldSize);    // 设置大小
    SET_Q(OutputContext, 8, Value);        // 设置值
    return FieldSize;
}

// ============================================================
// ReadPESectionFieldByte — 读取 PE 节区单字节字段
// 对应原始驱动 sub_14008A904
// ============================================================
__int64 ReadPESectionFieldByte(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM5);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    ULONG64 Value = *BufferBase;
    SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 1);
    CTX_Q(OutputContext, 0x20) |= 0x100000;  // 设置标志
    SET_D(OutputContext, 6, 1);               // 大小 = 1
    SET_Q(OutputContext, 8, Value);           // 值
    return 1;
}

// ============================================================
// ReadPESectionAsmField — 读取 PE 节区汇编指令字段
// 对应原始驱动 sub_14008A93C
// 根据汇编语法格式读取操作数大小(字节/字/双字/四字)
// ============================================================
__int64 ReadPESectionAsmField(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM5);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    INT OperandSize = CTX_D(DecodeContext, DEC_CTX_OPERAND_SIZE);
    ULONG64 Value;
    ULONG FieldSize;
    ULONG64 Flags;

    if (OperandSize == 1)
    {
        // 32 位模式
        if (BufferBase + 3 >= BufferEnd)
            return (ULONG64)-1;

        FieldSize = 4;
        SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 4);
        Value = *(ULONG *)BufferBase;
        Flags = 0x1000000;
        SET_D(OutputContext, 6, 4);
    }
    else if (OperandSize == 2)
    {
        // 64 位模式
        if (BufferBase + 3 >= BufferEnd && BufferBase + 1 < BufferEnd)
        {
            // word 回退
            FieldSize = 2;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 2);
            Value = *(USHORT *)BufferBase;
            Flags = 0x400000;
            SET_D(OutputContext, 6, 2);
        }
        else if (BufferBase + 3 < BufferEnd)
        {
            // qword (4 字节读取 + 符号扩展)
            FieldSize = 4;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 4);
            Value = *(INT *)BufferBase;  // 符号扩展
            Flags = 0x4000000;
            SET_D(OutputContext, 6, 8);
        }
        else
        {
            return (ULONG64)-1;
        }
    }
    else
    {
        // 16 位模式
        if (BufferBase + 1 >= BufferEnd)
            return (ULONG64)-1;

        FieldSize = 2;
        SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 2);
        Value = *(USHORT *)BufferBase;
        Flags = 0x400000;
        SET_D(OutputContext, 6, 2);
    }

    CTX_Q(OutputContext, 0x20) |= Flags;
    SET_Q(OutputContext, 8, Value);
    return FieldSize;
}

// ============================================================
// SerializeDataToBuffer — 序列化数据到缓冲区
// 对应原始驱动 sub_14008AA0C
// 根据数据类型从缓冲区读取并序列化编码后的数据值
// ============================================================
__int64 SerializeDataToBuffer(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM5);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    INT DataType = CTX_D(DecodeContext, DEC_CTX_OPERAND_SIZE);
    ULONG64 Value;
    ULONG FieldSize;
    ULONG64 Flags;
    ULONG OutputSize;

    if (DataType == 1)
    {
        // 类型 1: 6 字节读取
        if ((CTX_D(OutputContext, 0) & 0x1F) == 6)
        {
            if (BufferBase + 5 >= BufferEnd)
                return (ULONG64)-1;

            FieldSize = 6;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 6);
            CTX_D(DecodeContext, 0xFC) = 1;  // 额外标志
            // 读取 4 字节 + 2 字节
            CTX_D(OutputContext, 8) = *(ULONG *)BufferBase;  // 低 32 位
            CTX_D(OutputContext, 12) = *(USHORT *)(BufferBase + 4);  // 高 16 位
            Flags = 0x10000000;
            OutputSize = 6;
        }
        else
        {
            if (BufferBase + 3 >= BufferEnd)
                return (ULONG64)-1;

            FieldSize = 4;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 4);
            Value = *(ULONG *)BufferBase;
            Flags = 0x10000;
            OutputSize = 4;
            SET_D(OutputContext, 6, 4);
            SET_Q(OutputContext, 8, Value);
            CTX_Q(OutputContext, 0x20) |= Flags;
            return OutputSize;
        }
    }
    else if (DataType == 2)
    {
        // 类型 2: 8 字节读取
        if (BufferBase + 7 >= BufferEnd)
            return (ULONG64)-1;

        FieldSize = 8;
        SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 8);
        Value = *(ULONG64 *)BufferBase;
        Flags = 0x20000;
        OutputSize = 8;
        SET_D(OutputContext, 6, 8);
        SET_Q(OutputContext, 8, Value);
        CTX_Q(OutputContext, 0x20) |= Flags;
        return OutputSize;
    }
    else
    {
        // 其他类型
        ULONG64 OrigFlags = CTX_Q(OutputContext, 0);
        if ((OrigFlags & 0x1F) == 6)
        {
            if (BufferBase + 3 >= BufferEnd)
                return (ULONG64)-1;

            FieldSize = 4;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 4);
            CTX_D(DecodeContext, 0xFC) = 1;
            Value = *(ULONG *)BufferBase;
            Flags = 0x40000000;
            OutputSize = 4;
        }
        else
        {
            if (BufferBase + 1 >= BufferEnd)
                return (ULONG64)-1;

            FieldSize = 2;
            SET_D(DecodeContext, DEC_CTX_EXTRA_FIELD, 2);
            Value = *(USHORT *)BufferBase;
            Flags = 0x8000;
            OutputSize = 2;
        }
    }

    CTX_Q(OutputContext, 0x20) |= Flags;
    SET_D(OutputContext, 6, OutputSize);
    SET_Q(OutputContext, 8, Value);
    return OutputSize;
}

// ============================================================
// SetDecoderStateFlags — 设置解码器状态标志
// 对应原始驱动 sub_14008AE88
// 设置额外状态标志，根据系统位数设置地址宽度标志
// ============================================================
__int64 SetDecoderStateFlags(PUCHAR Context)
{
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM5);
    ULONG64 Flags = CTX_Q(OutputContext, 0x20);
    INT Mode = CTX_D(CTX_Q(Context, DEC_CTX_PARAM6) + 4, 0);  // 偏移 0x04 = 数据类型

    Flags |= 0x100000000LL;

    if (Mode == 1)
        Flags |= 0x20;
    else if (Mode == 2)
        Flags |= 0x40;
    else
        Flags |= 0x10;

    SET_D(OutputContext, 0x28, 7);  // 类型 7
    CTX_Q(OutputContext, 0x20) = Flags;
    return 0;
}

// ============================================================
// 解码表查找函数
// 每个函数模式：检查缓冲区边界 → 读取操作码字节 →
// 选择对应解码表 → 调用 DispatchInstructionDecode
// ============================================================

// DecodeOpcodeTable16_32_64 — 解码 16/32/64 位操作码表
// 对应原始驱动 sub_14008AED0
__int64 DecodeOpcodeTable16_32_64(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    ULONG64 TableBase;
    UCHAR Mode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_BYTE);

    if (Mode)
    {
        if (Mode == 3)
        {
            // Mode 3: 查 Mode3 表
            if (*(USHORT *)((ULONG64)g_PeDecodeTableMode3 + 4 + 20 * OpcodeByte) == 0xFFFF)
                goto USE_DEFAULT;
            SET_D(DecodeContext, DEC_CTX_STATE_FLAGS,
                  CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & ~0x20);
            TableBase = (ULONG64)g_PeDecodeTableMode3;
        }
        else if (Mode == 4)
        {
            // Mode 4: 查 Mode4 表
            if (*(USHORT *)((ULONG64)g_PeDecodeTableMode4 + 4 + 20 * OpcodeByte) == 0xFFFF)
                goto USE_DEFAULT;
            SET_D(DecodeContext, DEC_CTX_STATE_FLAGS,
                  CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & ~0x10);
            TableBase = (ULONG64)g_PeDecodeTableMode4;
        }
        else
        {
            goto USE_DEFAULT;
        }
    }
    else
    {
        // Mode 0: 查 Mode0 表
        if (*(USHORT *)((ULONG64)g_PeDecodeTableMode0 + 4 + 20 * OpcodeByte) == 0xFFFF)
            goto USE_DEFAULT;
        INT ModeVal = CTX_D(DecodeContext, DEC_CTX_MODE);
        SET_D(DecodeContext, DEC_CTX_STATE_FLAGS,
              CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & ~2);
        SET_D(DecodeContext, DEC_CTX_ADDR_SIZE, ModeVal);
        TableBase = (ULONG64)g_PeDecodeTableMode0;
    }

    TableEntry = TableBase + 20 * OpcodeByte;
    goto DISPATCH;

USE_DEFAULT:
    TableEntry = (ULONG64)&g_PeDecodeTableMode0[0x190];  // unk_140099250 + 4*5*OpcodeByte

DISPATCH:
    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)(BufferBase + 1),
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + 1);
}

// DecodeOpcodeTableWithPrefix — 解码带前缀的操作码表
// 对应原始驱动 sub_14008AFA0
__int64 DecodeOpcodeTableWithPrefix(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    ULONG PrefixIndex;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    PrefixIndex = OpcodeByte >> 4;
    TableEntry = (ULONG64)g_PeMultiByteTable1[PrefixIndex];
    if (TableEntry)
        TableEntry += 20 * (OpcodeByte & 0xF);
    else
        TableEntry = (ULONG64)&g_PeDecodeTableMode0[0x324];  // unk_140096A30

    // 根据模式选择不同的前缀表
    UCHAR Mode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_BYTE);
    if (Mode == 0)
    {
        ULONG64 AltTable = (ULONG64)g_PeMultiByteTable2[PrefixIndex];
        if (AltTable)
        {
            ULONG64 AltEntry = AltTable + 20 * (OpcodeByte & 0xF);
            if (*(USHORT *)(AltEntry + 4) != 0xFFFF)
            {
                INT ModeVal = CTX_D(DecodeContext, DEC_CTX_MODE);
                SET_D(DecodeContext, DEC_CTX_STATE_FLAGS,
                      CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & ~2);
                SET_D(DecodeContext, DEC_CTX_ADDR_SIZE, ModeVal);
                TableEntry = AltEntry;
            }
        }
    }
    else if (Mode == 3)
    {
        ULONG64 AltTable = (ULONG64)CTX_Q(DecodeContext, DEC_CTX_CUR_TABLE_ENTRY);  // 子解码表
        if (AltTable)
        {
            ULONG64 AltEntry = AltTable + 20 * (OpcodeByte & 0xF);
            if (*(USHORT *)(AltEntry + 4) != 0xFFFF)
            {
                SET_D(DecodeContext, DEC_CTX_STATE_FLAGS,
                      CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & ~0x20);
                TableEntry = AltEntry;
            }
        }
    }

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)(BufferBase + 1),
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + 1);
}

// DecodeOpcodeTableDirect — 直接解码操作码表
// 对应原始驱动 sub_14008B080
__int64 DecodeOpcodeTableDirect(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    ULONG PrefixIndex;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    PrefixIndex = OpcodeByte >> 4;
    // qword_1400CCF40 — 直接指针表 (全为 NULL)
    TableEntry = (ULONG64)&g_PeDecodeTableMode0[0x324];  // unk_140096A30

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)(BufferBase + 1),
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + 1);
}

// DecodeOpcodeTableWithOffset — 带偏移量的操作码表解码
// 对应原始驱动 sub_14008B108
// 基于前一个操作码字节和当前字节的 reg 域计算解码表偏移
__int64 DecodeOpcodeTableWithOffset(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);

    // 计算偏移: 160 * PrevOpcode + 20 * ((OpcodeByte >> 3) & 7) - 20480
    // 重新映射到 g_PeDecodeTableOneByte[0] 作为基址
    // unk_14009E350 偏移 = g_PeDecodeTableOneByte - 0x14009E350 + PrevOpcode*160
    // 但直接用公式计算
    ULONG Offset = (ULONG)(160 * PrevOpcode + 20 * ((OpcodeByte >> 3) & 7) - 20480);
    TableEntry = (ULONG64)&g_PeDecodeTableOneByte[0] + Offset - 0x3400;  // 调整到正确的基址

    // 由于 IDA 地址计算复杂，简化：使用 g_PeDecodeTableOneByte 作为基址
    // 实际偏移 = (PrevOpcode - 0x100) * 160 + 20 * ((OpcodeByte >> 3) & 7)
    // 其中 PrevOpcode 是 0x100-0x1FF 范围的 opcode
    TableEntry = (ULONG64)&g_PeDecodeTableOneByte[0]
               + 160 * (PrevOpcode - 0x80)
               + 20 * ((OpcodeByte >> 3) & 7);

    CTX_Q(Context, 0x10) = TableEntry;  // 保存表条目指针

    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase,
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeTableGroup1 — 解码操作码表组 1 (Grp1)
// 对应原始驱动 sub_14008B180
__int64 DecodeOpcodeTableGroup1(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    int RegIndex;
    int HasEntry;
    ULONG64 TableEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);
    RegIndex = (OpcodeByte >> 3) & 7;

    // 计算 Grp1 偏移
    ULONG64 BaseOffset;
    if (PrevOpcode >= 0xC0)
    {
        if (PrevOpcode + 64 <= 1)
            BaseOffset = 8 * PrevOpcode - 1536;
        else if (PrevOpcode + 48 <= 3)
            BaseOffset = 8 * PrevOpcode - 1648;
        else
            BaseOffset = 0;
        HasEntry = 0;
    }
    else
    {
        BaseOffset = 0;
        HasEntry = 1;
    }

    TableEntry = (ULONG64)&g_PeDecodeTableGrp1[0] + 20 * (BaseOffset + RegIndex);
    CTX_Q(Context, 0x10) = TableEntry;

    if (*(UCHAR *)TableEntry && *(UCHAR *)(TableEntry + 1))
        HasEntry = 1;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase,
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + HasEntry);
}

// DecodeOpcodeTableGroup2 — 解码操作码表组 2 (Grp2)
// 对应原始驱动 sub_14008B238
__int64 DecodeOpcodeTableGroup2(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);

    // 偏移: 160 * PrevOpcode + 20 * RegIndex - 39360
    TableEntry = (ULONG64)&g_PeDecodeTableGrp2[0]
               + 160 * PrevOpcode
               + 20 * ((OpcodeByte >> 3) & 7)
               - 39360;
    CTX_Q(Context, 0x10) = TableEntry;

    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase,
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeTableGroup3 — 解码操作码表组 3 (Grp3)
// 对应原始驱动 sub_14008B2B0
__int64 DecodeOpcodeTableGroup3(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    ULONG64 TableEntry;
    int RegIndex;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);
    RegIndex = (OpcodeByte >> 3) & 7;

    if (PrevOpcode == 0xFE)
        TableEntry = (ULONG64)&g_PeDecodeTableGrp3[0] + 20 * RegIndex;
    else
        TableEntry = (ULONG64)&g_PeDecodeTableGrp3[0] + 20 * (RegIndex + 8);

    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase,
        (ULONG64)BufferEnd,
        TableEntry,
        (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeMultiByteOpcode — 解码多字节操作码
// 对应原始驱动 sub_14008B338
// 处理 0xC0-0xFF 范围的多字节操作码
__int64 DecodeMultiByteOpcode(PUCHAR Context, ULONG64 Param2, ULONG64 UnusedParam)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    CHAR *SubTable;
    ULONG TotalSize;
    ULONG OpIndex;
    int SubTableIdx;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);
    SubTableIdx = PrevOpcode - 216;  // 0xD8-0xFF → 0-39

    if (OpcodeByte > 0xBF)
    {
        // Opcode 0xC0-0xFF: 使用 g_PeMultiByteTable2
        SubTable = (CHAR *)g_PeMultiByteTable2[SubTableIdx] + 20 * (OpcodeByte - 192);
    }
    else
    {
        // Opcode 0x00-0xBF: 使用 g_PeMultiByteTable1
        SubTable = (CHAR *)g_PeMultiByteTable1[SubTableIdx] + 20 * ((OpcodeByte >> 3) & 7);
        CTX_D(DecodeContext, 0x30) = *(USHORT *)(SubTable + 8);   // offset 0x30
        CTX_D(DecodeContext, 0x68) = *(USHORT *)(SubTable + 10);  // offset 0x68
    }

    SET_Q(DecodeContext, DEC_CTX_SUB_DECODE_TABLE, (ULONG64)SubTable);

    // 64 位模式检查
    if (CTX_D(DecodeContext, DEC_CTX_MODE) == 2)
    {
        ULONG TableFlags = *(ULONG *)(SubTable + 16);
        if ((TableFlags & 0x400000) != 0 ||
            ((TableFlags & 0x200000) != 0 && (CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & 2) == 0))
        {
            SET_D(DecodeContext, DEC_CTX_ADDR_SIZE, 2);
        }
    }

    TotalSize = 0;
    OpIndex = 0;
    if (*(UCHAR *)SubTable)
        OpIndex = *(UCHAR *)(SubTable + 1) != 0;

    UCHAR *OpPtr = (UCHAR *)SubTable;
    while (1)
    {
        if (*OpPtr == 0xFF)
            break;

        // 构造调用上下文
        PUCHAR FuncContext = CTX_Q(Context, 0);
        // 设置函数分发参数
        ULONG64 FuncContextArray[6];
        FuncContextArray[0] = (ULONG64)(BufferBase + TotalSize + OpIndex);
        FuncContextArray[1] = (ULONG64)BufferEnd;
        FuncContextArray[2] = (ULONG64)SubTable;
        FuncContextArray[3] = (ULONG64)Param2;
        FuncContextArray[4] = (ULONG64)DecodeContext;
        FuncContextArray[5] = 0;

        ULONG64 FuncTable = CTX_Q(DecodeContext, DEC_CTX_FUNC_TABLE);
        ULONG64 FuncPtr = *(ULONG64 *)(FuncTable + 8 * *OpPtr);
        ULONG64 (*Func)(ULONG64 *) = (ULONG64 (*)(ULONG64 *))FuncPtr;

        ULONG64 FuncResult = Func(FuncContextArray);
        if (FuncResult == (ULONG64)-1)
            return (ULONG64)-1;

        ++OpPtr;
        TotalSize += (ULONG)FuncResult;

        if (OpPtr - (UCHAR *)SubTable >= 2)
            break;
    }

    return TotalSize;
}

// DecodeOpcodeTableGroup4 — 解码操作码表组 4 (Grp4)
// 对应原始驱动 sub_14008B588
__int64 DecodeOpcodeTableGroup4(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp4[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeByPrefixGroup — 按前缀组分解码操作码
// 对应原始驱动 sub_14008B5EC
__int64 DecodeOpcodeByPrefixGroup(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int HasEntry;
    int RegIndex;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    HasEntry = 1;
    OpcodeByte = *BufferBase;
    RegIndex = (OpcodeByte >> 3) & 7;

    if ((OpcodeByte >> 6) == 3)
    {
        if ((OpcodeByte & 7) != 0)
        {
            if ((OpcodeByte & 7) == 1)
                TableEntry = (ULONG64)&g_PeDecodeTableGrp5[0] + 20 * RegIndex;  // unk_14009EDF0
            else
                goto USE_DEFAULT;
        }
        else
        {
            TableEntry = (ULONG64)&g_PeDecodeTableGrp4[0] + 20 * RegIndex;  // unk_14009ED50
        }
    }
    else
    {
USE_DEFAULT:
        TableEntry = (ULONG64)&g_PeDecodeTableGrp6[0] + 20 * RegIndex;  // unk_14009ECB0
    }

    CTX_Q(Context, 0x10) = TableEntry;
    if (!*(UCHAR *)TableEntry || !*(UCHAR *)(TableEntry + 1))
        HasEntry = 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + HasEntry);
}

// DecodeOpcodeTableGroup5 — 解码操作码表组 5 (Grp5)
// 对应原始驱动 sub_14008B6A8
__int64 DecodeOpcodeTableGroup5(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp5[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeTableGroup6 — 解码操作码表组 6 (Grp6)
// 对应原始驱动 sub_14008B70C
__int64 DecodeOpcodeTableGroup6(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp6[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeWithModrm — 解码带 ModRM 的操作码
// 对应原始驱动 sub_14008B484
__int64 DecodeOpcodeWithModrm(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR ModrmByte;
    ULONG64 ModrmState;
    int ImmediateSize;
    int HasEntry;
    ULONG64 TableEntry;
    int DispatchResult;
    ULONG TotalSize;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    ModrmByte = *BufferBase;
    HasEntry = 1;

    // 设置 ModRM 状态 (偏移 0xD8)
    ModrmState = CTX_D(DecodeContext, 0xD8) & 0xFFFFFFF0 | (ModrmByte & 7);
    CTX_D(DecodeContext, 0xD8) = (ULONG)ModrmState;
    CTX_D(DecodeContext, 0xD8) ^= (CTX_D(DecodeContext, 0xD8) ^ (4 * ModrmByte)) & 0x300;
    CTX_D(DecodeContext, 0xD8) = CTX_D(DecodeContext, 0xD8) & 0xFFFFFF0F | (2 * (ModrmByte & 0x38));

    // 读取立即操作数
    ImmediateSize = (int)DecodeImmediateOperandValue(
        (ULONG64)(BufferBase + 1), (ULONG64)BufferEnd, DecodeContext, 0);
    if (ImmediateSize == -1)
        return (ULONG64)-1;

    // 计算后续字节的分发表
    PUCHAR NextByte = BufferBase + ImmediateSize + 1;
    if (NextByte >= BufferEnd)
        return (ULONG64)-1;

    TableEntry = (ULONG64)&g_PeDecodeTableOpcodeByte[0] + 20 * *NextByte;
    CTX_Q(Context, 0x10) = TableEntry;

    if (!*(UCHAR *)TableEntry || !*(UCHAR *)(TableEntry + 1))
        HasEntry = 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;

    TotalSize = HasEntry + DispatchResult + 1;
    if (BufferBase + TotalSize > BufferEnd)
        return (ULONG64)-1;

    return TotalSize;
}

// DecodeOneByteOpcodeTable — 解码单字节操作码表
// 对应原始驱动 sub_14008BA3C
__int64 DecodeOneByteOpcodeTable(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableOneByte[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeTwoByteOpcode0F — 解码 0F 开头的双字节操作码
// 对应原始驱动 sub_14008BAA0
__int64 DecodeTwoByteOpcode0F(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int RegIndex;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    RegIndex = (OpcodeByte >> 3) & 7;

    if ((CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & 2) != 0)
        RegIndex += 8;

    TableEntry = (ULONG64)&g_PeDecodeTableTwoByte0F[0] + 20 * RegIndex;
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeTwoByteOpcode0F38 — 解码 0F38 开头的双字节操作码
// 对应原始驱动 sub_14008BB14
__int64 DecodeTwoByteOpcode0F38(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int RegIndex;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    RegIndex = (OpcodeByte >> 3) & 7;

    if ((CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & 2) != 0)
        RegIndex += 8;

    TableEntry = (ULONG64)&g_PeDecodeTableTwoByte38[0] + 20 * RegIndex;
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeTwoByteOpcode0F3A — 解码 0F3A 开头的双字节操作码
// 对应原始驱动 sub_14008BB88
__int64 DecodeTwoByteOpcode0F3A(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int RegIndex;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    RegIndex = (OpcodeByte >> 3) & 7;

    if ((CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) & 2) != 0)
        RegIndex += 8;

    TableEntry = (ULONG64)&g_PeDecodeTableTwoByte3A[0] + 20 * RegIndex;
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeModrmOpcodeTable — 解码 ModRM 操作码表
// 对应原始驱动 sub_14008BBFC
__int64 DecodeModrmOpcodeTable(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int RegIndex;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    RegIndex = (OpcodeByte >> 3) & 7;

    // mod=3 && rm=0 → 寄存器模式, 否则内存模式
    if ((OpcodeByte & 0xC0) == 0xC0 && (OpcodeByte & 7) == 0)
        TableEntry = (ULONG64)&g_PeDecodeTableModrmReg[0] + 20 * RegIndex;
    else
        TableEntry = (ULONG64)&g_PeDecodeTableModrmMem[0] + 20 * RegIndex;

    HasEntry = 0;
    CTX_Q(Context, 0x10) = TableEntry;
    if (*(UCHAR *)TableEntry)
        HasEntry = *(UCHAR *)(TableEntry + 1) != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// DecodeOpcodeByte — 解码操作码字节
// 对应原始驱动 sub_14008BC98
__int64 DecodeOpcodeByte(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_BASE);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, DEC_CTX_BUFFER_END);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, DEC_CTX_PARAM6);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableOpcodeByte[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    HasEntry = *(USHORT *)TableEntry != 0;

    DispatchResult = (int)DispatchInstructionDecode(
        (ULONG64)BufferBase, (ULONG64)BufferEnd, TableEntry, (ULONG64)DecodeContext);

    if (DispatchResult == -1)
        return (ULONG64)-1;
    return (ULONG)(DispatchResult + (HasEntry ? 1 : 0));
}

// ============================================================
// DecodeOpcodeStubZero — 解码操作码存根
// 对应原始驱动 sub_14008BF1C
// ============================================================
__int64 DecodeOpcodeStubZero(void)
{
    return 0;
}

// ============================================================
// DecodeCheckBound1Byte — 解码边界检查1字节
// 对应原始驱动 sub_14008BF58
// ============================================================
__int64 DecodeCheckBound1Byte(PUCHAR *Context)
{
    return Context[0] < Context[1] ? 1 : -1;
}

// ============================================================
// DecodeCheckBound2Byte — 解码边界检查2字节
// 对应原始驱动 sub_14008C044
// ============================================================
__int64 DecodeCheckBound2Byte(PUCHAR *Context)
{
    return (ULONG64)(Context[0] + 1) < (ULONG64)Context[1] ? 2 : -1;
}

// ============================================================
// DecodeCheckBound4Byte — 解码边界检查4字节
// 对应原始驱动 sub_14008C094
// ============================================================
__int64 DecodeCheckBound4Byte(PUCHAR *Context)
{
    return (ULONG64)(Context[0] + 3) < (ULONG64)Context[1] ? 4 : -1;
}

// ============================================================
// DecodeCheckBound8Byte — 解码边界检查8字节
// 对应原始驱动 sub_14008C0E4
// ============================================================
__int64 DecodeCheckBound8Byte(PUCHAR *Context)
{
    return (ULONG64)(Context[0] + 7) < (ULONG64)Context[1] ? 8 : -1;
}

// ============================================================
// DecodeOpcodeReadByte — 解码操作码读取字节
// 对应原始驱动 sub_14008BF20
// 从字节流读取一个字节，更新解码状态中的标志和值字段
// ============================================================
__int64 DecodeOpcodeReadByte(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    UCHAR ByteValue;

    if (Context[0] >= Context[1])
        return (ULONG64)-1;

    ByteValue = *Context[0];
    SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 1);
    CTX_Q(OperandOut, 0x20) |= 0x80000;
    SET_D(OperandOut, 6, 1);
    SET_Q(OperandOut, 8, (ULONG64)ByteValue);
    return 1;
}

// ============================================================
// DecodeReadWordImmediate — 解码读取16位立即数
// 对应原始驱动 sub_14008C008
// ============================================================
__int64 DecodeReadWordImmediate(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    USHORT WordValue;

    if (Context[0] + 1 >= Context[1])
        return (ULONG64)-1;

    WordValue = *(USHORT *)Context[0];
    SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 2);
    CTX_Q(OperandOut, 0x20) |= 0x200000;
    SET_D(OperandOut, 6, 2);
    SET_Q(OperandOut, 8, (ULONG64)WordValue);
    return 2;
}

// ============================================================
// DecodeReadSizeDependentImmediate — 解码读取大小相关的立即数
// 对应原始驱动 sub_14008C0F8
// 根据操作数大小(1=32位,2=64位,其他=16位)读取立即数
// ============================================================
__int64 DecodeReadSizeDependentImmediate(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    INT OperandSize = CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE);
    ULONG64 Value;
    ULONG FieldSize;

    if (OperandSize == 1)
    {
        // 32 位模式
        if (Context[0] + 3 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 4;
        SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 4);
        Value = (ULONG64)*(ULONG *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x800000;
    }
    else if (OperandSize == 2)
    {
        // 64 位模式
        if (Context[0] + 7 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 8;
        SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 8);
        Value = *(ULONG64 *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x2000000;
    }
    else
    {
        // 16 位模式
        if (Context[0] + 1 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 2;
        SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 2);
        Value = (ULONG64)*(USHORT *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x200000;
    }

    SET_D(OperandOut, 6, FieldSize);
    SET_Q(OperandOut, 8, Value);
    return FieldSize;
}

// ============================================================
// DecodeReadImmediateValue — 解码读取立即数
// 对应原始驱动 sub_14008BF68
// 根据当前操作数大小读取立即数，更新解码状态标志和值字段
// ============================================================
__int64 DecodeReadImmediateValue(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    INT OperandSize = CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE);
    ULONG64 Value;
    ULONG FieldSize;

    if (Context[0] >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 1);

    if (OperandSize == 1)
    {
        // 32 位模式: 读取4字节
        if (Context[0] + 3 >= Context[1])
            return (ULONG64)-1;
        Value = (ULONG64)*(ULONG *)Context[0];
        FieldSize = 4;
        CTX_Q(OperandOut, 0x20) |= 0x400000000LL;
        SET_D(OperandOut, 6, 4);
    }
    else if (OperandSize == 2)
    {
        // 64 位模式: 读取8字节
        if (Context[0] + 7 >= Context[1])
            return (ULONG64)-1;
        Value = *(ULONG64 *)Context[0];
        FieldSize = 8;
        CTX_Q(OperandOut, 0x20) |= 0x1000000000LL;
        SET_D(OperandOut, 6, 8);
    }
    else
    {
        // 16 位模式: 读取2字节
        if (Context[0] + 1 >= Context[1])
            return (ULONG64)-1;
        Value = (ULONG64)*(USHORT *)Context[0];
        FieldSize = 2;
        CTX_Q(OperandOut, 0x20) |= 0x200000000LL;
        SET_D(OperandOut, 6, 2);
    }

    SET_Q(OperandOut, 8, Value);
    return FieldSize;
}

// ============================================================
// DecodeOpcodeWithPrefix — 解码带前缀的操作码
// 对应原始驱动 sub_14008BCFC
// 解析前缀字节并设置解码器状态，处理REX前缀扩展和特殊寻址模式
// ============================================================
__int64 DecodeOpcodeWithPrefix(PUCHAR *Context)
{
    PUCHAR BufferPos = Context[0];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    UCHAR PrefixByte;
    ULONG NewModeFlags;
    ULONG OperandSize;
    ULONG RemainingSize;
    ULONG64 ImmediateSize;
    int Result;

    if (BufferPos >= Context[1])
        return (ULONG64)-1;

    PrefixByte = *BufferPos;
    Context[0] = BufferPos + 1;

    // 更新模式标志：编码前缀字节到模式标志位
    NewModeFlags = (PrefixByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xFFFFFC00)
                 | (2 * (PrefixByte & 0x38 | (2 * (PrefixByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewModeFlags);

    // 检查是否需要设置 64 位标志
    if ((CTX_D(Context[2], 4) & 0x2000000) != 0)
        SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewModeFlags | 0x300);

    // REX 前缀处理
    if ((CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE) & 0x40) != 0)
    {
        OperandSize = CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE);
        CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) |= ((OperandSize >> 2) & 1) << 7;

        NewModeFlags = CTX_D(DecodeCtx, DEC_CTX_MODE_DUP);
        ULONG RegField = (NewModeFlags >> 8) & 3;

        if ((RegField == 3 || (NewModeFlags & 0xF) != 4) &&
            (RegField != 0 || (NewModeFlags & 0xF) != 5))
        {
            CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) = NewModeFlags | (8 * (OperandSize & 1));
        }
    }

    // 解码立即操作数
    Result = DecodeImmediateOperandValue(Context[0], (ULONG64)Context[1], DecodeCtx, &ImmediateSize);
    if (Result == -1)
        return (ULONG64)-1;

    RemainingSize = Result + 1;
    Context[0] += ImmediateSize;
    DecodeModrmInstruction(Context);
    Context[0] -= ImmediateSize;
    Context[0]--;

    return RemainingSize;
}

// ============================================================
// DecodeOpcodeWithPrefixEx — 解码带前缀的操作码(扩展版)
// 对应原始驱动 sub_14008BE20
// 使用DecodeImmediateOperandSize替代DecodeImmediateOperandValue
// ============================================================
__int64 DecodeOpcodeWithPrefixEx(PUCHAR *Context)
{
    PUCHAR BufferPos = Context[0];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    UCHAR PrefixByte;
    ULONG NewModeFlags;
    ULONG OperandSize;
    ULONG RemainingSize;
    ULONG64 SizeResult;
    int Result;

    if (BufferPos >= Context[1])
        return (ULONG64)-1;

    PrefixByte = *BufferPos;
    Context[0] = BufferPos + 1;

    NewModeFlags = (PrefixByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xFFFFFC00)
                 | (2 * (PrefixByte & 0x38 | (2 * (PrefixByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewModeFlags);

    if ((CTX_D(Context[2], 4) & 0x2000000) != 0)
        SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewModeFlags | 0x300);

    if ((CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE) & 0x40) != 0)
    {
        OperandSize = CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE);
        CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) |= ((OperandSize >> 2) & 1) << 7;

        NewModeFlags = CTX_D(DecodeCtx, DEC_CTX_MODE_DUP);
        ULONG RegField = (NewModeFlags >> 8) & 3;

        if ((RegField == 3 || (NewModeFlags & 0xF) != 4) &&
            (RegField != 0 || (NewModeFlags & 0xF) != 5))
        {
            CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) = NewModeFlags | (8 * (OperandSize & 1));
        }
    }

    Result = DecodeImmediateOperandSize(Context[0], (ULONG64)Context[1], DecodeCtx, &SizeResult);
    if (Result == -1)
        return (ULONG64)-1;

    RemainingSize = Result + 1;
    Context[0]--;

    return RemainingSize;
}

// ============================================================
// DecodeModrmByte — 解码ModRM字节
// 对应原始驱动 sub_14008C3FC
// 解析ModRM字节设置寻址模式/寄存器/rm域标志，处理RIP相对寻址
// ============================================================
__int64 DecodeModrmByte(ULONG64 BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx)
{
    UCHAR ModrmByte;
    ULONG NewFlags;

    if (BufferPos >= BufferEnd)
        return (ULONG64)-1;

    ModrmByte = *(PUCHAR)BufferPos;
    NewFlags = (ModrmByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xFFFFFC00)
             | (2 * (ModrmByte & 0x38 | (2 * (ModrmByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewFlags);

    // REX 扩展
    if ((CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE) & 0x40) != 0)
    {
        if ((NewFlags & 0xF) != 5 || (CTX_D(DecodeCtx, DEC_CTX_MODE) & 0x300) != 0)
            CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) = NewFlags | (8 * (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) & 1));
        CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) |= ((CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) >> 1) & 1) << 7;
    }

    // RIP 相对寻址 (mod=00, rm=101 in 64-bit mode)
    if ((CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xF) == 5 &&
        (CTX_D(DecodeCtx, DEC_CTX_MODE) & 0x300) == 0)
    {
        if (BufferPos + 4 < BufferEnd)
        {
            CTX_D(DecodeCtx, 0xF4) = *(LONG *)(BufferPos + 1);  // 4 字节位移
            SET_D(DecodeCtx, 0xF8, 4);  // 位移大小
            return 5;
        }
        return (ULONG64)-1;
    }

    return 1;
}

// ============================================================
// DecodeModrmByteSimple — 解码ModRM字节(简化版)
// 对应原始驱动 sub_14008C4DC
// 不读取位移量但返回总字节数，用于仅计算操作数大小的场景
// ============================================================
__int64 DecodeModrmByteSimple(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx)
{
    UCHAR ModrmByte;
    ULONG NewFlags;

    if ((ULONG64)BufferPos >= BufferEnd)
        return (ULONG64)-1;

    ModrmByte = *BufferPos;
    NewFlags = (ModrmByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xFFFFFC00)
             | (2 * (ModrmByte & 0x38 | (2 * (ModrmByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_MODE_DUP, NewFlags);

    // REX 扩展
    if ((CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE) & 0x40) != 0)
    {
        CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) = NewFlags
            | (8 * (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) & 1))
            | (((CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) >> 1) & 1) << 7);
    }

    // RIP 相对寻址
    if ((CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xF) == 5 &&
        (CTX_D(DecodeCtx, DEC_CTX_MODE) & 0x300) == 0)
    {
        return (ULONG64)(BufferPos + 4) < BufferEnd ? 5 : -1;
    }

    return 1;
}

// ============================================================
// DecodeImmediateOperandValue — 解码立即操作数值
// 对应原始驱动 sub_14008C598
// 根据操作数类型和操作数大小从字节流中读取立即操作数值
// ============================================================
__int64 DecodeImmediateOperandValue(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx, PULONG pSize)
{
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_MODE) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_MODE) >> 8) & 3;
    ULONG TotalSize = 0;
    ULONG DecodedSize = 0;
    ULONG Value;
    ULONG Size;

    if (pSize)
        *pSize = 0;

    if (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) == 0)
    {
        // 操作数大小16位
        if (RegField)
        {
            if (RegField == 1)
            {
                // 8 位立即数
                if ((ULONG64)BufferPos >= BufferEnd)
                    return (ULONG64)-1;
                Value = *BufferPos;
                Size = 1;
                SET_D(DecodeCtx, 0xF4, 1);
                goto SET_VALUE;
            }
            if (RegField != 2)
                return TotalSize;
            // 16 位立即数
            if ((ULONG64)(BufferPos + 1) >= BufferEnd)
                return (ULONG64)-1;
            Value = (ULONG64)*(USHORT *)BufferPos;
        }
        else
        {
            if (ModeField != 6)
                return TotalSize;
            if ((ULONG64)(BufferPos + 1) >= BufferEnd)
                return (ULONG64)-1;
            Value = (ULONG64)*(USHORT *)BufferPos;
        }
        Size = 2;
        SET_D(DecodeCtx, 0xF4, 2);
        goto SET_VALUE;
    }

    // 操作数大小32位或64位
    if (RegField == 3 || ModeField != 4)
    {
        // 直接立即数寻址，不需要 ModRM
    }
    else
    {
        // 需要 ModRM 解码
        DecodedSize = (ULONG)DecodeModrmByte((ULONG64)BufferPos, BufferEnd, DecodeCtx);
        TotalSize = DecodedSize;
        if (pSize)
            *pSize = DecodedSize;
        if (DecodedSize == (ULONG)-1)
            return (ULONG64)-1;
        BufferPos += DecodedSize;
    }

    if (RegField)
    {
        if (RegField == 1)
        {
            // 8 位立即数
            if ((ULONG64)BufferPos >= BufferEnd)
                return (ULONG64)-1;
            Value = *BufferPos;
            TotalSize++;
            SET_D(DecodeCtx, 0xF4, 1);
            goto SET_VALUE;
        }
        if (RegField == 2)
        {
            // 32 位立即数
            if ((ULONG64)(BufferPos + 3) >= BufferEnd)
                return (ULONG64)-1;
            Value = *(ULONG *)BufferPos;
            TotalSize += 4;
            SET_D(DecodeCtx, 0xF4, 4);
            goto SET_VALUE;
        }
        return TotalSize;  // RegField == 3, no immediate
    }
    else
    {
        // RegField == 0
        if (ModeField != 5)
            return TotalSize;
        // 32 位立即数
        if ((ULONG64)(BufferPos + 3) >= BufferEnd)
            return (ULONG64)-1;
        Value = *(ULONG *)BufferPos;
        TotalSize += 4;
        SET_D(DecodeCtx, 0xF4, 4);
        goto SET_VALUE;
    }

    return TotalSize;

SET_VALUE:
    CTX_D(DecodeCtx, 0xE0) = Value;  // 立即数值
    return TotalSize;
}

// ============================================================
// DecodeImmediateOperandSize — 解码立即操作数大小
// 对应原始驱动 sub_14008C6EC
// 计算立即操作数的字节大小而不读取实际值
// ============================================================
__int64 DecodeImmediateOperandSize(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx, PULONG pSize)
{
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_MODE) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_MODE) >> 8) & 3;
    ULONG TotalSize = 0;
    ULONG DecodedSize = 0;

    if (pSize)
        *pSize = 0;

    if (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) == 0)
    {
        // 操作数大小16位
        if (RegField)
        {
            if (RegField == 1)
            {
                // 8 位立即数
                return (ULONG64)BufferPos < BufferEnd ? 1 : -1;
            }
            if (RegField != 2)
                return 0;
            // 16 位立即数
            return (ULONG64)(BufferPos + 1) < BufferEnd ? 2 : -1;
        }
        else
        {
            if (ModeField != 6)
                return 0;
            return (ULONG64)(BufferPos + 1) < BufferEnd ? 2 : -1;
        }
    }

    // 操作数大小32位或64位
    if (RegField != 3 && ModeField == 4)
    {
        DecodedSize = (ULONG)DecodeModrmByteSimple(BufferPos, BufferEnd, DecodeCtx);
        TotalSize = DecodedSize;
        if (pSize)
            *pSize = DecodedSize;
        if (DecodedSize == (ULONG)-1)
            return (ULONG64)-1;
        BufferPos += DecodedSize;
    }

    if (RegField)
    {
        if (RegField == 1)
        {
            if ((ULONG64)BufferPos >= BufferEnd)
                return (ULONG64)-1;
            return TotalSize + 1;
        }
        if (RegField == 2)
        {
            if ((ULONG64)(BufferPos + 3) >= BufferEnd)
                return (ULONG64)-1;
            return TotalSize + 4;
        }
        return TotalSize;  // RegField == 3, no immediate
    }
    else
    {
        if (ModeField != 5)
            return TotalSize;
        if ((ULONG64)(BufferPos + 3) >= BufferEnd)
            return (ULONG64)-1;
        return TotalSize + 4;
    }
}

// ============================================================
// DecodeModrmAddressingMode — 解码ModRM寻址模式
// 对应原始驱动 sub_14008C18C
// 根据寄存器编号和操作数类型设置寻址模式标志
// ============================================================
__int64 DecodeModrmAddressingMode(
    PULONG Context,
    ULONG64 UnusedParam,
    INT OperandType,
    PUCHAR OperandOut,
    INT Flag)
{
    ULONG RegIndex = CTX_D(OperandOut, 0) & 0x1F;
    ULONG AddressMode = CTX_D(Context, 2);
    ULONG Result = 0;

    if (Flag)
    {
        RegIndex = 4;
        Result = 11;
        if (CTX_D(Context, 1) == 2)
            RegIndex = 11;
    }
    else if (RegIndex == 15 || RegIndex == 0)
    {
        if (AddressMode)
        {
            if (AddressMode == 1)
                RegIndex = 11;
            else if (AddressMode == 2)
                RegIndex = 4;
        }
        else
        {
            RegIndex = 16;
        }
    }

    // 设置寻址模式标志
    if (RegIndex == 3)
    {
        // 直接寄存器寻址
        ULONG AddrSizeFlags = CTX_D(Context, 8);
        if ((AddrSizeFlags & 0x40) != 0)
        {
            ULONG AdjustedType = OperandType - 4;
            if (AdjustedType <= 3)
                OperandType += 12;
        }
        CTX_Q(OperandOut, 0x20) |= 8;
        Result = AddrSizeFlags;
    }
    else if (RegIndex == 4)
    {
        CTX_Q(OperandOut, 0x20) |= 0x20;
    }
    else if (RegIndex == 11)
    {
        CTX_Q(OperandOut, 0x20) |= 0x40;
    }
    else if (RegIndex == 16)
    {
        CTX_Q(OperandOut, 0x20) |= 0x10;
    }

    SET_D(OperandOut, 0x28, OperandType);
    return Result;
}

// ============================================================
// InitDataTypeByIndex — 按索引初始化数据类型
// 对应原始驱动 sub_14008C220
// ============================================================
__int64 InitDataTypeByIndex(
    PUCHAR DecodeCtx,
    ULONG64 TableEntry,
    ULONG DataIndex,
    PUCHAR OperandOut)
{
    ULONG DataTypeSize;
    ULONG SubTypeValue;

    CTX_Q(OperandOut, 0x20) |= 0x10;
    DataTypeSize = g_PeDataTypeSizeTable[DataIndex];
    SET_D(OperandOut, 0x28, DataTypeSize);

    if (DataIndex < 4)
    {
        CTX_Q(OperandOut, 0x20) |= 2;
        SubTypeValue = g_PeDataTypeSubTypeTable[DataIndex];
        SET_D(OperandOut, 0x2C, SubTypeValue);
    }

    return DataTypeSize;
}

// ============================================================
// SetupDecodedInstructionState — 设置解码指令状态
// 对应原始驱动 sub_14008C7C4
// 根据ModRM解码结果设置操作数的类型标志和寄存器编号
// ============================================================
__int64 SetupDecodedInstructionState(
    PUCHAR OperandOut,
    PUCHAR DecodeCtx)
{
    ULONG ModeFlags = CTX_D(DecodeCtx, DEC_CTX_MODE_DUP);
    ULONG RegField = (ModeFlags >> 4) & 0xF;
    ULONG RmField = ModeFlags & 0xF;
    ULONG AddrSizeField = (ModeFlags >> 8) & 3;
    ULONG64 SizeFlag = 64;

    if (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) == 1)
        SizeFlag = 32;

    if (RegField != 4)
    {
        SET_D(OperandOut, 0x2C, RegField);
        CTX_Q(OperandOut, 0x20) |= SizeFlag | 2;
        if (AddrSizeField)
        {
            CTX_Q(OperandOut, 0x20) |= 4;
            SET_D(OperandOut, 0x30, 1 << AddrSizeField);
        }
    }

    if (RmField != 5 || (CTX_D(DecodeCtx, DEC_CTX_MODE) & 0x300) != 0)
    {
        SET_D(OperandOut, 0x28, RmField);
        CTX_Q(OperandOut, 0x20) |= SizeFlag | 1;
    }
    else if (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) == 1)
    {
        CTX_Q(OperandOut, 0x20) |= 0x10000;
        SET_D(OperandOut, 0x10, CTX_D(DecodeCtx, 0xE0));
    }
    else
    {
        CTX_Q(OperandOut, 0x20) |= 0x20000;
        SET_Q(OperandOut, 0x10, (ULONG64)(LONG)CTX_D(DecodeCtx, 0xE0));
    }

    return SizeFlag;
}

// ============================================================
// CalcOpcodeSize — 计算操作码大小
// 对应原始驱动 sub_14008C254
// 根据寻址模式类型计算当前指令操作数的字节大小
// ============================================================
__int64 CalcOpcodeSize(PUCHAR DecodeCtx, PULONG OperandInfo)
{
    ULONG OperandSize = OperandInfo[6];
    ULONG Flags;
    ULONG RegIndex;
    ULONG AddressMode;
    ULONG ModeDup;

    if (OperandSize != 0)
        return OperandSize;

    Flags = OperandInfo[0];
    RegIndex = Flags & 0x1F;

    if (RegIndex == 15)
    {
        AddressMode = CTX_D(DecodeCtx, 8);
        if (AddressMode)
        {
            if (AddressMode == 1)
                RegIndex = 11;
            else if (AddressMode == 2)
                RegIndex = 4;
        }
        else
        {
            RegIndex = 16;
        }
    }

    if (RegIndex == 3)
        return 1;
    if (RegIndex == 4)
        return 4;
    if (RegIndex == 5)
        return 8;
    if (RegIndex == 6)
    {
        // RegIndex 6: 寻址方式取决于操作数大小模式
        ModeDup = CTX_D(DecodeCtx, 4);
        if (ModeDup == 1)
            return 6;
        if (ModeDup == 2)
            return 12;
        return 4;
    }
    if (RegIndex == 11)
        return 8;
    if (RegIndex == 16)
        return 2;

    return 4;
}

// ============================================================
// DispatchInstructionDecode — 指令解码分发函数
// 对应原始驱动 sub_14008C2D4
// 设置解码上下文，遍历解码操作序列，对每个操作数调用解码函数
// ============================================================
__int64 DispatchInstructionDecode(
    ULONG64 BufferPos,
    ULONG64 BufferEnd,
    ULONG64 TableEntry,
    ULONG64 DecodeCtx)
{
    PUCHAR OpcodeSeq = (PUCHAR)TableEntry;
    ULONG TotalSize = 0;
    ULONG OperandIndex = 0;
    ULONG FuncIndex;
    ULONG64 FuncTable;
    ULONG64 ContextArray[5];
    int Result;

    // 设置解码上下文
    SET_Q(DecodeCtx, DEC_CTX_CUR_TABLE_ENTRY, TableEntry);
    SET_D(DecodeCtx, 0x30, *(USHORT *)(TableEntry + 8));    // Operand 0 初始值
    SET_D(DecodeCtx, 0x68, *(USHORT *)(TableEntry + 10));   // Operand 1 初始值
    SET_D(DecodeCtx, 0xA0, *(USHORT *)(TableEntry + 12));   // Operand 2 初始值

    // 设置地址大小
    if (CTX_D(DecodeCtx, DEC_CTX_MODE) == 2)
    {
        ULONG EntryFlags = *(ULONG *)(TableEntry + 16);
        if ((EntryFlags & 0x400000) != 0 ||
            ((EntryFlags & 0x200000) != 0 && (CTX_D(DecodeCtx, 0x20) & 2) == 0))
        {
            SET_D(DecodeCtx, DEC_CTX_ADDR_SIZE, 2);
        }
    }
    else if ((*(ULONG *)(TableEntry + 16) & 0x4000000) != 0)
    {
        SET_D(DecodeCtx, DEC_CTX_ADDR_SIZE, 1);
    }

    // 构建上下文数组
    ContextArray[0] = BufferPos;
    ContextArray[1] = BufferEnd;
    ContextArray[2] = TableEntry;
    ContextArray[4] = DecodeCtx;

    // 获取函数表指针
    FuncTable = CTX_Q(DecodeCtx, DEC_CTX_FUNC_TABLE);
    if (FuncTable == 0)
        FuncTable = (ULONG64)g_PeDecodeFunctionTable;

    // 遍历操作码序列
    while (OpcodeSeq[OperandIndex] != 0xFF)
    {
        FuncIndex = OpcodeSeq[OperandIndex];
        ContextArray[3] = 56LL * OperandIndex + DecodeCtx + 0x30;

        Result = (int)((ULONG64(*)(ULONG64 *))((PULONG64)FuncTable)[FuncIndex])(ContextArray);
        if (Result == -1)
            return (ULONG64)-1;

        TotalSize += Result;
        ContextArray[0] += Result;
        OperandIndex++;

        // 设置操作数大小
        CalcOpcodeSize(DecodeCtx, (PULONG)(56LL * (OperandIndex - 1) + DecodeCtx + 0x30));

        if (OperandIndex >= 3)
            return TotalSize;
    }

    return TotalSize;
}

// ============================================================
// DecodeModrmInstruction — 解码ModRM指令
// 对应原始驱动 sub_14008B770
// 根据ModRM寻址模式和操作数标志位组合确定操作数类型
// ============================================================
__int64 DecodeModrmInstruction(PULONG64 ContextArray)
{
    PUCHAR DecodeCtx = (PUCHAR)ContextArray[4];
    PUCHAR OperandOut = (PUCHAR)ContextArray[3];
    ULONG OpFlags = CTX_D(OperandOut, 0) & 0xFE0;
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) >> 4) & 0xF;
    ULONG AddrField = (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) >> 8) & 3;
    ULONG TableEntryFlags = *(USHORT *)(CTX_Q(DecodeCtx, DEC_CTX_CUR_TABLE_ENTRY) + 4);
    INT IsModrmAddr = 0;
    int Is32BitMode;

    // 检查标志位组合
    if (OpFlags == 640)
    {
        IsModrmAddr = 0;
        goto LABEL_MODRM_ADDR;
    }

    if ((TableEntryFlags & 0xF00) == 0x400)
    {
        // ModRM 相关标志位处理
        switch (OpFlags)
        {
            case 1024:  // 0x400
                CTX_Q(OperandOut, 0x20) |= 0x800;
                goto LABEL_SET_REG;

            case 1056:  // 0x420
                CTX_Q(OperandOut, 0x20) |= 0x400;
                if (*(USHORT *)(CTX_Q(DecodeCtx, DEC_CTX_CUR_TABLE_ENTRY) + 4) == 131 &&
                    CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE) == 1)
                {
                    if ((CTX_D(DecodeCtx, 0x20) & 4) != 0)
                    {
                        CTX_D(DecodeCtx, 0x20) &= 0xFFFFFFFB;
                        SET_D(OperandOut, 0x28, 8);
                        return 0;
                    }
                }
                goto LABEL_SET_REG;

            case 1088:  // 0x440
                goto LABEL_SPECIAL;

            case 1120:  // 0x460
            {
                INT RegCount = (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) >> 4) & 7;
                if (RegCount >= 5)
                    RegCount = 5;
                CTX_Q(OperandOut, 0x20) |= 0x1000;
                SET_D(OperandOut, 0x28, RegCount);
                return 0;
            }

            case 1136:  // 0x470
                CTX_Q(OperandOut, 0x20) |= 0x2000;
                RegField &= 7;
                goto LABEL_SET_REG;

            case 1184:  // 0x4A0
                CTX_Q(OperandOut, 0x20) |= 0x100;
                RegField &= 7;
                goto LABEL_SET_REG;

            default:
                if (OpFlags == 1216 && AddrField == 3)  // 0x4C0
                {
                    ModeField = CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) & 0xF;
                LABEL_SPECIAL:
                    CTX_Q(OperandOut, 0x20) |= 0x200;
                LABEL_SET_REG:
                    SET_D(OperandOut, 0x28, RegField);
                    return 0;
                }
                break;
        }
    }

    // 非 ModRM 标志位处理
    if (CTX_D(DecodeCtx, DEC_CTX_OPERAND_SIZE) == 0)
    {
        // 16 位操作数大小
        if (AddrField == 0)
        {
            if (ModeField == 6)
            {
                ULONG DispValue = CTX_D(DecodeCtx, 0xE0);
                CTX_Q(OperandOut, 0x20) |= 0x8000;
                SET_D(OperandOut, 0x10, DispValue);
                return 0;
            }
            else
            {
                CTX_Q(OperandOut, 0x20) |= 1;
                InitDataTypeByIndex(DecodeCtx, 0, ModeField, OperandOut);
                return 0;
            }
        }

        if (AddrField == 1)
        {
            InitDataTypeByIndex(DecodeCtx, 0, ModeField, OperandOut);
            ULONG DispValue = CTX_D(DecodeCtx, 0xE0);
            CTX_Q(OperandOut, 0x20) |= 0x4001;
            SET_D(OperandOut, 0x10, DispValue);
            return 0;
        }

        if (AddrField == 2)
        {
            InitDataTypeByIndex(DecodeCtx, 0, ModeField, OperandOut);
            ULONG DispValue = CTX_D(DecodeCtx, 0xE0);
            CTX_Q(OperandOut, 0x20) |= 0x8001;
            SET_D(OperandOut, 0x10, DispValue);
            return 0;
        }

        Is32BitMode = 0;
        goto LABEL_MODRM;
    }
    else
    {
        // 32/64 位操作数大小
        if (AddrField == 0)
        {
            if (ModeField == 4)
            {
                SetupDecodedInstructionState(OperandOut, DecodeCtx);
                return 0;
            }
            if (ModeField == 5)
            {
                if (CTX_D(DecodeCtx, DEC_CTX_MODE) == 2)
                    CTX_Q(OperandOut, 0x20) |= 0x40000;
                else
                    CTX_Q(OperandOut, 0x20) |= 0x10000;
                SET_D(OperandOut, 0x10, CTX_D(DecodeCtx, 0xE0));
                return 0;
            }

            CTX_Q(OperandOut, 0x20) |= 1;
            IsModrmAddr = 1;
            goto LABEL_MODRM_ADDR;
        }

        if (AddrField == 1)
        {
            if (ModeField == 4)
            {
                SetupDecodedInstructionState(OperandOut, DecodeCtx);
            }
            else
            {
                CTX_Q(OperandOut, 0x20) |= 1;
                DecodeModrmAddressingMode(DecodeCtx, 0, ModeField, OperandOut, 1);
            }
            ULONG DispValue = CTX_D(DecodeCtx, 0xE0);
            CTX_Q(OperandOut, 0x20) |= 0x4000;
            SET_D(OperandOut, 0x10, DispValue);
            return 0;
        }

        if (AddrField == 2)
        {
            if (ModeField == 4)
            {
                SetupDecodedInstructionState(OperandOut, DecodeCtx);
            }
            else
            {
                CTX_Q(OperandOut, 0x20) |= 1;
                DecodeModrmAddressingMode(DecodeCtx, 0, ModeField, OperandOut, 1);
            }
            ULONG DispValue = CTX_D(DecodeCtx, 0xE0);
            CTX_Q(OperandOut, 0x20) |= 0x10000;
            SET_D(OperandOut, 0x10, DispValue);
            return 0;
        }

        Is32BitMode = 1;
    }

LABEL_MODRM:
    if (Is32BitMode != 1)
        return 0;

LABEL_MODRM_ADDR:
    DecodeModrmAddressingMode(DecodeCtx, 0, RegField, OperandOut, IsModrmAddr);
    return 0;
}

// ============================================================
// DecodeReadDwordImmediate — 解码读取32位立即数
// 对应原始驱动 sub_14008C058
// ============================================================
__int64 DecodeReadDwordImmediate(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    ULONG DwordValue;

    if (Context[0] + 3 >= Context[1])
        return (ULONG64)-1;

    DwordValue = *(ULONG *)Context[0];
    SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 4);
    CTX_Q(OperandOut, 0x20) |= 0x800000;
    SET_D(OperandOut, 6, 4);
    SET_Q(OperandOut, 8, (ULONG64)DwordValue);
    return 4;
}

// ============================================================
// DecodeReadQwordImmediate — 解码读取64位立即数
// 对应原始驱动 sub_14008C0A8
// ============================================================
__int64 DecodeReadQwordImmediate(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    ULONG64 QwordValue;

    if (Context[0] + 7 >= Context[1])
        return (ULONG64)-1;

    QwordValue = *(ULONG64 *)Context[0];
    SET_D(DecodeCtx, DEC_CTX_EXTRA_FIELD, 8);
    CTX_Q(OperandOut, 0x20) |= 0x2000000;
    SET_D(OperandOut, 6, 8);
    SET_Q(OperandOut, 8, QwordValue);
    return 8;
}