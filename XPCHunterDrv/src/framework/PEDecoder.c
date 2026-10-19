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
// 【⚠ 重大修正 2026-10-17】以下偏移全部改为**仿真器实测值**：在模拟内核里执行原始
//   ReadPESectionEntry 并对描述符缓冲区挂内存写钩子，逐条记录「哪个 RIP 写了哪个偏移」。
//   实测写入序列（第一条条目）：
//     init : +0x28=0xFF  +0x24=3  +0x20=0  +0x00=Mode  +0x04=ModeDup  +0x08=AddrSize
//            +0x110=ExtraField  +0x10=Param6  +0x18=Param7  +0x108=函数表
//     loop : +0x20=0x40  +0x2C=type5  +0x08=2  +0xE4=opcode  +0x2A=count  +0xE8=readptr+param4
//     dispatch: +0x118=当前表项  +0x30/+0x68/+0xA0=三个操作数记录
//     handlers: +0xD8  +0xDC=0x44  +0xF4  +0xE0  +0x58  +0x50/0x40  +0x88/0x90  +0x48/0x80  +0xF0=消耗量
//   载荷字段位于**操作数记录**内：+0x38=op0+0x08、+0x50=op0+0x20、+0x78=op1+0x10、+0x88=op1+0x20。
//   （此前把 Mode 写在 +0x18、状态标志写在 +0x28、消耗量写在 +0xE0，与调用方读取的偏移全错位。）
#define DEC_CTX_DECODE_TABLE_PTR    0x00  // QWORD: 解码表指针（上下文偏移，与描述符 +0x00 同值巧合）
#define DEC_CTX_BUFFER_BASE         0x08  // QWORD: 缓冲区基址（上下文偏移）
#define DEC_CTX_BUFFER_END          0x10  // QWORD: 缓冲区结束（上下文偏移）
#define DEC_CTX_MODE                0x00  // DWORD: 模式（init 写；类型 0/1 会改写 +0x04/+0x08）
#define DEC_CTX_MODE_DUP            0x04  // DWORD: 模式副本
#define DEC_CTX_ADDR_SIZE           0x08  // DWORD: 地址大小（init 写 ctx.AddrSize；类型 5 置 2）
#define DEC_CTX_PARAM6_DESC         0x10  // QWORD: init 写 ctx.Param6
#define DEC_CTX_PARAM7_DESC         0x18  // QWORD: init 写 ctx.Param7
#define DEC_CTX_STATE_FLAGS         0x20  // DWORD: 类型状态标志（0x40=已见类型5 等）
#define DEC_CTX_OPERAND_SIZE        0x24  // DWORD: 操作数大小（init=3；类型 2 置 subtype-9）
#define DEC_CTX_SUBTYPE_BYTE        0x28  // BYTE: 子类型字节（init=0xFF，随后逐类型写入）
#define DEC_CTX_INSTR_COUNT_WORD    0x2A  // WORD: 本次已消费的指令字节数（尾部写）
#define DEC_CTX_TYPE5_VALUE         0x2C  // DWORD: 类型 5 的取值
#define DEC_CTX_OPERANDS            0x30  // 操作数记录数组：3 × 0x38（+0x30/+0x68/+0xA0）
#define DEC_CTX_PREFIX_FLAGS        0xD8  // DWORD: 前缀/操作数标志（Classify 读 & 0x300）
#define DEC_CTX_MODRM_BYTE          0xDC  // DWORD: ModRM 相关字节
#define DEC_CTX_IMM_VALUE           0xE0  // DWORD: 立即数解析结果
#define DEC_CTX_READPTR_PARAM4      0xE8  // QWORD: 读指针 + ctx.Param4（尾部写）
#define DEC_CTX_CONSUMED            0xF0  // DWORD: 本条目的消耗字节数（**调用方按此推进读指针**）
#define DEC_CTX_IMM_FLAG            0xF4  // DWORD: 立即数标志
#define DEC_CTX_STATUS_ACC          0x100 // DWORD: 错误/结束累加器（|=2 错误、|=4 到界；==2 走特殊返回）
#define DEC_CTX_FUNC_TABLE          0x108 // QWORD: 解码函数表指针（init 写）
#define DEC_CTX_EXTRA_FIELD         0x110 // DWORD: ctx.ExtraField（init 写）
#define DEC_CTX_CUR_TABLE_ENTRY     0x118 // QWORD: 当前解码表条目（Dispatch 写；调用方读 +6 取子类型）
// 【修正 2026-10-17】+0xF8 是原始描述符的「本次读取长度」字段（DecodeOpcodeReadByte 等写 1/2/4），
//   旧代码把它当「上下文暂存槽」使用 —— 语义冲突，已废弃暂存用法。
#define DEC_CTX_READ_FLAG           0xF8  // DWORD: 本次读取长度（1/2/4）

// ============================================================
// 解码器入参 ContextArray 的真实布局（0x28 字节，DispatchInstructionDecode 栈上构建）
// 【⚠ 重大修正 2026-10-17】原始解码器的入参 a1 就是这个 5 元素数组，而不是描述符：
//     a1[0] 读指针   a1[1] 结束边界   a1[2] 表条目（回写）   a1[3] 操作数记录   a1[4] 描述符
//   旧代码把 a1 当描述符按 DEC_CTX_* 去读（+0x08/+0x10/+0xF8），于是
//   **把"结束边界"当成"读指针"、把"表条目"当成"结束边界"** —— 解码器第一步就越界返回 -1。
// ============================================================
#define CTXARR_READ_PTR             0x00  // QWORD: a1[0] = 当前读指针
#define CTXARR_END_PTR              0x08  // QWORD: a1[1] = 结束边界
#define CTXARR_TABLE                0x10  // QWORD: a1[2] = 当前表条目（解码器回写）
#define CTXARR_OPERAND              0x18  // QWORD: a1[3] = 操作数记录指针
#define CTXARR_DESC                 0x20  // QWORD: a1[4] = 0x120 字节指令描述符

// ============================================================
// PE 解码上下文（PE_DECODE_CONTEXT，0x48 字节）的真实偏移
// 由 0x14008A7E4 与 0x14008A54C 两个函数的反汇编汇总得出（并集恰好 0x00~0x40）
// 【注意】上面那套 DEC_CTX_* 是 0x120 字节指令描述符的偏移，两者不可混用；
//   历史遗留问题正是混用所致，新代码一律使用本组宏访问上下文。
// ============================================================
#define CTX_OFF_DECODE_TABLE   0x00  // QWORD: 解码表指针（决定操作码如何解码）
#define CTX_OFF_READ_PTR       0x08  // QWORD: 当前读指针（初值 Base，调用方按解码长度推进）
#define CTX_OFF_END_PTR        0x10  // QWORD: 缓冲区结束边界
#define CTX_OFF_MODE           0x18  // DWORD: 模式（2 = 64 位）
#define CTX_OFF_MODE_DUP       0x1C  // DWORD: 模式副本
#define CTX_OFF_ADDR_SIZE      0x20  // DWORD: 地址大小（Mode==2 时为 1）
#define CTX_OFF_PARAM4         0x28  // QWORD: 第 4 参数
#define CTX_OFF_PARAM6         0x30  // QWORD: 第 6 参数
#define CTX_OFF_PARAM7         0x38  // QWORD: 第 7 参数
#define CTX_OFF_EXTRA_FIELD    0x40  // DWORD: 第 5 参数（栈上传入，唯一非 0 的附加参数）

// 输出上下文额外偏移
#define DEC_CTX_LAST_OPCODE_SAVE    0xE4  // BYTE: 保存的最后操作码字节
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
// 对应原始驱动 sub_14008A7E4（地址 0x14008A7E4，95 字节）
// 【逆向来源】反汇编逐条重建（函数体共 29 条指令，全部写入偏移已逐条核对）
// 【原始指令 ↔ 偏移对照】
//   mov [r10+8],   rcx   → +0x08 = Base                  （读指针初值）
//   mov [r10+18h], r8d   → +0x18 = Mode
//   mov [r10+10h], rax   → +0x10 = Base + (int)Size      （rax = movsxd edx + rcx）
//   mov [r10+1Ch], r8d   → +0x1C = Mode
//   mov [r10+40h], eax   → +0x40 = 第 5 参数 ExtraField
//   mov [r10+28h], r9    → +0x28 = 第 4 参数
//   mov [r10+30h], rax   → +0x30 = 第 6 参数
//   mov [r10+38h], rax   → +0x38 = 第 7 参数
//   Mode==2 → [r10+20h]=1  且解码表 = 0x140097E50
//   否则    → [r10+20h]=Mode 且解码表 = 0x140096A50
//   mov [r10], rax       → +0x00 = 解码表指针
// 【⚠ 修正记录】此前重建把后 4 个参数写到了 0xDC/0xF0/0xF8/0x100，那是 0x120 字节
//   指令描述符的偏移，不是本上下文的；且调用点上下文只声明 8 字节，属栈越界。
//   详见 PE_DECODE_CONTEXT 的注释。
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
    SET_Q(Context, CTX_OFF_READ_PTR, (ULONG64)Base);
    SET_D(Context, CTX_OFF_MODE, Mode);
    SET_Q(Context, CTX_OFF_END_PTR, (ULONG64)(Base + (int)Size));
    SET_D(Context, CTX_OFF_MODE_DUP, Mode);
    SET_D(Context, CTX_OFF_EXTRA_FIELD, ExtraField);
    SET_Q(Context, CTX_OFF_PARAM4, (ULONG64)Param5);
    SET_Q(Context, CTX_OFF_PARAM6, (ULONG64)Param6);
    SET_Q(Context, CTX_OFF_PARAM7, (ULONG64)Param7);

    if (Mode == 2)
    {
        SET_D(Context, CTX_OFF_ADDR_SIZE, 1);
        SET_Q(Context, CTX_OFF_DECODE_TABLE, (ULONG64)g_PeDataDescrambleTable);
    }
    else
    {
        SET_D(Context, CTX_OFF_ADDR_SIZE, (ULONG)Mode);
        SET_Q(Context, CTX_OFF_DECODE_TABLE, (ULONG64)g_PeLegacyDescrambleTable);
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
    SET_B(SectionInfo, DEC_CTX_SUBTYPE_BYTE, 0xFF);
    SET_D(SectionInfo, DEC_CTX_OPERAND_SIZE, 3);
    SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, 0);

    SET_D(SectionInfo, DEC_CTX_MODE, CTX_D(Context, CTX_OFF_MODE));
    SET_D(SectionInfo, DEC_CTX_MODE_DUP, CTX_D(Context, CTX_OFF_MODE_DUP));
    SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, CTX_D(Context, CTX_OFF_ADDR_SIZE));
    // 【⚠ 修正记录】上下文只有 0x48 字节，原重建这里读的是 Context+0xDC/+0xF0/+0xF8
    //   （那是 0x120 字节指令描述符的偏移），属越界读取。按 PE_DECODE_CONTEXT 的真实
    //   偏移改为 +0x40/+0x28/+0x30，参数角色一一对应：
    //     ExtraField(第5参数) → +0x40，第4参数 → +0x28，第6参数 → +0x30
    //   注意：原始驱动把这三个值分别写入描述符的 +0x110/+0x10/+0x18，本重建的目标
    //   偏移尚未按原始布局改正（见审计报告 P0-1 的 0x120 描述符布局表）。
    SET_D(SectionInfo, DEC_CTX_EXTRA_FIELD, CTX_D(Context, CTX_OFF_EXTRA_FIELD));
    SET_Q(SectionInfo, DEC_CTX_PARAM6_DESC, CTX_Q(Context, CTX_OFF_PARAM6));
    SET_Q(SectionInfo, DEC_CTX_PARAM7_DESC, CTX_Q(Context, CTX_OFF_PARAM7));
    SET_Q(SectionInfo, DEC_CTX_FUNC_TABLE, (ULONG64)g_PeDecodeFunctionTable);
    /* 【我方内部】把上下文指针存入描述符 +0xF8，供各子解码器取回（原始驱动不使用该槽） */
    /* 【已废弃】旧代码在此把上下文指针暂存到描述符 +0xF8；原始该槽是「读取长度」字段，不可占用 */

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
            CTX_D(SectionInfo, DEC_CTX_TYPE5_VALUE) = *(USHORT *)(TableEntry + 8) - 50;
            if ((CTX_D(SectionInfo, DEC_CTX_TYPE5_VALUE) & 8) != 0)
                SET_D(SectionInfo, DEC_CTX_ADDR_SIZE, 2);
            goto LABEL_CONTINUE;
        }

        NewFlags = CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) & 0xFFFFFFBF;
        SET_B(SectionInfo, DEC_CTX_SUBTYPE_BYTE, (UCHAR)TypeField);
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
            CTX_D(SectionInfo, DEC_CTX_STATUS_ACC) |= 4;
            break;
        }
    }

    // 循环结束后的处理
    if (CTX_D(SectionInfo, DEC_CTX_STATUS_ACC))
    {
        if (CTX_D(SectionInfo, DEC_CTX_STATUS_ACC) == 2)
        {
            ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                          CTX_Q(Context, CTX_OFF_PARAM4);
            SET_D(SectionInfo, DEC_CTX_STATUS_ACC, 0);
            SET_D(SectionInfo, DEC_CTX_CONSUMED, 1);
            SET_Q(SectionInfo, DEC_CTX_READPTR_PARAM4, ResultBase);
            /* 【⚠ 修正 2026-10-17】原始 0x14008A7B2/7B9 是
               `lea rax,[r8+0B40h]` 再存 `[rbx+118h]`，而 **r8 = 解码表 + opcode*20**
               （0x14008A74F-757：`movzx eax,r10b; lea rcx,[rax+rax*4]; lea r8,[r8+rcx*4]`）。
               旧实现写成 `DecodeTablePtr + 2880`，漏掉 `20*opcode` —— 于是描述符 +0x118
               指向固定表项，所有节区扫描用 `*(WORD*)(Entry[0x118]+6)` 取到的类型恒为同一值
               （实机采样恒为 0x50E 一类），`type==0x558 && Entry[0x50]&0x4000000` 永不成立
               → FindNtOpenThreadTargetWin8 返回 0 → InitAllHookSubsystems 置 Success=0
               → sc start 错误 31。 */
            SET_Q(SectionInfo, 0x118, DecodeTablePtr + 20 * (UCHAR)*BufferPos + 2880);
            return 0;
        }
    }
    else
    {
        // 正常完成：分发到指令解码器
        SET_B(SectionInfo, DEC_CTX_LAST_OPCODE_SAVE, *BufferPos);
        ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                      CTX_Q(Context, CTX_OFF_PARAM4);
        SET_W(SectionInfo, DEC_CTX_INSTR_COUNT_WORD, ByteIndex);
        SET_Q(SectionInfo, DEC_CTX_READPTR_PARAM4, ResultBase);

        DispatchResult = (int)DispatchInstructionDecode(
            (ULONG64)(BufferPos + 1),
            CTX_Q(Context, DEC_CTX_BUFFER_END),
            DecodeTablePtr + 20 * (UCHAR)*BufferPos,
            (ULONG64)SectionInfo);

        if (DispatchResult == -1)
        {
            CTX_D(SectionInfo, DEC_CTX_STATUS_ACC) |= 4;
        }
        else
        {
            SET_D(SectionInfo, DEC_CTX_CONSUMED,
                  ByteIndex + DispatchResult + 1);
            if ((CTX_D(SectionInfo, DEC_CTX_STATE_FLAGS) & 4) != 0)
                ClassifyPESectionType((PUCHAR)SectionInfo);
            return 0;
        }
    }

    return Result;

LABEL_ERROR:
    CTX_D(SectionInfo, DEC_CTX_STATUS_ACC) |= 2;
    // 继续执行到函数末尾的错误处理
    if (CTX_D(SectionInfo, DEC_CTX_STATUS_ACC))
    {
        if (CTX_D(SectionInfo, DEC_CTX_STATUS_ACC) == 2)
        {
            ULONG64 ResultBase = CTX_Q(Context, DEC_CTX_BUFFER_BASE) +
                          CTX_Q(Context, CTX_OFF_PARAM4);
            SET_D(SectionInfo, DEC_CTX_STATUS_ACC, 0);
            SET_D(SectionInfo, DEC_CTX_CONSUMED, 1);
            SET_Q(SectionInfo, DEC_CTX_READPTR_PARAM4, ResultBase);
            /* 【⚠ 修正 2026-10-17】原始 0x14008A7B2/7B9 是
               `lea rax,[r8+0B40h]` 再存 `[rbx+118h]`，而 **r8 = 解码表 + opcode*20**
               （0x14008A74F-757：`movzx eax,r10b; lea rcx,[rax+rax*4]; lea r8,[r8+rcx*4]`）。
               旧实现写成 `DecodeTablePtr + 2880`，漏掉 `20*opcode` —— 于是描述符 +0x118
               指向固定表项，所有节区扫描用 `*(WORD*)(Entry[0x118]+6)` 取到的类型恒为同一值
               （实机采样恒为 0x50E 一类），`type==0x558 && Entry[0x50]&0x4000000` 永不成立
               → FindNtOpenThreadTargetWin8 返回 0 → InitAllHookSubsystems 置 Success=0
               → sc start 错误 31。 */
            SET_Q(SectionInfo, 0x118, DecodeTablePtr + 20 * (UCHAR)*BufferPos + 2880);
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
            Result = CTX_D(Context, DEC_CTX_PREFIX_FLAGS) & 0x300;   /* 原始 Classify 读描述符 +0xD8 */
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
    /* 原始 lea rax, unk_14009932C = 0x99250 + 0xDC → Legacy2 表内部偏移 */
    SET_Q(Context, DEC_CTX_CUR_TABLE_ENTRY, (ULONG64)&g_PeDecodeTableLegacy2[0xDC]);
    return (ULONG64)&g_PeDecodeTableLegacy2[0xDC];
}

// ============================================================
// CalcPESectionFieldSize — 计算 PE 节区字段大小
// 对应原始驱动 sub_14008A844
// 【修正 2026-10-18】原始 0x14008A84B 是 `mov ecx,[rax+8]`，读的是
//   **描述符 +0x08（ADDR_SIZE）**，不是 +0x24（操作数大小）。
//   旧实现读 +0x24（init=3）→ 恒走 `else` 的 2 字节分支。
// 根据地址大小(1=32位,2=64位,其他=16位)返回对应的字段大小
// ============================================================
__int64 CalcPESectionFieldSize(PUCHAR Context)
{
    INT AddrSize = CTX_D(Context, DEC_CTX_ADDR_SIZE);
    ULONG64 Result;

    if (AddrSize == 1)
        Result = 4;
    else if (AddrSize == 2)
        Result = 8;
    else
        Result = 2;

    // 缓冲区边界检查
    if (CTX_Q(Context, CTXARR_READ_PTR) + (INT)Result >
        CTX_Q(Context, CTXARR_END_PTR))
        return (ULONG64)-1;

    return Result;
}

// ============================================================
// CalcPESectionFieldSizeAlt — 计算 PE 节区字段大小(备选)
// 对应原始驱动 sub_14008A9E8
// 【修正 2026-10-18】原始 0x14008A9EC 是 `mov edx,[rax+8]`（ADDR_SIZE），
//   非零 → 4，零 → 2。旧实现读 +0x24（操作数大小）。
// ============================================================
__int64 CalcPESectionFieldSizeAlt(PUCHAR Context)
{
    ULONG64 Result = CTX_D(Context, DEC_CTX_ADDR_SIZE) != 0 ? 4 : 2;

    if (CTX_Q(Context, CTXARR_READ_PTR) + (INT)Result >
        CTX_Q(Context, CTXARR_END_PTR))
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
    /* 【ContextArray 约定】Context[0]读指针 [1]结束 [2]表条目 [3]操作数记录 [4]描述符
       原始 sub_14008A87C 逐条对照：读 v1[2]=描述符+0x08（地址大小），
       记录写 +0xF8(长度) / 操作数记录 +0x20(标志) +0x18(大小) +0x08(值) */
    PUCHAR *Args = (PUCHAR *)Context;
    PUCHAR BufferBase = Args[0];
    PUCHAR BufferEnd = Args[1];
    PUCHAR OperandOut = Args[3];
    PUCHAR DecodeContext = Args[4];
    INT AddrSize = CTX_D(DecodeContext, DEC_CTX_ADDR_SIZE);

    if (!AddrSize)
    {
        if (BufferBase + 1 >= BufferEnd)
            return (ULONG64)-1;
        SET_D(DecodeContext, DEC_CTX_READ_FLAG, 2);
        CTX_Q(OperandOut, 0x20) |= 0x200000;
        SET_D(OperandOut, 0x18, 2);
        SET_Q(OperandOut, 0x08, (ULONG64)*(USHORT *)BufferBase);
        return 2;
    }
    if (BufferBase + 3 >= BufferEnd)
        return (ULONG64)-1;
    SET_D(DecodeContext, DEC_CTX_READ_FLAG, 4);
    if (AddrSize != 2)
    {
        CTX_Q(OperandOut, 0x20) |= 0x800000;
        SET_D(OperandOut, 0x18, 4);
        SET_Q(OperandOut, 0x08, (ULONG64)*(ULONG *)BufferBase);
        return 4;
    }
    /* 原始 64 位分支（addr_size==2）：0x14008A8B1 `movsxd rcx,dword [rax]`
       —— **符号扩展** 32→64（旧实现写成零扩展），并按 8 字节记录 */
    CTX_Q(OperandOut, 0x20) |= 0x2000000;
    SET_D(OperandOut, 0x18, 8);
    SET_Q(OperandOut, 0x08, (ULONG64)(LONG64)*(INT *)BufferBase);
    return 4;
}

// ============================================================
// ReadPESectionFieldByte — 读取 PE 节区单字节字段
// 对应原始驱动 sub_14008A904
// ============================================================
__int64 ReadPESectionFieldByte(PUCHAR Context)
{
    /* 【ContextArray 约定】原始 sub_14008A904 */
    PUCHAR *Args = (PUCHAR *)Context;
    PUCHAR OperandOut = Args[3];
    PUCHAR DecodeContext = Args[4];

    if (Args[0] >= Args[1])
        return (ULONG64)-1;

    SET_D(DecodeContext, DEC_CTX_READ_FLAG, 1);
    CTX_Q(OperandOut, 0x20) |= 0x100000;
    SET_D(OperandOut, 0x18, 1);
    SET_Q(OperandOut, 0x08, (ULONG64)*(UCHAR *)Args[0]);
    return 1;
}

// ============================================================
// ReadPESectionAsmField — 读取 PE 节区汇编指令字段
// 对应原始驱动 sub_14008A93C
// 根据汇编语法格式读取操作数大小(字节/字/双字/四字)
// ============================================================
__int64 ReadPESectionAsmField(PUCHAR Context)
{
    /* 【ContextArray 约定】原始 sub_14008A93C：按描述符 +0x08（地址大小）选 2/4/8 字节 */
    PUCHAR *Args = (PUCHAR *)Context;
    PUCHAR BufferBase = Args[0];
    PUCHAR BufferEnd = Args[1];
    PUCHAR OperandOut = Args[3];
    PUCHAR DecodeContext = Args[4];
    ULONG OpSize = CTX_D(DecodeContext, DEC_CTX_ADDR_SIZE);

    if (OpSize != 1)
    {
        if (OpSize == 2)
        {
            if (BufferBase + 3 >= BufferEnd)
                return (ULONG64)-1;
            SET_D(DecodeContext, DEC_CTX_READ_FLAG, 4);
            CTX_Q(OperandOut, 0x20) |= 0x4000000;
            SET_D(OperandOut, 0x18, 8);
            /* 原始 v5 = (int)**a1 —— 有符号 32 位扩展 */
            SET_Q(OperandOut, 0x08, (ULONG64)(LONG64)*(INT *)BufferBase);
            return 4;
        }
        if (BufferBase + 1 >= BufferEnd)
            return (ULONG64)-1;
        SET_D(DecodeContext, DEC_CTX_READ_FLAG, 2);
        CTX_Q(OperandOut, 0x20) |= 0x400000;
        SET_D(OperandOut, 0x18, 2);
        SET_Q(OperandOut, 0x08, (ULONG64)*(USHORT *)BufferBase);
        return 2;
    }
    if (BufferBase + 3 >= BufferEnd)
        return (ULONG64)-1;
    SET_D(DecodeContext, DEC_CTX_READ_FLAG, 4);
    CTX_Q(OperandOut, 0x20) |= 0x1000000;
    SET_D(OperandOut, 0x18, 4);
    SET_Q(OperandOut, 0x08, (ULONG64)*(ULONG *)BufferBase);
    return 4;
}

// ============================================================
// SerializeDataToBuffer — 序列化数据到缓冲区
// 对应原始驱动 sub_14008AA0C
// 根据数据类型从缓冲区读取并序列化编码后的数据值
// ============================================================
__int64 SerializeDataToBuffer(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, CTXARR_OPERAND);   /* 【修正 2026-10-17】入参是 ContextArray，操作数记录在 +0x18（原误用真实上下文的 +0x28 → 垃圾指针 → 实机 0x7E AV）*/
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    /* 【修正 2026-10-18】原始 0x14008AA17 是 `mov eax,[rcx+4]`（rcx = 描述符），
       读的是 **描述符 +0x04（模式副本）**，不是 +0x24（操作数大小，init=3）。
       旧实现读 +0x24（恒 3）→ 三条分支全部落到 `else`（2 字节路径）→
       操作数记录与原始完全不同（差分 oracle 实测：原返回 4/8，我方返回 2）。 */
    INT DataType = CTX_D(DecodeContext, DEC_CTX_MODE_DUP);
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
            SET_D(DecodeContext, DEC_CTX_STATUS_ACC, 6);
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
            SET_D(DecodeContext, DEC_CTX_STATUS_ACC, 4);
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
        SET_D(DecodeContext, DEC_CTX_STATUS_ACC, 8);
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
            SET_D(DecodeContext, DEC_CTX_STATUS_ACC, 4);
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
            SET_D(DecodeContext, DEC_CTX_STATUS_ACC, 2);
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
    PUCHAR OutputContext = (PUCHAR)CTX_Q(Context, CTXARR_OPERAND);   /* 【修正 2026-10-17】入参是 ContextArray，操作数记录在 +0x18（原误用真实上下文的 +0x28 → 垃圾指针 → 实机 0x7E AV）*/
    ULONG64 Flags = CTX_Q(OutputContext, 0x20);
    INT Mode = CTX_D(CTX_Q(Context, CTXARR_DESC) + 4, 0);  // 偏移 0x04 = 数据类型

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    ULONG64 TableBase;
    /* 原始读 v1[40] = 描述符 +0x28（子类型字节），非 +0x2C */
    UCHAR Mode = CTX_B(DecodeContext, DEC_CTX_SUBTYPE_BYTE);

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
    /* 原始 v5 = (char *)&unk_140099250 + 20 * opcode（Legacy2 表按操作码索引） */
    TableEntry = (ULONG64)&g_PeDecodeTableLegacy2[0] + 20 * OpcodeByte;

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    ULONG PrefixIndex;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    /* 原始：r8 = off_14009E250[opcode>>4]（16 项指针表，指向 320 字节子表）
              r8 ? r8 + 20*(opcode&0xF) : &unk_140096A30（默认表首项） */
    PrefixIndex = OpcodeByte >> 4;
    TableEntry = g_PeDecodeTablePrefixPtrA[PrefixIndex];
    if (TableEntry)
        TableEntry += 20 * (OpcodeByte & 0xF);
    else
        TableEntry = (ULONG64)g_PeDecodeTableDefault;

    /* 原始读 v1[40] = 描述符 +0x28（子类型字节） */
    UCHAR SubType = CTX_B(DecodeContext, DEC_CTX_SUBTYPE_BYTE);
    if (SubType == 0)
    {
        /* 原始：r11 = off_14009E2D0[opcode>>4] */
        ULONG64 AltTable = g_PeDecodeTablePrefixPtrB[PrefixIndex];
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
    else if (SubType == 3)
    {
        /* 原始：r11 = qword_1400CCEC0[opcode>>4]（.data 虚拟填充区，全 0 → 该分支在
           原始驱动中恒不生效，属死代码；此处按原样保留结构） */
        ULONG64 AltTable = g_PeDecodeTableSubtypePtr[PrefixIndex];
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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    ULONG PrefixIndex;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE) = OpcodeByte;

    PrefixIndex = OpcodeByte >> 4;
    /* 原始：v3 = qword_1400CCF40[opcode>>4]；该表位于 .data 虚拟填充区（全 0），
       故 v3 == 0 恒成立 → 表条目 = &unk_140096A30（默认表首项，**不带索引**） */
    TableEntry = g_PeDecodeTableDirectPtr[PrefixIndex];
    if (TableEntry)
    {
        ULONG64 AltEntry = TableEntry + 20 * (OpcodeByte & 0xF);
        if (*(USHORT *)(AltEntry + 4) != 0xFFFF)
        {
            CTX_D(DecodeContext, DEC_CTX_ADDR_SIZE) = CTX_D(DecodeContext, DEC_CTX_MODE);
            CTX_D(DecodeContext, DEC_CTX_STATE_FLAGS) &= ~2u;
            TableEntry = AltEntry;
        }
    }
    else
    {
        TableEntry = (ULONG64)g_PeDecodeTableDefault;
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

// DecodeOpcodeTableWithOffset — 带偏移量的操作码表解码
// 对应原始驱动 sub_14008B108
// 基于前一个操作码字节和当前字节的 reg 域计算解码表偏移
__int64 DecodeOpcodeTableWithOffset(PUCHAR Context)
{
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    UCHAR PrevOpcode;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    PrevOpcode = CTX_B(DecodeContext, DEC_CTX_LAST_OPCODE_SAVE);

    /* 【原始算法】v4 = &unk_14009E350 + 160*desc[0xE4] + 20*((byte>>3)&7) - 20480
       0x14009E350 - 0x5000 = 0x140099350 = Legacy2 表 + 0x100，即 2D 表
       [上一个操作码][modrm.reg3]（每行 8 项 × 20 字节 = 160 字节） */
    TableEntry = (ULONG64)&g_PeDecodeTableLegacy2[0x100]
               + 160 * (ULONG)PrevOpcode
               + 20 * ((OpcodeByte >> 3) & 7);

    CTX_Q(Context, CTXARR_TABLE) = TableEntry;  // 原始：a1[2] = 表条目

    /* 原始：v5 = (*v4 != 0)，读指针**不前进**（Dispatch 传的是 v1 而非 v1+1） */
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    // 【原始】cmp dl,0C0h / cmp al,r8b(1) / cmp al,3 —— 前两条比较都是**8 位截断**
    //   （(BYTE)(prev+0x40) <= 1 → prev ∈ {0xC0,0xC1}；(BYTE)(prev+0x30) <= 3 → prev ∈ {0xD0..0xD3}）
    //   第三支（else）原始从栈参数取值（未初始化），此处按默认表索引 0 处理
    ULONG64 BaseOffset;
    if (PrevOpcode >= 0xC0)
    {
        if ((UCHAR)(PrevOpcode + 0x40) <= 1)
            BaseOffset = 8 * PrevOpcode - 1536;   // 0xC0/0xC1 → 0 / 8
        else if ((UCHAR)(PrevOpcode + 0x30) <= 3)
            BaseOffset = 8 * PrevOpcode - 1648;   // 0xD0..0xD3 → 16..47
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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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

    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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

    /* 原始：*((_QWORD *)DecodeContext + 35) = pDecodeEntry → 描述符 +0x118（= DEC_CTX_CUR_TABLE_ENTRY），
       旧代码写的 0x160 越出描述符范围 */
    SET_Q(DecodeContext, DEC_CTX_CUR_TABLE_ENTRY, (ULONG64)SubTable);

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

    /* 原始：TotalSize = *pDecodeEntry ? (pDecodeEntry[1] != 0) : 0 —— 初值即 HasEntry，
       既作为读指针偏移，也计入最终返回值 */
    TotalSize = 0;
    if (*(UCHAR *)SubTable)
        TotalSize = *(UCHAR *)(SubTable + 1) != 0;
    OpIndex = 0;

    UCHAR *OpPtr = (UCHAR *)SubTable;
    while (1)
    {
        if (*OpPtr == 0xFF)
            break;

        // 构造调用上下文
        PUCHAR FuncContext = (PUCHAR)CTX_Q(Context, 0);
        // 设置函数分发参数
        ULONG64 FuncContextArray[6];
        FuncContextArray[0] = (ULONG64)(BufferBase + TotalSize);
        FuncContextArray[1] = (ULONG64)BufferEnd;
        FuncContextArray[2] = (ULONG64)SubTable;
        FuncContextArray[3] = CTX_Q(Context, CTXARR_OPERAND);  /* 原始 v14[3] = pContext[3] */
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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp4[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
                TableEntry = (ULONG64)&g_PeDecodeTablePrefixM3[0] + 20 * RegIndex;  /* 原 unk_14009EDF0（mod==3,rm==1）*/
            else
                goto USE_DEFAULT;
        }
        else
        {
            TableEntry = (ULONG64)&g_PeDecodeTablePrefixM1[0] + 20 * RegIndex;  /* 原 unk_14009ED50（mod==3,rm==0）*/
        }
    }
    else
    {
USE_DEFAULT:
        TableEntry = (ULONG64)&g_PeDecodeTablePrefixM0[0] + 20 * RegIndex;  /* 原 unk_14009ECB0（mod!=3 或 rm>=2）*/
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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp5[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableGrp6[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
        (PUCHAR)(BufferBase + 1), (ULONG64)BufferEnd, DecodeContext, 0);
    if (ImmediateSize == -1)
        return (ULONG64)-1;

    // 计算后续字节的分发表
    PUCHAR NextByte = BufferBase + ImmediateSize + 1;
    if (NextByte >= BufferEnd)
        return (ULONG64)-1;

    /* 原始：pDecodeTable = (char *)&unk_14009F610 + 20 * *pNextByte
       （0x9F610 = 256 项 × 20 字节的 ModRM 操作码分发表） */
    TableEntry = (ULONG64)&g_PeDecodeTableModrmOpcode[0] + 20 * *NextByte;
    CTX_Q(Context, CTXARR_TABLE) = TableEntry;

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableOneByte[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
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
    PUCHAR BufferBase = (PUCHAR)CTX_Q(Context, CTXARR_READ_PTR);
    PUCHAR BufferEnd = (PUCHAR)CTX_Q(Context, CTXARR_END_PTR);
    PUCHAR DecodeContext = (PUCHAR)CTX_Q(Context, CTXARR_DESC);
    UCHAR OpcodeByte;
    ULONG64 TableEntry;
    BOOLEAN HasEntry;
    int DispatchResult;

    if (BufferBase >= BufferEnd)
        return (ULONG64)-1;

    OpcodeByte = *BufferBase;
    TableEntry = (ULONG64)&g_PeDecodeTableOpcodeByte[0] + 20 * ((OpcodeByte >> 3) & 7);
    CTX_Q(Context, 0x10) = TableEntry;
    /* 【修正 2026-10-17】原始为 AND 语义：byte0!=0 && byte1!=0
       （原始 `cmp [r8],bl; jz` + `cmp [r8+1],bl; jz`，两处跳转都不成立才置 1）。
       旧代码 `*(USHORT*)TableEntry != 0` 是 OR 语义，对 byte0==0 的条目
       （例如 Legacy2 表的 `00 21 ff`）会多算 1 字节 → 解码流从该条起整体错位，
       实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目。 */
    HasEntry = (*(UCHAR *)TableEntry != 0) && (*(UCHAR *)((PUCHAR)TableEntry + 1) != 0);

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
    /* 【ContextArray 约定】原始 sub_14008BF20 */
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];

    if (Context[0] >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_READ_FLAG, 1);
    CTX_Q(OperandOut, 0x20) |= 0x80000;
    SET_D(OperandOut, 0x18, 1);
    SET_Q(OperandOut, 0x08, (ULONG64)*(UCHAR *)Context[0]);
    return 1;
}

// ============================================================
// DecodeReadWordImmediate — 解码读取16位立即数
// 对应原始驱动 sub_14008C008
// ============================================================
__int64 DecodeReadWordImmediate(PUCHAR *Context)
{
    /* 【ContextArray 约定】原始 sub_14008C008 */
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];

    if (Context[0] + 1 >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_READ_FLAG, 2);
    CTX_Q(OperandOut, 0x20) |= 0x200000;
    SET_D(OperandOut, 0x18, 2);
    SET_Q(OperandOut, 0x08, (ULONG64)*(USHORT *)Context[0]);
    return 2;
}

// ============================================================
// DecodeReadSizeDependentImmediate — 解码读取大小相关的立即数
// 对应原始驱动 sub_14008C0F8
// 【修正 2026-10-18】选择依据是**描述符 +0x08（ADDR_SIZE）**，不是 +0x24（OPERAND_SIZE）。
//   原始 0x14008C100 是 `mov eax,[r9+8]`（r9 = Context[4] = 描述符），
//   随后 `cmp eax,1` → 4 字节分支；`cmp eax,2` → 8 字节；否则 2 字节。
//   旧实现读 +0x24（操作数大小，init=3）→ 在本机恒走 16 位分支，
//   于是 `B8 41 00 00 00`（mov eax,0x41）只吃掉 3 字节（B8 41 00），
//   描述符 op1 标志置 0x200000 而非 0x800000 → FindKernelPESectionByType
//   的 `(Entry[0x88] & 0x800000)` 判据不成立 → 返回默认值 0x1000000 →
//   FindSyscallNumbers 的 stride 与扫描锚点全错 → GT[0x62] 永不写入。
// 【逆向来源】0x14008C0F8–0x14008C18A 逐条对照。
// 根据地址大小(1=32位,2=64位,其他=16位)读取立即数
// ============================================================
__int64 DecodeReadSizeDependentImmediate(PUCHAR *Context)
{
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    INT AddrSize = CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE);
    ULONG64 Value;
    ULONG FieldSize;

    if (AddrSize == 1)
    {
        // 32 位模式
        if (Context[0] + 3 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 4;
        SET_D(DecodeCtx, DEC_CTX_STATUS_ACC, 4);
        Value = (ULONG64)*(ULONG *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x800000;
    }
    else if (AddrSize == 2)
    {
        // 64 位模式
        if (Context[0] + 7 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 8;
        SET_D(DecodeCtx, DEC_CTX_STATUS_ACC, 8);
        Value = *(ULONG64 *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x2000000;
    }
    else
    {
        // 16 位模式
        if (Context[0] + 1 >= Context[1])
            return (ULONG64)-1;
        FieldSize = 2;
        SET_D(DecodeCtx, DEC_CTX_STATUS_ACC, 2);
        Value = (ULONG64)*(USHORT *)Context[0];
        CTX_Q(OperandOut, 0x20) |= 0x200000;
    }

    SET_D(OperandOut, 6, FieldSize);
    SET_Q(OperandOut, 8, Value);
    return FieldSize;
}

// ============================================================
// DecodeReadImmediateValue — 解码读取立即数
// 对应原始驱动 sub_14008BF68（36 条指令，逐条核对）
// 【修正 2026-10-17】旧实现与原始语义整体不符：
//   - 选择依据：原始读 **描述符 +0x08（AddrSize）**，旧代码读 +0x24（OperandSize）
//   - 读取宽度：原始**恒读 1 个有符号字节**，旧代码按 4/8/2 字节读
//   - 写入偏移：原始写描述符 +0xF8=1（读取长度）与操作数记录 +0x18（大小）
//     +0x20（标志）、+0x08（值）；旧代码把长度写进 +0x100，并把大小写进 +0x06
//   - 返回值：原始**恒返回 1**（仅越界时返回 -1），旧代码返回 4/8/2
//   该返回值直接进 DispatchInstructionDecode 的长度累加，故旧实现每个
//   `00 21 FF` 之类的表项都会多算 1 字节，导致解码流整体错位
//   （实机表现为 FindNtOpenThreadTargetWin8 扫不到 type==0x558 的条目）。
// ============================================================
__int64 DecodeReadImmediateValue(PUCHAR *Context)
{
    ULONG64 BufferEnd = Context[1];
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];
    INT AddrSize;
    ULONG64 Value;
    ULONG Result = 1;

    if (Context[0] >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_READ_FLAG, 1);

    AddrSize = CTX_D(DecodeCtx, DEC_CTX_ADDR_SIZE);
    if (AddrSize == 1)
    {
        /* movsx eax,byte [rax] → 32 位符号扩展后零扩展入 rax */
        Value = (ULONG64)(ULONG)(INT)(*(signed char *)Context[0]);
        SET_D(OperandOut, 0x18, 4);
        SET_Q(OperandOut, 0x08, Value);
        CTX_Q(OperandOut, 0x20) |= 0x400000000LL;
    }
    else if (AddrSize == 2)
    {
        /* movsx rcx,byte [rax] → 完整 64 位符号扩展 */
        Value = (ULONG64)(LONG64)(*(signed char *)Context[0]);
        SET_D(OperandOut, 0x18, 8);
        CTX_Q(OperandOut, 0x20) |= 0x1000000000LL;
        SET_Q(OperandOut, 0x08, Value);
    }
    else
    {
        /* movsx ecx + movzx eax,cx → 符号扩展至 16 位 */
        Value = (ULONG64)(USHORT)(INT)(*(signed char *)Context[0]);
        SET_D(OperandOut, 0x18, 2);
        SET_Q(OperandOut, 0x08, Value);
        CTX_Q(OperandOut, 0x20) |= 0x200000000LL;
    }

    return Result;
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
    NewModeFlags = (PrefixByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xFFFFFC00)
                 | (2 * (PrefixByte & 0x38 | (2 * (PrefixByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS, NewModeFlags);

    // 检查是否需要设置 64 位标志
    if ((CTX_D(Context[2], 4) & 0x2000000) != 0)
        SET_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS, NewModeFlags | 0x300);

    // REX 前缀处理
    /* 【修正 2026-10-18】原始 0x14008BD77 `mov eax,[r8+0x20]` + `test al,0x40`
       —— 读的是 **描述符 +0x20（状态标志）**，不是 +0x08（地址大小）；
       0x14008BD7F `mov ecx,[r8+0x2c]` —— 读的是 **+0x2C（类型 5 的取值）**，
       不是 +0x24（操作数大小）。旧实现两处都读错，
       REX 分支的条件与取值全偏。 */
    if ((CTX_D(DecodeCtx, DEC_CTX_STATE_FLAGS) & 0x40) != 0)
    {
        OperandSize = CTX_D(DecodeCtx, DEC_CTX_TYPE5_VALUE);
        CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) |= ((OperandSize >> 2) & 1) << 7;

        NewModeFlags = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS);
        ULONG RegField = (NewModeFlags >> 8) & 3;

        if ((RegField == 3 || (NewModeFlags & 0xF) != 4) &&
            (RegField != 0 || (NewModeFlags & 0xF) != 5))
        {
            CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) = NewModeFlags | (8 * (OperandSize & 1));
        }
    }

    // 解码立即操作数
    Result = (int)DecodeImmediateOperandValue(Context[0], (ULONG64)Context[1], DecodeCtx, (PULONG)&ImmediateSize);
    if (Result == -1)
        return (ULONG64)-1;

    RemainingSize = Result + 1;
    Context[0] += ImmediateSize;
    DecodeModrmInstruction((PULONG64)Context);
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

    NewModeFlags = (PrefixByte & 7) | (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xFFFFFC00)
                 | (2 * (PrefixByte & 0x38 | (2 * (PrefixByte & 0xC0))));
    SET_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS, NewModeFlags);

    if ((CTX_D(Context[2], 4) & 0x2000000) != 0)
        SET_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS, NewModeFlags | 0x300);

    /* 【修正 2026-10-18】原始 0x14008BE92/0x14008BE9A 读 [r8+0x20]（状态标志）与
       [r8+0x2c]（类型 5 取值），非 +0x08/+0x24。同上。 */
    if ((CTX_D(DecodeCtx, DEC_CTX_STATE_FLAGS) & 0x40) != 0)
    {
        OperandSize = CTX_D(DecodeCtx, DEC_CTX_TYPE5_VALUE);
        CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) |= ((OperandSize >> 2) & 1) << 7;

        NewModeFlags = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS);
        ULONG RegField = (NewModeFlags >> 8) & 3;

        if ((RegField == 3 || (NewModeFlags & 0xF) != 4) &&
            (RegField != 0 || (NewModeFlags & 0xF) != 5))
        {
            CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) = NewModeFlags | (8 * (OperandSize & 1));
        }
    }

    Result = (int)DecodeImmediateOperandSize(Context[0], (ULONG64)Context[1], DecodeCtx, (PULONG)&SizeResult);
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
// 【修正 2026-10-18】旧实现整体语义不符（逐条对照 0x14008C3FC 重写）：
//   1) 组合结果写入 **描述符 +0xDC（ModRM 字节）**，不是 +0xD8（前缀标志）；
//      `mov [r8+0xdc], r11d`（0x14008C448）—— +0xDC 是被读-改-写的累加槽；
//   2) 保留位取 **+0xDC** 的高 22 位（0x14008C429），不是 +0xD8；
//   3) REX 扩展的开关是 **+0x20（状态标志）& 0x40**（0x14008C43B/44F），
//      不是 +0x08（地址大小）；
//   4) REX 扩展的取值来自 **+0x2C（类型 5 取值）**（0x14008C466/47A），
//      不是 +0x24；
//   5) RIP 相对位移写入 **+0xE0**、长度写 **+0xF4**（0x14008C4B7/C8），
//      旧实现写反到 +0xF4/+0xF8；
//   6) 返回值为 5（读到位移）/1（仅 ModRM）/-1（越界）。
// ============================================================
__int64 DecodeModrmByte(ULONG64 BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx)
{
    UCHAR ModrmByte;
    ULONG Composed;
    LONG Result = 1;

    if (BufferPos >= BufferEnd)
        return (ULONG64)-1;

    ModrmByte = *(PUCHAR)BufferPos;

    /* 组合 ModRM：低 3 位 | 2×(0x38 位) | 4×(0xC0 位) | 保留 +0xDC 高 22 位 */
    Composed = (ModrmByte & 7)
             | (2 * ((ModrmByte & 0x38) | (2 * (ModrmByte & 0xC0))))
             | (CTX_D(DecodeCtx, DEC_CTX_MODRM_BYTE) & 0xFFFFFC00);
    SET_D(DecodeCtx, DEC_CTX_MODRM_BYTE, Composed);

    /* REX 扩展：开关是状态标志 +0x20 的 0x40 位，取值是类型 5 取值 +0x2C */
    if ((CTX_D(DecodeCtx, DEC_CTX_STATE_FLAGS) & 0x40) != 0)
    {
        if ((Composed & 0xF) != 5 ||
            (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0x300) == 0)
        {
            SET_D(DecodeCtx, DEC_CTX_MODRM_BYTE,
                  ((CTX_D(DecodeCtx, DEC_CTX_TYPE5_VALUE) & 1) << 3) | Composed);
        }
        CTX_D(DecodeCtx, DEC_CTX_MODRM_BYTE) |=
            ((((CTX_D(DecodeCtx, DEC_CTX_TYPE5_VALUE) >> 1) & 1) << 3) << 4);
    }

    /* RIP 相对寻址 (mod=00, rm=101 in 64-bit mode) */
    if ((CTX_D(DecodeCtx, DEC_CTX_MODRM_BYTE) & 0xF) == 5 &&
        (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0x300) == 0)
    {
        if (BufferPos + 4 < BufferEnd)
        {
            SET_D(DecodeCtx, DEC_CTX_IMM_FLAG, 4);
            CTX_D(DecodeCtx, DEC_CTX_IMM_VALUE) = *(LONG *)(BufferPos + 1);
            Result = 5;
        }
        else
        {
            return (ULONG64)-1;
        }
    }

    return (ULONG64)Result;
}

// ============================================================
// DecodeModrmByteSimple — 解码ModRM字节(简化版)
// 对应原始驱动 sub_14008C4DC
// 不读取位移量但返回总字节数，用于仅计算操作数大小的场景
// 【修正 2026-10-18】逐条对照 0x14008C4DC 重写：
//   组合结果写 **+0xDC（ModRM 字节）**；保留位取 +0xDC 高 22 位；
//   REX 开关是 **+0x20（状态标志）& 0x40**、取值是 **+0x2C（类型 5 取值）**；
//   RIP 相对寻址返回 5（读得下 4 字节位移）/ -1（越界）。
// ============================================================
__int64 DecodeModrmByteSimple(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx)
{
    UCHAR ModrmByte;
    ULONG Composed;

    if ((ULONG64)BufferPos >= BufferEnd)
        return (ULONG64)-1;

    ModrmByte = *BufferPos;
    Composed = (ModrmByte & 7)
             | (2 * ((ModrmByte & 0x38) | (2 * (ModrmByte & 0xC0))))
             | (CTX_D(DecodeCtx, DEC_CTX_MODRM_BYTE) & 0xFFFFFC00);
    SET_D(DecodeCtx, DEC_CTX_MODRM_BYTE, Composed);

    // REX 扩展
    if ((CTX_D(DecodeCtx, DEC_CTX_STATE_FLAGS) & 0x40) != 0)
    {
        ULONG Type5 = CTX_D(DecodeCtx, DEC_CTX_TYPE5_VALUE);
        SET_D(DecodeCtx, DEC_CTX_MODRM_BYTE,
              Composed
              | (((Type5 & 1) << 3))
              | ((((Type5 >> 1) & 1) << 3) << 4));
    }

    // RIP 相对寻址
    if ((CTX_D(DecodeCtx, DEC_CTX_MODRM_BYTE) & 0xF) == 5 &&
        (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0x300) == 0)
    {
        return (ULONG64)(BufferPos + 4) <= BufferEnd ? 5 : (ULONG64)-1;
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
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) >> 8) & 3;
    ULONG TotalSize = 0;
    ULONG DecodedSize = 0;
    ULONG Value;
    ULONG Size;

    if (pSize)
        *pSize = 0;

    /* 【修正 2026-10-18】原始 0x14008C5E0 是 `cmp dword ptr [r8+4], ecx`
       （r8 = 描述符），读的是 **+0x04（模式副本）**，不是 +0x24（操作数大小）。 */
    if (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) == 0)
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
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) >> 8) & 3;
    ULONG TotalSize = 0;
    ULONG DecodedSize = 0;

    if (pSize)
        *pSize = 0;

    /* 【修正 2026-10-18】原始 0x14008C728 是 `cmp dword ptr [r8+4], ecx`
       （r8 = 描述符），读的是 **+0x04（模式副本）**，不是 +0x24（操作数大小）。 */
    if (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) == 0)
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
    /* 【修正 2026-10-19】原始 0x14008C1B6 读 `[rcx+8]` = **Context+0x08**
       （旧代码误写成 Context+2）。 */
    ULONG AddressMode = CTX_D(Context, 8);
    ULONG Result = 0;

    if (Flag)
    {
        /* 【修正 2026-10-19】原始 0x14008C19C 是 `cmp dword ptr [rcx+4], 2`
           —— 读 **Context+0x04**，旧代码误写成 Context+0x01（读到垃圾/0）
           → RegIndex 停在 4（置 0x20）而非 11（置 0x40）
           → 描述符 +0x50 出现 0x21 而原始是 0x41
           → FindHookTargetInExportWin8 的 `+0x50 == 0x40000` 判据永不成立。 */
        RegIndex = 4;
        if (CTX_D(Context, 4) == 2)
            RegIndex = 11;
    }
    else if (RegIndex == 15 || RegIndex == 0)
    {
        /* 【修正 2026-10-19】原始 0x14008C1CA/1C8/1D1 的映射为
           AddressMode==1 → 4、AddressMode==2 → 11、**==0 → 16**；
           旧代码把 1 与 2 的结果写反了（1→11、2→4）。 */
        if (AddressMode == 1)
            RegIndex = 4;
        else if (AddressMode == 2)
            RegIndex = 11;
        else
            RegIndex = 16;
    }

    // 设置寻址模式标志
    if (RegIndex == 3)
    {
        // 直接寄存器寻址；原始 0x14008C1FE 读 `[r10+0x20]` = Context+0x20
        ULONG AddrSizeFlags = CTX_D(Context, 0x20);
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
// 【修正 2026-10-18】两处选择依据均为**描述符 +0x04（模式副本）**，不是 +0x24：
//   原始 0x14008C7EB `cmp dword ptr [rdx+4], 1`（选 32/64 位大小标志）
//   原始 0x14008C832 `cmp dword ptr [rdx+4], 1`（选 +0x10 写入宽度）
//   旧实现读 +0x24（操作数大小，init=3）→ 恒不等 1 → 大小标志恒 64、
//   +0x10 恒按 64 位写。与原始语义不符。
// 根据ModRM解码结果设置操作数的类型标志和寄存器编号
// ============================================================
__int64 SetupDecodedInstructionState(
    PUCHAR OperandOut,
    PUCHAR DecodeCtx)
{
    ULONG ModeFlags = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS);
    ULONG RegField = (ModeFlags >> 4) & 0xF;
    ULONG RmField = ModeFlags & 0xF;
    ULONG AddrSizeField = (ModeFlags >> 8) & 3;
    ULONG64 SizeFlag = 64;

    if (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) == 1)
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

    if (RmField != 5 || (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0x300) != 0)
    {
        SET_D(OperandOut, 0x28, RmField);
        CTX_Q(OperandOut, 0x20) |= SizeFlag | 1;
    }
    else if (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) == 1)
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
    /* 【修正 2026-10-17】原始 0x14008C322 是 `cmp [r9], r8d`（r8d=2），比较的是
       **描述符 +0x00（Mode）**，不是 +0xD8（前缀标志）。旧代码读 +0xD8 恒 != 2，
       于是总走 else 分支把 desc+0x08 置 1；原始对 64 位模式且表项 +0x10 含
       0x400000/0x200000 的条目会置 2。desc+0x08 正是 ReadPESectionAsmField
       判定的 OpSize：置 2 时它 OR 0x4000000，置 1 时 OR 0x1000000 —— 实机表现为
       FindNtOpenThreadTargetWin8 拿到的 Entry[0x50] 缺 bit26，`& 0x4000000` 判定失败。 */
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
        CalcOpcodeSize((PUCHAR)DecodeCtx, (PULONG)(56LL * (OperandIndex - 1) + DecodeCtx + 0x30));

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
    ULONG ModeField = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xF;
    ULONG RegField = (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) >> 4) & 0xF;
    ULONG AddrField = (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) >> 8) & 3;
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
                INT RegCount = (CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) >> 4) & 7;
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
                    ModeField = CTX_D(DecodeCtx, DEC_CTX_PREFIX_FLAGS) & 0xF;
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
    /* 【修正 2026-10-18】原始 0x14008B88A 是 `cmp dword ptr [rdi+4], 0`
       （rdi = 描述符），读的是 **+0x04（模式副本）**，不是 +0x24（操作数大小）。 */
    if (CTX_D(DecodeCtx, DEC_CTX_MODE_DUP) == 0)
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
                /* 【修正 2026-10-17】原始 0x14008B954 是 `cmp dword ptr [rdi], 2`
                   （rdi = 描述符，[rdi] = **Mode**），旧代码误读 +0xD8（前缀标志）。
                   原始在 Mode==2 时置 bit18（0x40000），否则置 bit16（0x10000）。 */
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
                DecodeModrmAddressingMode((PULONG)DecodeCtx, 0, ModeField, OperandOut, 1);
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
                DecodeModrmAddressingMode((PULONG)DecodeCtx, 0, ModeField, OperandOut, 1);
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
    DecodeModrmAddressingMode((PULONG)DecodeCtx, 0, RegField, OperandOut, IsModrmAddr);
    return 0;
}

// ============================================================
// DecodeReadDwordImmediate — 解码读取32位立即数
// 对应原始驱动 sub_14008C058
// ============================================================
__int64 DecodeReadDwordImmediate(PUCHAR *Context)
{
    /* 【ContextArray 约定】原始 sub_14008C058 */
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];

    if (Context[0] + 3 >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_READ_FLAG, 4);
    CTX_Q(OperandOut, 0x20) |= 0x800000;
    SET_D(OperandOut, 0x18, 4);
    SET_Q(OperandOut, 0x08, (ULONG64)*(ULONG *)Context[0]);
    return 4;
}

// ============================================================
// DecodeReadQwordImmediate — 解码读取64位立即数
// 对应原始驱动 sub_14008C0A8
// ============================================================
__int64 DecodeReadQwordImmediate(PUCHAR *Context)
{
    /* 【ContextArray 约定】原始 sub_14008C0A8（与 Word/Dword 同族，8 字节） */
    PUCHAR OperandOut = (PUCHAR)Context[3];
    PUCHAR DecodeCtx = (PUCHAR)Context[4];

    if (Context[0] + 7 >= Context[1])
        return (ULONG64)-1;

    SET_D(DecodeCtx, DEC_CTX_READ_FLAG, 8);
    CTX_Q(OperandOut, 0x20) |= 0x2000000;
    SET_D(OperandOut, 0x18, 8);
    SET_Q(OperandOut, 0x08, *(ULONG64 *)Context[0]);
    return 8;
}

// FindPESectionByName — 按名称查找 PE 节（返回节在文件内的偏移）
// 对应原始驱动 0x140005C28（137 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（26 行伪代码），按伪代码实现
// 【⚠ 修正记录】本函数**此前只有 SSDT.c 里一个 2 参数的 static 简化版**，而
//   ContextMgmt/Minifilter/PeParse 都在调用它（靠隐式声明蒙混），且头文件的
//   3 参数声明（原始伪代码实证）与之不符 —— 本轮按原始伪代码补齐全局实现。
// 【逻辑】读 PE 头 +0x3C 处的签名偏移 → 取节数(+6) 与节头起始(+20/+24) →
//   遍历节头（每节 40 字节）用 StringCompareCaseInsensitiveV2 比较节名 →
//   命中且该节的文件偏移（+12）< 文件大小则返回之，否则返回 0。
__int64 FindPESectionByName(__int64 PeBase, unsigned int PeSize, __int64 SectionName)
{
    __int64 PeHeaderRva;
    unsigned int Result = 0;
    unsigned int NumberOfSections;
    __int64 SectionHeaderStart;
    unsigned int SectionIndex;

    PeHeaderRva = *(int *)(PeBase + 60);
    NumberOfSections = *(unsigned __int16 *)(PeHeaderRva + PeBase + 6);
    SectionHeaderStart = *(unsigned __int16 *)(PeHeaderRva + PeBase + 20) + PeHeaderRva + PeBase + 24;
    SectionIndex = 0;

    if (*(_WORD *)(PeHeaderRva + PeBase + 6))
    {
        while ((unsigned int)StringCompareCaseInsensitiveV2(SectionName,
                                                            SectionHeaderStart + 40LL * SectionIndex))
        {
            if (++SectionIndex >= NumberOfSections)
                return Result;
        }
        if (*(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 12) < PeSize)
            return *(unsigned int *)(SectionHeaderStart + 40LL * SectionIndex + 12);
    }
    return Result;
}

// FindPESectionByNameReturnVa — 按名称查找 PE 节（返回节虚拟地址）
// 对应原始驱动 0x140005CB4（151 字节）
// 【逆向来源】⚠ 可被反编译（33 行伪代码），按伪代码实现（同上处修正说明）
// 【逻辑】同上，但命中后需额外校验：节 VA(+8) < 文件大小 且 节大小(+12) < 文件大小
//   且 VA+Size < 文件大小，才返回该节 VA；否则返回 0。
__int64 FindPESectionByNameReturnVa(__int64 PeBase, unsigned int PeSize, __int64 SectionName)
{
    __int64 PeSignature;
    unsigned int Result = 0;
    unsigned int NumberOfSections;
    __int64 SectionHeaderStart;
    unsigned int SectionIndex;
    unsigned int SectionVa;
    unsigned int SectionSize;

    PeSignature = *(int *)(PeBase + 60);
    NumberOfSections = *(unsigned __int16 *)(PeSignature + PeBase + 6);
    SectionHeaderStart = *(unsigned __int16 *)(PeSignature + PeBase + 20) + PeSignature + PeBase + 24;
    SectionIndex = 0;

    if (*(_WORD *)(PeSignature + PeBase + 6))
    {
        while ((unsigned int)StringCompareCaseInsensitiveV2(SectionName,
                                                            SectionHeaderStart + 40LL * SectionIndex))
        {
            if (++SectionIndex >= NumberOfSections)
                return Result;
        }
        SectionVa = *(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 8);
        if (SectionVa < PeSize)
        {
            SectionSize = *(_DWORD *)(SectionHeaderStart + 40LL * SectionIndex + 12);
            if (SectionSize < PeSize && SectionVa + SectionSize < PeSize)
                return *(unsigned int *)(SectionHeaderStart + 40LL * SectionIndex + 8);
        }
    }
    return Result;
}
