// ============================================================
// 自定义结构体定义
// ============================================================

#include "xpc_basic.h"

// ============================================================
// 基本类型定义
// ============================================================
typedef struct _IRP_INPUT_HEADER {
    ULONG Type;                     // 必须为 0x20202020
    ULONG Type2;                    // 辅助类型
    ULONG ChecksumHigh;             // 校验和高位
    ULONG ChecksumLow;              // 校验和低位
    ULONG Param1;                   // 参数 1 (Flink)
    ULONG Param2;                   // 参数 2 (Flink high)
    ULONGLONG Param3;                 // 参数 3 (UserBuffer1)
    ULONGLONG Param4;                 // 参数 4 (UserBuffer2)
    ULONGLONG Param5;                 // 参数 5 (MdlAddress)
    ULONG Opcode;                   // 操作码 (Size+1 处)
} IRP_INPUT_HEADER, *PIRP_INPUT_HEADER;

// ============================================================
// MD5 上下文（族 2）—— InitMd5Context / Md5Update / Md5Final
// 【布局依据】原始反汇编逐条核对（全部为 capstone/IDA `op.addr` 实测位移）：
//   InitMd5Context 0x140059CB4: memset(0, 0x58)；State 写入 +0x00/+0x04/+0x08/+0x0C
//   Md5Update     0x14005A50C: 计数读写在 +0x50；缓冲 memmove 目标 = +0x10+index；
//                              Md5Transform2(State=+0x00, Block=+0x10)
//   Md5Final      0x140059C14: 长度尾写入 +0x48/+0x4C（即 Buffer 末 8 字节）；摘要取 +0x00
//   故 Buffer 覆盖 +0x10..+0x4F，计数紧随其后位于 +0x50，结构总长 0x58。
// 【⚠ 缺陷修正】此前误写为 State@0x00 / Count[2]@0x10 / Buffer@0x18，与原始完全不符。
typedef struct _MD5_CONTEXT {
    ULONG State[4];                 // 0x00: 状态 (A,B,C,D)
    UCHAR Buffer[64];               // 0x10: 数据缓冲区（末 8 字节存 64 位位长）
    ULONGLONG Count;                // 0x50: 64 位**字节**计数（非位计数）
} MD5_CONTEXT, *PMD5_CONTEXT;

// ============================================================
// MD5 上下文（族 1）—— Md5Init / Md5Update2 / Md5Final2 / Md5Transform
// 【布局依据】原始反汇编逐条核对：
//   Md5Init    0x140003A28: memset(0, 0x58)；State 写入 +0x48/+0x4C/+0x50/+0x54
//   Md5Update2 0x140003A60: 计数读写在 +0x00；缓冲 memmove 目标 = +0x08+index；
//                           Md5Transform(State=+0x48, Block=+0x08)
//   Md5Final2  0x140003988: 长度尾写入 +0x40/+0x44（即 Buffer 末 8 字节）；摘要取 +0x48
//   故 Buffer 覆盖 +0x08..+0x47，状态位于 +0x48，结构总长 0x58。
typedef struct _MD5_CONTEXT_LEGACY {
    ULONGLONG Count;                // 0x00: 64 位**字节**计数
    UCHAR Buffer[64];               // 0x08: 数据缓冲区（末 8 字节存 64 位位长）
    ULONG State[4];                 // 0x48: 状态 (A,B,C,D)
} MD5_CONTEXT_LEGACY, *PMD5_CONTEXT_LEGACY;

// ============================================================
// SHA1 上下文
// 【布局依据】原始反汇编逐条核对：
//   Sha1InitContext  0x140076500: memset(0, 0x60)；State 写入 +0x08/+0x0C/+0x10/+0x14/+0x18
//   Sha1Update       0x14007761C: 计数为 **单个 64 位位计数**，读写在 +0x00
//                                  （`mov r11,[rcx]` / `add [rcx], Length<<3`）；
//                                  缓冲 memmove 目标 = +0x1C+index；
//                                  Sha1Transform(State=+0x08, Block=+0x1C)
//   Sha1FinalTransform 0x1400763E0: `mov rcx,[rbx]` 取 64 位位计数按大端展开为 8 字节
//   故 State 位于 +0x08，Buffer 覆盖 +0x1C..+0x5B，结构总长 0x60（末 4 字节为对齐填充）。
// 【⚠ 缺陷修正】此前误写为 State[5]@0x00 / Count[2]@0x14 / Buffer@0x1C，
//   导致 State 与计数整体错位 8 字节，且 GetCount 语义（位/字节）不匹配。
typedef struct _SHA1_CONTEXT {
    ULONGLONG Count;                // 0x00: 64 位**位**计数
    ULONG State[5];                 // 0x08: 状态 (A,B,C,D,E)
    UCHAR Buffer[64];               // 0x1C: 数据缓冲区
} SHA1_CONTEXT, *PSHA1_CONTEXT;

// ============================================================
// 回调函数类型定义
// ============================================================
typedef __int64 (*PCOMMAND_HANDLER)(
    __int64 InputBuffer,
    __int64 InputSize,
    _DWORD *pOutputBuffer,
    int OutputSize
    );
