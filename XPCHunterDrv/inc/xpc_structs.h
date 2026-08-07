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
// MD5 上下文
// ============================================================
typedef struct _MD5_CONTEXT {
    ULONG State[4];                 // 0x00: 状态 (A,B,C,D)
    ULONG Count[2];                 // 0x10: 位计数
    UCHAR Buffer[64];               // 0x18: 数据缓冲区
} MD5_CONTEXT, *PMD5_CONTEXT;

// ============================================================
// SHA1 上下文
// ============================================================
typedef struct _SHA1_CONTEXT {
    ULONG State[5];                 // 0x00: 状态 (A,B,C,D,E)
    ULONG Count[2];                 // 0x14: 位计数
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
