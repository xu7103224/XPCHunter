// ============================================================
// 基础类型、宏、Minifilter 前向声明
// ============================================================

#pragma once

//
// XPCHunterDrv.h — PCHunter 内核驱动主头文件
// 1:1 复刻 View++_Driver64.sys (Linxer)
//

// 内核模式定义（必须在 WDK 头文件之前）
// 注意：MSVC /kernel 开关会保留 _KERNEL_MODE 宏，因此不能在命令行 /D 定义
#ifndef _KERNEL_MODE
#define _KERNEL_MODE
#endif

// 注意：WDK 内核模式下 windef.h 不定义 WORD/DWORD/LONG64 等类型，
// 但 ntimage.h 使用这些类型，因此必须在 #include <ntimage.h> 之前定义
#ifndef WORD
typedef unsigned short WORD;
#endif
#ifndef PWORD
typedef WORD *PWORD;
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif
#ifndef LONG64
typedef __int64 LONG64;
#endif
#ifndef ULONG64
typedef unsigned __int64 ULONG64;
#endif

// IDA Pro 风格类型别名（用于函数声明兼容）
typedef unsigned char _BYTE;
typedef unsigned short _WORD;
typedef unsigned long _DWORD;
typedef unsigned __int64 _QWORD;

#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

// 注意：intrin.h 在 WDK 内核模式下可能引起兼容性问题
// 需要 __readmsr/__writemsr/__cpuid 的源文件自行 #pragma intrinsic 声明

// bool 类型定义（WDK 已定义 BOOLEAN，仅在纯 C 模式下需要）
#ifndef __cplusplus
#ifndef bool
#define bool BOOLEAN
#endif
#endif

// 额外类型别名
// 128 位联合体，支持位域访问（用于替代 IDA 反编译中的 __int128）
typedef union _OWORD {
    unsigned __int64 qword[2];
    unsigned long dword[4];
    unsigned short word[8];
    unsigned char byte[16];
} _OWORD;

// Lvalue 兼容的字节/字访问宏（MSVC C 模式下 LOBYTE/HIWORD 等不是 lvalue）
// 注意：MSVC C 模式下不允许在带括号的表达式上做赋值（C2106），
// 因此宏定义中不能包含外层括号，以保证展开后 *(UCHAR *)&x = val 的 lvalue 语义。
// 使用 (UCHAR *) 中间转换（而非 (void *)）以保持 MSVC /Ze 扩展兼容。
#define LOBYTE_LV(x)  *(UCHAR  *)(UCHAR *)&(x)
#define HIBYTE_LV(x)  *(UCHAR  *)((UCHAR *)&(x) + 1)
#define BYTE1_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 1)
#define BYTE2_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 2)
#define BYTE3_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 3)
#define LOWORD_LV(x)  *(WORD  *)(WORD *)&(x)
#define HIWORD_LV(x)  *(WORD  *)((UCHAR *)&(x) + 2)

#define LODWORD_LV(x)  *(ULONG *)(ULONG *)&(x)

// 非 lvalue 字节/字宏（兼容原始反编译代码中的用法）
#define HIBYTE(x)     ((UCHAR)(((ULONG_PTR)(x) >> 8) & 0xFF))
#define BYTE1(x)      ((UCHAR)(((ULONG_PTR)(x) >> 8) & 0xFF))
#define BYTE2(x)      ((UCHAR)(((ULONG_PTR)(x) >> 16) & 0xFF))
#define LODWORD(x)    ((ULONG)((ULONG_PTR)(x) & 0xFFFFFFFF))
#define HIDWORD(x)    ((ULONG)(((ULONG_PTR)(x) >> 32) & 0xFFFFFFFF))
#define SBYTE1(x)     ((char)(((ULONG_PTR)(x) >> 8) & 0xFF))

// Minifilter 类型前向声明（Minifilter.c 包含完整的 fltKernel.h 声明）
// 当 fltKernel.h 已包含时，使用其定义；否则使用前向声明
#ifndef __FLTKERNEL__
typedef struct _FLT_FILTER *PFLT_FILTER;
typedef struct _FLT_INSTANCE *PFLT_INSTANCE;
typedef struct _FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;
typedef struct _FLT_CALLBACK_DATA *PFLT_CALLBACK_DATA;
typedef int FLT_INSTANCE_SETUP_FLAGS;
typedef int FLT_INSTANCE_QUERY_FLAGS;
typedef int FLT_TEARDOWN_FLAGS;
typedef int FLT_FILTER_UNLOAD_FLAGS;
typedef int FLT_POST_OPERATION_FLAGS;
typedef int FLT_CONTEXT_TYPE;
typedef int FLT_CONTEXT_CLEANUP_FLAGS;
#else
// fltKernel.h 已包含，补充其未定义的类型
typedef int FLT_INSTANCE_QUERY_FLAGS;
typedef int FLT_TEARDOWN_FLAGS;
typedef int FLT_CONTEXT_CLEANUP_FLAGS;
#endif
