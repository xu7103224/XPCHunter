// ============================================================
// 编译时配置、IRP/CMD 协议常量
// ============================================================

#include "xpc_basic.h"

// ============================================================
// 编译时配置
// ============================================================
#define XPCHUNTER_DEVICE_NAME      L"\\Device\\View++ByLinxer"
#define XPCHUNTER_SYMLINK_NAME     L"\\DosDevices\\View++ByLinxer"
#define XPCHUNTER_REGISTRY_PATH    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\XPCHunterDrv"

#define DRIVER_TAG                 'XPCH'
#define POOL_TAG                   'xpcH'


// ============================================================
// IRP 通信协议常量
// ============================================================
#define IRP_TYPE_MAGIC             0x20202020  // IRP Type 标记
#define IRP_INPUT_BUFFER_SIZE      48          // 输入缓冲区大小 (48 字节)
#define IOCTL_METHOD               METHOD_NEITHER  // 通信方法
#define IOCTL_OPTIONS_VALUE        48          // Create.Options 验证值

// ============================================================
// 命令操作码范围
// ============================================================
#define CMD_OPCODE_MIN             32
#define CMD_OPCODE_MAX             0x11A  // 282
#define CMD_OPCODE_COUNT           (CMD_OPCODE_MAX + 1)
