# 目标驱动是否存在隐藏 Shellcode 的核查（2026-10-29）

> 针对「1.0.0.5 有 74 个空槽位，原版 exe 仍会发送这些命令，是否存在隐藏 shellcode
> 在运行时补齐这些能力」的疑问，做系统性取证。
>
> **结论：不存在。** 空槽位就是真空，没有替代实现路径。

## 0. 结论

| 检查项 | 结果 |
|---|---|
| 内嵌加密/压缩载荷 | **无**（无高熵块） |
| 自修改代码 / 运行时解密循环 | **无** |
| 动态解析并跳转到外部代码 | **仅 2 处，均为良性** |
| 内核 shellcode 特征指令（swapgs/sysret/iretq） | **0 处** |
| 异常段权限（W+X 段） | **无** |
| 第二张命令表 / 备用分发路径 | **无** |
| PE 尾部未覆盖数据 | 仅标准数字签名（27,416 字节 PKCS#7） |

## 1. 段结构核查

两版都是干净的 7 段结构，权限符合内核驱动常规：

### 1.0.0.5（exe 实际释放）

| 段 | VA | VSZ | RAW | 权限 |
|---|---|---|---|---|
| .text | 0x1000 | 0x7B52A | 0x400 | CODE \| EXEC \| READ |
| .rdata | 0x7D000 | 0x627C | 0x7BA00 | IDATA \| READ |
| .data | 0x84000 | 0x300A0 | 0x81E00 | IDATA \| READ \| WRITE |
| .pdata | 0xB5000 | 0x3828 | 0x92000 | IDATA \| READ |
| INIT | 0xB9000 | 0xB4A | 0x95A00 | CODE \| EXEC \| READ \| DISCARD |
| .rsrc | 0xBA000 | 0x320 | 0x96600 | IDATA \| READ \| DISCARD |
| .reloc | 0xBB000 | 0x17C | 0x96A00 | IDATA \| READ \| DISCARD |

**没有任何 W+X（可写且可执行）段**，这是 shellcode 驻留的必要条件之一。
`.data` 是 RW 不可执行，`.text` 是 RX 不可写，权限边界正常。

1.0.6.0 的段结构与权限完全同构，只是 `.text` 更大（0x8BB7A）。

### 1.1 PE 尾部

1.0.0.5 文件长度 644,888，段表最大 RAW 末尾 617,472，尾部 27,416 字节：

```
WIN_CERTIFICATE  dwLength=27416  wRevision=0x0200  wCertificateType=2
```

`wCertificateType=2` 即 `WIN_CERT_TYPE_PKCS_SIGNED_DATA`，长度恰好等于尾部剩余，
**没有任何夹带**。1.0.6.0 的文件末尾与段末尾完全对齐（尾部剩余 0）。

## 2. 熵分析（排除加密载荷）

| 区域 | 熵 | 判断 |
|---|---|---|
| 1.0.0.5 `.data` 前 64KB | **2.87** bits/byte | 正常数据 |
| 1.0.0.5 `.text` 前 64KB | **6.51** bits/byte | 正常机器码 |
| 按 4KB 分块，熵 > 7.2 的块 | **0 个** | 无加密/压缩载荷 |

加密或压缩的 PE 载荷熵通常在 7.9 以上。这里最高的块也低于 7.2，
说明**驱动里没有待解密的代码或数据**。

## 3. Shellcode 特征指令扫描

在 1.0.0.5 的 `.text`（0x7B600 字节）中扫描：

| 指令 | 字节模式 | 出现次数 |
|---|---|---|
| `swapgs` | `0F 01 F8` | **0** |
| `sysret` | `48 0F 07` | **0** |
| `iretq` | `48 CF` | **0** |

这三条是内核态 shellcode 的典型特征（用于从内核态构造返回用户态的路径）。
全部为 0。

间接调用统计：

| 模式 | 次数 |
|---|---|
| call rax | 43 |
| call rbx | 34 |
| call rbp | 84 |
| call rsi | 154 |
| call rdi | 125 |
| call rcx / rdx / r8 / r9 | 9 |
| jmp rax / jmp rcx | 2 |
| **合计** | **451** |

451 个间接调用对一个 500KB 的 ARK 驱动是正常量级——
283 槽命令表、各类回调表、全局函数指针（GT 表）都会产生这种调用。

## 4. 动态代码解析核查

唯一的动态解析原语是 `MmGetSystemRoutineAddress`，共 **2 个调用点**：

### 4.1 `sub_14006BF84` —— 读取真实系统版本号

```c
if (NtBuildNumber >= 0x47BA) {          // >= 18362 (Win10 1903)
    wcscpy(SourceString, L"RtlGetVersion");
    RtlInitUnicodeString(&DestinationString, SourceString);
    SystemRoutineAddress = MmGetSystemRoutineAddress(&DestinationString);
    if (SystemRoutineAddress) {
        v4[0] = 276;                     // sizeof(RTL_OSVERSIONINFOW)
        if (SystemRoutineAddress(v4) >= 0)
            return v4[3];                // dwBuildNumber
    }
}
return NtBuildNumber;
```

用途：老系统的 `NtBuildNumber` 不可靠，用 `RtlGetVersion` 取准确版本。
**这是微软文档推荐的做法，良性。**

### 4.2 `sub_140051D3C` —— 枚举设备栈

```c
SystemRoutineAddress = Gt(12575);        // 先查全局表缓存
v6 = Gt(12227);
if (!SystemRoutineAddress) {
    wcscpy(SourceString, L"IoGetDeviceAttachmentBaseRef");
    ...MmGetSystemRoutineAddress...
}
if (!v6) v6 = ObfDereferenceObject;

// 用 IoGetDeviceAttachmentBaseRef 拿到设备栈底
v7 = SystemRoutineAddress(a1);
v8 = *(_QWORD **)(v7 + 8);               // 上层设备对象
v6(v7);                                  // 解引用
v9 = (_QWORD *)v8[6];                    // AttachedDevice 链
v10 = (_QWORD *)*v9;
// ... 遍历设备链，把每个对象所在内核模块的基址/大小回填到 a2[]
```

用途：把设备对象地址映射到它所属的内核模块（用于判断驱动是否被隐藏/篡改）。
**这是 ARK 工具枚举驱动对象的常规手段，良性。**

两处都是「按名字取一个公开 API 的地址」，**没有任何一处是从数据构造代码再跳转**。

## 5. 缺少注入与执行原语

1.0.0.5 的导入表只有 91 个函数，来自三个模块：

| 模块 | 导入数 | 内容 |
|---|---|---|
| FLTMGR.SYS | 8 | `FltRegisterFilter` / `FltStartFiltering` / `FltCreateFile` 等文件过滤 |
| ntoskrnl.exe | 80 | 进程/内存/对象/注册表/文件操作 |
| HAL.dll | 3 | `HalGetAdapter` / `HalGetBusDataByOffset` / `HalAllocateCrashDumpRegisters` |

**不存在**以下任一注入原语：

| 分类 | 缺失的原语 |
|---|---|
| 内存权限篡改 | `MmProtectMdlSystemAddress`、`ZwProtectVirtualMemory` |
| 代码注入 | `KeInsertQueueApc`、`PsCreateSystemThread`、`RtlCreateUserThread` |
| 回调注册 | `PsSetCreateProcessNotifyRoutine` 等（未作为 import） |
| 跨模块调用 | 无 `win32k.sys`、无 `ntdll.dll` 依赖 |

`ZwMapViewOfSection` 存在，但在 ARK 驱动里的标准用途是读取被占用的文件
（绕过句柄检查），不是把 PE 映射进来执行。

### 5.1 两个看似可疑、实为良性的导入

**`KeBugCheckEx`** —— 只有 2 个调用点：

- `__report_gsfailure`（MSVC `/GS` 栈保护失败桩）
- `sub_140069BB8`（异常展开辅助，参数 `0x35` = `STATUS_STACK_BUFFER_OVERRUN`）

后者操作的是 `EXCEPTION_REGISTRATION_RECORD`（`a3+67` 的 TryLevel、
`a3+184` 的异常帧链），是编译器生成的 SEH 代码。**没有反调试逻辑。**

**`MmMapIoSpace`** —— 只有 1 处引用，位于 `DriverEntry`：

```asm
add rcx, cs:IoAttachDeviceToDeviceStack
add rcx, cs:IoAttachDeviceByPointer
add rcx, cs:IoAttachDevice
add rcx, cs:MmUnmapIoSpace
add rcx, cs:MmMapIoSpace
add rcx, cs:ZwQueryKey
... （共 17 个 IAT 项依次累加）
call sub_140026E2C
```

这是一串 `add rcx, cs:<IAT项>`，把 17 个导入函数地址累加成一个校验和，
再调用校验函数——**这是驱动自身的反篡改自检**，不是执行映射。

## 6. 只有一张命令表

在整个文件中搜索命令表容量常量：

| 常量 | 出现位置 | 用途 |
|---|---|---|
| `0x915` (2325) | 4 处 | 命令表分配（0x7222B 等） |
| `0x8D8` (2264) | 3 处 | 0x723F8 = 命令表 memset；另两处是别的缓冲尺寸 |

命令表的分配与初始化只有一处（`sub_140072FE0`）。
**不存在第二张表或备用分发路径。**

## 7. 空槽位是真空的证据链

综合以上，那 74 个空槽位（含 1.0.0.5 独有的 51 个）确实是真空槽：

1. 表项被 `memset` 显式清零，没有指向任何 fallback 桩函数
2. 分发逻辑是 `if (HandlerFunc) HandlerFunc(...)`，NULL 直接跳过
3. 没有第二张表可以兜底
4. 没有运行时修补表项（无自修改代码、无高熵载荷）
5. 没有 APC/线程/回调注入原语去旁路

**所以原版 exe 在那些功能点上，确实是点了没反应。**

## 8. 对我们工作的意义

### 8.1 排除了一个风险

之前担心「我们补齐 1.0.6.0 的 49 条命令可能和原版的隐藏实现冲突」。
现在确认没有隐藏实现，**我们补的就是原版缺的**，不存在语义冲突。

### 8.2 决定性证据：两版导入表完全相同

1.0.0.5 与 1.0.6.0 的导入表**各 91 个函数，差异为零**：

```
1.0.6.0 多出的导入: （无）
1.0.0.5 多出的导入: （无）
```

这是整份核查里最强的一条证据。1.0.6.0 多实现了 51 个功能
（SSDT 读写、Hook 安装、内核内存操作、进程/线程上下文），
却**没有多引入任何一个 API**。说明：

- 那些功能是用同样这 91 个 API 重新组合实现的
- 1.0.0.5 里不存在「未在导入表中声明但实际调用」的隐藏路径
- 那 51 个空槽位确实没有实现，不是换了另一种方式实现

如果 1.0.0.5 真的用 shellcode 或动态解析补齐了这些能力，它必然需要
额外的 API（比如 `ZwProtectVirtualMemory`、`KeInsertQueueApc`），
而这些在两版的导入表里都找不到。

### 8.3 坚定了技术路线

我们按 1.0.6.0 逐槽复刻（248 实现 / 35 NULL），是 1.0.0.5（197 / 86）
的严格超集，且**在原版空槽的 49 条上领先**。这些恰好是 SSDT、Hook、
内核内存、进程上下文这些 ARK 核心能力。

按 A/B/C 三层规划工作时：

- **A 层 186 条**：与「原版真实能力」对齐，必做
- **B 层 49 条**：原版做不到、我们能做，是差异化优势
- **C 层 25 条**：两版都空，不必做

### 8.4 一个副产品

1.0.0.5 里那两个 `MmGetSystemRoutineAddress` 用法（`RtlGetVersion` 取准确版本、
`IoGetDeviceAttachmentBaseRef` 映射设备到模块）值得抄，比硬编码版本号健壮。
我方驱动里对应的逻辑可以对照检查。

## 9. 取证方法（可复现）

```python
# 段权限
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe+6)[0]      # 注意 +6，不是 +4
opt = pe + 0x18 + struct.unpack_from('<H', d, pe+0x14)[0]
for i in range(nsec):
    s = opt + i*40
    ch = struct.unpack_from('<I', d, s+36)[0]
    # 0x20000000=EXEC 0x40000000=READ 0x80000000=WRITE

# 熵
import collections, math
def ent(b):
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())

# shellcode 特征
text.count(b'\x0f\x01\xf8')   # swapgs
text.count(b'\x48\x0f\x07')   # sysret
text.count(b'\x48\xcf')       # iretq
```

> 注意：PE 头里 `NumberOfSections` 在 `pe+6`，`Machine` 在 `pe+4`，
> `Characteristics` 在 `pe+0x16`。本文件早期分析曾把 `+4` 当 `+6` 读，
> 导致段数被读成 34404 的假象。已在本文修正。