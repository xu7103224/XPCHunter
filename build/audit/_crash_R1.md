# 实机崩溃记录 R1（2026-10-17 01:20）

## 环境
- 驱动：`build/sign/XPCHunterDrv_signed.sys`（676352→677776 字节，SHA1 `FC51E94C72145B0DDD5F70DA631039F41FDB709B`）
- 部署：`sc create RTR1` + `sc start`（Guest 内文件名 `C:\kd_tmp\$GF`，模块名显示为 `kd_tmp_GF`）
- 结果：**驱动已加载并执行**，随后 Guest 蓝屏

## 蓝屏信息（kd_bugcheck / kd_capture_fault）
```
BUGCHECK 0x0000007E (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)
  Arg1 = 0xFFFFFFFFC0000005   (STATUS_ACCESS_VIOLATION)
  Arg2 = 0xfffff8056b4d1e92   (故障指令地址)
  Arg3 = 0xffffc0003d3db1c8   (EXCEPTION_RECORD)
  Arg4 = 0xffffc0003d3daa10   (CONTEXT)
模块基址：kd_tmp_GF = fffff805`6b4c0000
  → 故障 RVA = 0xfffff8056b4d1e92 - 0xfffff8056b4c0000 = 0x11E92
```

## 故障指令（我方镜像 RVA 0x11E92）
```
011e89  e8821c0400          call 0x53b10          ; ReadPESectionEntry(&Ctx, Entry)
011e8e  85c0                test eax, eax
011e90  7511                jne  0x11ea3          ; 非 0 → 跳出循环
011e92  6639342506000000    cmp  word ptr [6], si ; <<< 故障：读绝对地址 6（基址 = NULL + 6）
011e9a  7407                je   0x11ea3
011e9c  ffc3                inc  ebx
011e9e  83fb14              cmp  ebx, 0x14
011ea1  72dd                jb   0x11e80          ; 循环 20 次
```
对应源码（`XPCHunterDrv/src/kernel/Minifilter.c:5043-5051`）：
```c
for (i = 0; i < 0x14; ++i) {
    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
    Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
    Ctx.ReadPtr += Len;
    Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // ← Entry+0x118 == 0 时崩
    if (Type == 0x545) break;
    ...
}
```
（同一代码形状在 `DriverEntry.c:5020-5033` 也有，但那里是 `i < 0x64`；此处为 `i < 0x14`，故属 Minifilter.c 的解析循环。
 `.map` 把 RVA 0x11830 标为 `InitKernelMemoryContext`，应为 LTCG 把该解析循环内联进去了。）

## 结论
`ReadPESectionEntry` **返回 0（成功）但未写入描述符 +0x118（当前表项指针）**，调用方随即解引用 NULL+6 → AV。

我方 `ReadPESectionEntry` 只有 3 条路径返回 0（PEDecoder.c:328 / 356 / 375）：
- 328/375：显式 `SET_Q(SectionInfo, 0x118, DecodeTablePtr + 2880)`
- 356（正常路径）：依赖 `DispatchInstructionDecode` 写入 `DEC_CTX_CUR_TABLE_ENTRY(0x118)`

因此待查方向（下一轮）：
1. 正常路径下 `DispatchInstructionDecode` 是否真的写到了 `SectionInfo + 0x118`（注意：本次已把描述符 +0xF8 由「我方上下文暂存槽」还原为原始的「读取长度」字段，
   且解码器入参由「描述符」纠正为「ContextArray」——`DispatchInstructionDecode` 内部对 `DecodeCtx` 的写入点需逐条复核）。
2. `CTX_D(SectionInfo, DEC_CTX_STATUS_ACC)(+0x100)` 的语义：解码器已不再写 +0x100（改为写 +0xF8），
   故 `== 2` 的特殊返回路径（会写 0x118）现在永不触发，需按原始 `ReadPESectionEntry` 尾部逻辑重新对照。

## 与差分台的关系
描述符流差分（`build/audit/pe_desc_diff.py`，合成输入）两侧均 16 次调用跑完且 `dp`（表选择）一致，
说明表选择链已正确；但**真实内核数据**触发了差分台未覆盖的路径（STATUS_ACC 分支 / 表项指针写入），
下一轮应把该真实输入加入差分用例。

---

# 追加：0x7E 根因确认与修复（2026-10-17 02:20）

## 真正的根因（推翻初判）
故障指令是**绝对地址**寻址 `cmp word ptr [6], si`（编码 `66 39 34 25 06 00 00 00`，
SIB 无基址 = `*(WORD *)(NULL + 6)`），**不是**「描述符 +0x118 未写入」。

成因：原始驱动把「描述符 `SectionEntry` 数组内的字段」在各自函数里声明为**命名栈局部**
（原始反汇编可见：`SectionDataPtr` = 描述符 +0x118、`FieldValue` = +0x50、`EntryFlags` = +0x58、
`SectionSize` = +0x78、`FieldValue2` = +0x88、`SectionSize2` = +0xF0，如 0x14001CF34）。
我方移植时把这些字段**另立为独立局部并初始化为 0 / 从不赋值** → MSVC + LTCG 证明其恒为 0
→ 生成 `NULL + off` 的绝对寻址 → 实机加载即 AV。

## 检测手段（可重复）
用 capstone 扫我方 `.text`，找**无段前缀（非 rip/gs/fs）的绝对地址内存操作数**——
这正是编译器把「可证明为 0 的基址」折叠后的特征：

```
python - <<'PY'   # 见本轮会话记录
# 修复前：5 处；修复后：1 处
PY
```
修复前 5 处：0x11E92 / 0x12CCC / 0x12D43 / 0x13042（均 `+6`）、0x29B30（`+8`）
修复后 1 处：0x29B70 `cmp qword ptr [8], rax`（属 `DispatchCpuMsrBaseLookup` 内联区，
`FindCpuMsrBaseLegacy/Win10` 的 `SectionTypeInfo` 家族字段，待按原始核对后修正）

## 已做的修正
1. `EnumFileSystemCallbackEntries`（原始 0x14003EAA8）整函数按反汇编 1:1 重写
   （原移植版 6 个字段局部未赋值 + `EntrySize` 误取 +0x30 应为 +0xF0 + 构建号判断方向反了）
2. 全库 `+6` 类型读取改为经描述符 `+0x118` 取值：覆盖 81 个函数 / 162 处
   （两次批量脚本：第一次 27 处按"从未赋值"筛选；第二次按作用域修正基址名 95 处）
3. `ContextMgmt.c` 三个 MSR 函数：类型指针偏移 `+0x48` → `+0x118`（7 处）
4. `MiniFilterPostWrite`：字段改为描述符读取

## 待办（下一步）
- 0x29B70 的 `+8` 折叠（`FindCpuMsrBaseLegacy/Win10`）
- 上述字段的**语义偏移**仍需逐函数按原始核对（部分函数只改了 +6，其他字段偏移可能仍错）
- 实机加载验证：本轮部署时 Guest SSH 不可达（`guest exec` 全部 exit=1），未能完成加载测试

---

# 追加：实机验证 R4（2026-10-17 03:30）——驱动首次成功加载，卡在 DriverEntry

## 结果
`sc start RTR4` **不再蓝屏**（NULL 折叠已全部消除），但 **DriverEntry 不返回**（SCM 侧超时）。
调试器现场证据：
```
lm m rtR4*            → rtR4 已加载（fffff804`2ae50000 ~ fffff804`2af26000）
!drvobj \Driver\RTR4  → Dispatch 例程仍为 nt!IopInvalidDeviceRequest
                        DriverUnload: 00000000   → 说明 DriverEntry 未执行到
                        `DriverObject->MajorFunction[...] = ...`（我方 DriverEntry 第 154-156 行）
Host CPU 15.6%        → 是**等待**而非自旋
```
GT 进度（g_GlobalTable 运行时 0xfffff8042aef0060，逐槽读取）：
```
GT[0x914] build        = 0x47BA (18362)   ✓ 早期步骤完成
GT[0x61]  EPROCESS     = ffffc088`9de8e380 ✓ InitGtCore 完成
GT[0x20]  KernelBase   = ffffd287`5ca00000 ✓ 内核模块扫描完成
GT[0x21]  KernelSize   = 0xAB2000          ✓
GT[0x415E] syscall 槽   = 0xB1A0E87F        ← 半写/异常
GT[0x177] NtImageSize  = 0                  ✗ 未写
GT[0x7BF] callback     = 0                  ✗ 未写
GT[0x7B2..0x7D7] 全部 = 0                  ✗ InitKernelMemoryContext 扫描器一个都没跑
```
→ 卡点在 **DriverEntry 第 128-133 行之间**（InitSyscallNumberTable / BuildHookTable 一带），
   该路径需要**读取 ntoskrnl 文件**。

## 阻塞机理（已定位到代码）
文件读取走 GT 解析出来的辅助函数（`TailHelpers.c:316+`，设备 `\Device\Ip` 的 FSCTL 读取）：
```c
Irp = IrpFsControlFunc(0x128030, InputBuffer, SectionHandle, 0x10, 0, 0, &EventObj, &IoStatusBlock);
IoctlResult = AllocateIrpStackAndCallDriver(0, SectionHandle, Irp);
if (IoctlResult == 0x103 /*STATUS_PENDING*/)
    KeWaitForSingleObjectFunc(&EventObj, 0, 0, 0, 0);      // ← 永久等待
```
`Protocol.c` 的 IRP 读路径同样是 `if (CallResult == STATUS_PENDING) KeWaitForSingleObject(&Event, ...)`
（事件为 SynchronizationEvent 且已设入 `Irp->UserEvent`，写法正确）。
**若下层驱动永不完成该 IRP，等待即永久挂起** —— 与「驱动已加载、DriverEntry 不返回、CPU 空闲」完全吻合。

## 下一轮定位方向（按优先级）
1. 复核 `AllocateIrpStackAndCallDriver` 与 IRP 派发前的监控/挂钩三步：
   `GetIrpMonitorContext` / `AcquireVolumeChangeLock` / `SwapDiskIrpFunctionPointer`
   （原始用 pCallDriver 挂钩再派发；任一步错都会让 IRP 不被派发 → 永久 PENDING）
2. 复核 `TailHelpers.c` 的 `IrpFsControlFunc`（GT 解析出的函数指针）参数与事件传递
3. `ModuleMgmt.c:1463`（`ScanFileForPeSectionInfo`）的 `InitPESectionReadContext` 调用
   仍有 8 实参但无上下文（`ReadContext` 从未初始化），需按原始重写后再修
