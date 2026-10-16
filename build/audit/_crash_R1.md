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
