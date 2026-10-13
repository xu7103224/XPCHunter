// MiniFilterCommPortReply — 通信端口回复（0x140019344）
// 对应原始驱动 0x140019344（105 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：
//     `if (!GtRead(GtCommPortCallbackReady)) return STATUS_DEVICE_NOT_READY; return STATUS_SUCCESS;`
//   注释称"需要 IRP 或命名管道上下文"，与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始不读任何 GT 而我方读 0x8F2；反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x140019344：
//   rdi = r8（用户缓冲）；bl = 0（结果）
//   rcx = *MmUserProbeAddress
//   ① r8 >= rcx        → 返回 0     ; 越界
//   ② r8 == 0          → 返回 0     ; 空指针
//   ③ r8+4 >= rcx      → 返回 0     ; 4 字节写入会越界
//   ④ r9d != 4         → 返回 0     ; 输入长度必须为 4
//   ProbeForWrite(r8, 4, 4)          ; 校验可写
//   ⑤ *rdi = (*(volatile ULONG64*)0x1400A84D9 != 0)   ; 注意：直接读绝对地址
//   返回 1
// 【说明】第 ⑤ 步读的 **不是** GT 表，而是绝对地址 0x1400A84D9
//   （反汇编 `cmp qword ptr [rip+0x8f151], rbx`，rbx=0），
//   这是原驱动自己的一个全局标志，不经过 GtRead —— 故运行时 GT 序列为空。
NTSTATUS MiniFilterCommPortReply(void **Address, int Length, _DWORD *Output, unsigned int OutputSize)
{
    char   Result = 0;
    ULONG64 ProbeLimit;

    Output = (_DWORD *)Address;             // rdi = r8（原始把 r8 视作输出缓冲）

    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;      // rcx = *MmUserProbeAddress
    if ((unsigned __int64)Address >= ProbeLimit       // 0x140019361
        || Address == 0                               // 0x140019366
        || (unsigned __int64)Address + 4 >= ProbeLimit // 0x14001936F
        || OutputSize != 4)                           // 0x140019377
        return 0;

    ProbeForWrite(Address, 4, 4);                     // 0x140019382

    *Output = (*(volatile ULONG64 *)0x1400A84D9 != 0) ? 1 : 0;   // 0x140019388/38F/392
    Result = 1;                                       // 0x140019394
    return Result;
}

// MiniFilterNotifyRoutineEx2 — Minifilter 通知例程（扩展 2，0x14001A3E4）
// 对应原始驱动 0x14001A3E4（110 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：只读 GT 0x8F2 后 `xor eax,eax`。
//   发现方式同上（逐函数差分：原始读 0x8F3，我方读 0x8F2 且不返回值）。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001A3E4：与 0x140019344 同构，仅末段不同——
//   校验（越界/空/加4越界/长度!=4）→ ProbeForWrite(r8,4,4)
//   → 读 GT **0x8F3**（`mov ecx,0x8F3; call GtRead`）
//   → *rdi = (GT 值 != 0)；返回 1。
// 【与 MiniFilterCommPortReply 的差异】本函数读的是 GT 表索引 0x8F3
//   （经 GtRead），而前者读的是绝对地址 0x1400A84D9。两者结果都写入 *r8。
NTSTATUS MiniFilterNotifyRoutineEx2(void **Address, int Length, _DWORD *Output, unsigned int OutputSize)
{
    char   Result = 0;
    ULONG64 ProbeLimit;

    Output = (_DWORD *)Address;             // rdi = r8

    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;
    if ((unsigned __int64)Address >= ProbeLimit       // 0x14001A401
        || Address == 0                               // 0x14001A406
        || (unsigned __int64)Address + 4 >= ProbeLimit // 0x14001A40F
        || OutputSize != 4)                           // 0x14001A417
        return 0;

    ProbeForWrite(Address, 4, 4);                     // 0x14001A422

    *Output = ((ULONG)GtRead(GtMiniFilterNotifyRoutineReady) != 0) ? 1 : 0;  // 0x14001A428/434/437（0x8F3）
    Result = 1;                                       // 0x14001A439
    return Result;
}
