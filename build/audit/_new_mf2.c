// MiniFilterInstanceSetup — FLT 实例安装回调：校验用户缓冲并按构建号分发
// 对应原始驱动 0x1400129CC（179 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— 原实现是 `return STATUS_SUCCESS;` 空壳。
// 【帧定基】mov rax,rsp → 存 rbx/rsi/rdi/r14 到 [rax+8..0x20] → push r15 → sub rsp,0x30
//   形参：rcx=FltFilter, rdx=Instance, r8=上下文缓冲, r9d=缓冲大小
BOOL MiniFilterInstanceSetup(void *FltFilter, void *Instance, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;
    ULONG Adj;
    BOOL  Ok;

    (void)FltFilter; (void)Instance;

    if (!Buffer)                                             // 0x1400129ED test r8,r8
        return Result;
    if (BufferSize <= 0x70)                                  // 0x1400129F2 cmp esi,70h / jbe
        return Result;
    if ((ULONG64)Buffer >= *(ULONG64 *)MmUserProbeAddress)   // 0x1400129F7/2A01
        return Result;
    if ((ULONG64)Buffer + BufferSize >= *(ULONG64 *)MmUserProbeAddress)  // 0x140012A06/0A0A
        return Result;

    ProbeForWrite(Buffer, BufferSize, 1);                    // 0x140012A1B（ProbeForWrite）

    memset(Buffer, 0, BufferSize);                           // 0x140012A29  → 0x1400013F0
    *(ULONG *)Buffer = 0;                                    // 0x140012A2E

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1771)        // 0x140012A30/3A
        return Result;

    // 0x140012A46：调 OpenMiniFilterVolumeFile(Buffer, BufferSize)
    Adj = (ULONG)OpenMiniFilterVolumeFile((__int64)Buffer, (__int64)BufferSize);
    (void)Adj;

    Ok = (*(ULONG *)Buffer != 0);                            // 0x140012A4E cmp dword ptr [rdi],ebx
    Result = Ok ? 1 : 0;                                     // cmovne
    return Result;
}

// MiniFilterPreFastIo — 快速 IO 预处理：校验用户缓冲并按结构尺寸分发枚举
// 对应原始驱动 0x14001B2B4（176 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— 原实现是 `return STATUS_SUCCESS;` 空壳。
// 【帧定基】存 rbx/rsi 到 [rsp+8..0x10] → push rdi → sub rsp,0x30
//   形参：rcx=Filter, rdx=CallbackData, r8=输出缓冲, r9d=缓冲大小
// 【要点】以魔数除法 (0xA41A41A41A41A41B) 算 (BufferSize-0x278)/0x278 + 1 作为条目数
BOOL MiniFilterPreFastIo(void *Filter, void *CallbackData, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;
    ULONG64 Entries;
    ULONG64 T;
    ULONG64 Q;
    ULONG64 R;

    (void)Filter; (void)CallbackData;

    if (!Buffer)                                             // 0x14001B2C8 test r8,r8
        return Result;
    if (BufferSize < 0x278)                                  // 0x14001B2D1 cmp r9d,278h / jb
        return Result;
    if ((ULONG64)Buffer >= *(ULONG64 *)MmUserProbeAddress)   // 0x14001B2DA/2E4
        return Result;
    if ((ULONG64)Buffer + BufferSize >= *(ULONG64 *)MmUserProbeAddress)  // 0x14001B2EC/2F0
        return Result;

    ProbeForWrite(Buffer, BufferSize, 8);                    // 0x14001B2FE（ProbeForWrite）

    memset(Buffer, 0, BufferSize);                           // 0x14001B30C → 0x1400013F0
    *(ULONG *)Buffer = 0;                                    // 0x14001B311

    // 0x14001B313：条目数 = (BufferSize - 0x278) / 0x278 + 1（编译器用魔数实现无符号除法）
    T = (ULONG64)BufferSize - 0x278;
    Q = (ULONG64)(((unsigned __int128)T * 0xA41A41A41A41A41BULL) >> 64);  // mul rcx 的高半
    R = T - Q;
    R >>= 1;
    Entries = (Q + R) >> 9;
    Entries += 1;

    // 0x14001B33F：调 EnumerateAleEndpointLayers(&(Buffer+1), Buffer+2*4, Entries)
    //   —— 原始 rcx=rdi（缓冲首 DWORD 作输出计数）、rdx=rdi+8、r8=条目数
    if (EnumerateAleEndpointLayers((_DWORD *)Buffer, (__int64)Buffer + 8, (int)Entries))  // 0x14001B23C
        Result = 1;                                          // 0x14001B344
    return Result;
}