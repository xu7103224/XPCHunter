// RegisterFilterUnloadCallback — 注册过滤卸载回调（0x14001A39C）
// 对应原始驱动 0x14001A39C（69 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：
//     `if (!GtRead(GtCommPortCallbackReady)) return STATUS_SUCCESS; return ...;`
//   —— 读错索引（0x8F2 而非 0x8F3），且两个分支返回同一常量，
//   等于什么都不做。注释"将文件操作通知发送到 GT 0x3400 缓冲区"与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始读 GT 0x8F3 而我方读 0x8F2；反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001A39C：
//   0x14001A3A2  ecx = 0x8F3 ; GtRead        ; 已注册标志
//   0x14001A3AE  test eax,eax ; jne 返回 0    ; 已注册则直接返回 0（不做重复注册）
//   0x14001A3B2  ecx = 0x41AB ; GtRead        ; 取注册函数指针
//   0x14001A3BC  test rax,rax ; je 返回 0     ; 未解析到则返回 0
//   0x14001A3C1  lea rcx,[rip-0x1B8]          ; -> 0x14001A210 (MiniFilterQueryIdleRoutine)
//   0x14001A3C8  call rax                     ; 注册该回调
//   0x14001A3CA  edx = 1 ; ecx = 0x8F3 ; GtWrite  ; 置已注册标志 = 1
//   0x14001A3D7  bl = 1                       ; 返回 1
// 【说明】本函数与 MiniFilterActiveRoutine（0x14001A240）是配对的一对：
//   本函数**注册**回调并置标志位 1；后者**注销**回调并清标志位 0。
//   两者读的是同一个指针槽（0x41AB）与同一个标志槽（0x8F3）。
//   0x41AB 在枚举里被误标为 GtSyscallHash16811，语义实为
//   "回调注册函数指针"，故此处以裸索引 + 注释书写。
NTSTATUS RegisterFilterUnloadCallback(void)
{
    char Result = 0;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *));

    if ((ULONG)GtRead(GtMiniFilterNotifyRoutineReady) == 0)       // 0x14001A3A2/3AE（0x8F3）
    {
        RegisterCallbackFunc =
            (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *)))
            GtRead((GLOBAL_TABLE_INDEX)0x41AB);                   // 0x14001A3B2
        if (RegisterCallbackFunc)                                 // 0x14001A3BC
        {
            RegisterCallbackFunc(
                (__int64 *(__fastcall *)(__int64, __int64, _DWORD *))
                MiniFilterQueryIdleRoutine);                      // 0x14001A3C8（lea rcx,[rip-0x1B8]）
            GtWrite(GtMiniFilterNotifyRoutineReady, 1);            // 0x14001A3CD/3D2（0x8F3 = 1）
            Result = 1;                                           // 0x14001A3D7
        }
    }
    return Result;
}
