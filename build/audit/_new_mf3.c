// MiniFilterNormalizeName — 规范化对象名并解除只读映射
// 对应原始驱动 0x140019DD8（199 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— IDA `decompile` 返回 None
//   （属 91 个不可反编译函数之一），故走"读反汇编 → 按寄存器/栈槽归属转写"。
//   本函数此前在源码中**完全缺失**（被 _FINAL_GAP.json 误归为"占位"）。
// 【帧定基】`mov rbp,rsp`（标准帧）→ push rbp,rdi,r14 → `sub rsp,0x60`
//   故 rbp = 推送 rbp 后的 rsp；形参 arg_38 位于 [rbp+0x38]。
// 【算法】
//   1) AcquireMiniFilterMutexEx()（0x140071874）取互斥；
//   2) 若第 3 参（bl = r8b）== 1：
//        取 3 个函数指针 —— GtRead(0x432E)、GtRead(0x41CF)、GtRead(0x4334)；
//        任一为 0 则跳过整段；
//        否则在栈上布置 { [rbp-0x30]=0x30, [rbp-0x18]=0x200, 其余槽清零 }，
//        以 (rcx=[rbp+0x38], edx=1, r8=[rbp-0x30], r9=[rbp-0x40]) 调 FnQuery(0x432E)；
//        返回非负则调用 FnUnmap(0x41CF)(查询结果, 0) 卸载，再 FnFree(0x4334)(结果) 释放；
//   3) AcquireMiniFilterMutex()（0x14007182C）释放互斥。
void MiniFilterNormalizeName(__int64 Param1, __int64 Object, UCHAR DoNormalize)
{
    __int64 FnQuery;                 // 0x432E
    __int64 FnUnmap;                 // 0x41CF
    __int64 FnFree;                  // 0x4334
    ULONG64 QueryOut;                // [rbp+0x38]
    UCHAR   Req[0x48];               // [rbp-0x40..]：请求结构

    (void)Param1; (void)Object;

    AcquireMiniFilterMutexEx();                              // 0x140019DF3

    if (DoNormalize == 1)                                    // 0x140019DF8
    {
        FnQuery = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x432E);   // 0x140019E06
        FnUnmap = (__int64)GtRead(GtSyscallHash16847);           // 0x140019E13  ecx=0x41CF
        FnFree  = (__int64)GtRead(GtExFreePoolFunc);             // 0x140019E20  ecx=0x4334

        if (FnQuery && FnUnmap && FnFree)                    // 0x140019E28~E35
        {
            // 清空请求结构（0x140019E37~E49）
            memset(Req, 0, 0x28);                            // [rbp-0x38] / [rbp-0x28] / [rbp-0x20]
            *(ULONG64 *)&Req[0x28] = 0;                      // [rbp-0x10]

            QueryOut = 0;                                    // 0x140019E37 [rbp+0x38]
            *(ULONG *)&Req[0x08] = 0x30;                     // 0x140019E63 [rbp-0x30]
            *(ULONG *)&Req[0x20] = 0x200;                    // 0x140019E6A [rbp-0x18]

            // 0x140019E71：rcx=&QueryOut, edx=1, r8=&Req[0x08], r9=&Req[0x00]
            if ((int)((__int64(__fastcall *)(ULONG64 *, ULONG, void *, void *))FnQuery)(
                    &QueryOut, 1, &Req[0x08], &Req[0x00]) >= 0)      // test eax,eax / js
            {
                ((void(__fastcall *)(ULONG64, __int64))FnUnmap)(QueryOut, 0);  // 0x140019E7D
                ((void(__fastcall *)(ULONG64))FnFree)(QueryOut);               // 0x140019E83
            }
        }
    }

    AcquireMiniFilterMutex();                                // 0x140019E85
}

// MiniFilterFormatFileNameWithPath — 装格式化文件名回调并清零就绪标志
// 对应原始驱动 0x14001A068（54 字节）
// 【逆向来源】同上（人工逐条转写）。源码中此前完全缺失。
// 【算法】取函数指针 GtRead(0x41BA)；非空则调用它并向 GT 0x8F1 写 0；返回是否成功。
UCHAR MiniFilterFormatFileNameWithPath(void)
{
    ULONG64 Fn = (ULONG64)GtRead(GtSyscallHash16826);        // 0x14001A06E  ecx=0x41BA
    UCHAR Result = 0;

    if (Fn)                                                  // 0x14001A07A
    {
        // 0x14001A07F `lea rcx,[rip-0x1E6]` 即本函数地址（作回调注册参数）
        ((void(__fastcall *)(void *))Fn)((void *)MiniFilterFormatFileNameWithPath);
        GtWrite(GtMiniFilterFormatNameExReady, 0);           // 0x14001A08F  ecx=0x8F1
        Result = 1;                                          // 0x14001A094
    }
    return Result;
}

// MiniFilterFormatFileNameWithContext — 上下文版格式化回调安装
// 对应原始驱动 0x14001A0E8（69 字节）
// 【逆向来源】同上（人工逐条转写）。源码中此前完全缺失。
// 【算法】先读就绪标志 GtRead(0x8F1)：**非零则直接返回 0**（不重复安装）；
//   否则取函数指针 GtRead(0x41A5)，非空则调用并向 0x8F1 写 1；返回是否成功。
UCHAR MiniFilterFormatFileNameWithContext(void)
{
    ULONG64 Ready = (ULONG64)GtRead(GtMiniFilterFormatNameExReady);  // 0x14001A0EE ecx=0x8F1
    ULONG64 Fn;
    UCHAR Result = 0;

    if (Ready)                                               // 0x14001A0FA test eax,eax / jne
        return Result;

    Fn = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x41A5);        // 0x14001A0FE ecx=0x41A5
    if (Fn)                                                  // 0x14001A108
    {
        ((void(__fastcall *)(void *))Fn)((void *)MiniFilterFormatFileNameWithContext); // 0x14001A114
        GtWrite(GtMiniFilterFormatNameExReady, 1);           // 0x14001A119/11E
        Result = 1;                                          // 0x14001A123
    }
    return Result;
}