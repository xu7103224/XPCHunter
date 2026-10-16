// EnableDeviceObjectProtection — 启用设备对象保护（0x140010460）
// 对应原始驱动 0x140010460（606 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（5 行：读 GtDriverObject 置 DO_DEVICE_INITIALIZING 位），
//   与原始函数体无关。发现方式：差分报原始读 13 个 GT 槽（0x422F/0x41C6/0x4223/0x41DB/
//   0x194/0x325/0x329/0x326/0x327/0x32A/0x195/0x2A3/0x32B）而我方只读 1 个。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【语义】对**进程对象**（非设备对象）设置保护：
//   1) 取四个函数指针：0x422F→rsi、0x41C6→rdi、0x4223→r15、0x41DB→rbp，
//      四者皆须非 0；
//   2) 以 (第1参, 0x80000000, *rsi, &局部[+0x80]) 调用 rdi（打开对象），返回值须 >= 0；
//   3) 调 0x14002DCD0(句柄, &局部[+0x88], 0) 取对象信息，须返回 1；
//   4) 分支一：若 GT 0x194 非 0 且 `*(局部[0x88]+8) == GT0x194`：
//        rsi = 局部[0x80][+0x18]（进程体）、rdi = 局部[0x80][+0x20]；两者非 0；
//        `*(GT0x325 + rsi) = 1`；
//        再 `rsi = *(GT0x329 + rsi)`；若非 0 且 rbp(rsi) 返回真：
//          `*(GT0x326 + rsi) = 1`；第 2 参为 1 时 `*(WORD*)(GT0x327 + rsi) = 0`；
//          置返回 0；
//        再对 rdi 调 rbp，须为真；`rdi = *(GT0x32A + rdi)`；若非 0 且 rbp(rdi) 为真：
//          `*(GT0x32B + rdi) = 1`（经 0x328 分支汇合）；
//   5) 分支二：若 GT 0x195 非 0 且 `*(局部[0x88]+8) == GT0x195`：
//        rdi = 局部[0x80][+0x18]；若非 0，按其首 WORD 与 0x502/0xD02 比较：
//          0x502 分支：`(WORD - 0x502) <= 2` 则写 `*(GT0x32B + rdi) = 1`
//          0x2A3 分支：`(WORD - 0xD02) <= 3` 则同上；
//   6) 收尾：调 r15(局部[0x80])（关闭对象），返回 ebx（0 或 0xC0000001）。
// 【返回值】0 表示已处理；0xC0000001(STATUS_UNSUCCESSFUL) 表示前置失败。
__int64 EnableDeviceObjectProtection(__int64 ObjectHandle, char Flag)
{
    __int64  Result = 0xC0000001;             // ebx
    __int64  FnOpen;                          // rsi = GT 0x422F
    __int64  FnQuery;                         // rdi = GT 0x41C6
    __int64  FnClose;                         // r15 = GT 0x4223
    __int64  FnValidate;                      // rbp = GT 0x41DB
    char     One = 1;                          // r14b
    __int64  HandleSlot;                      // [rsp+0x80]
    __int64  InfoSlot;                        // [rsp+0x88]
    __int64 *ObjInfo;
    __int64  ProcessBody;                     // rsi
    __int64  Secondary;                       // rdi

    FnOpen     = GtRead((GLOBAL_TABLE_INDEX)0x422F);            // 0x140010484
    FnQuery    = GtRead((GLOBAL_TABLE_INDEX)0x41C6);            // 0x140010491
    FnClose    = GtRead((GLOBAL_TABLE_INDEX)0x4223);            // 0x14001049E
    FnValidate = GtRead((GLOBAL_TABLE_INDEX)0x41DB);            // 0x1400104AB

    if (!FnOpen || !FnQuery || !FnClose || !FnValidate)          // 0x1400104B6..D4
        return Result;

    /* 打开对象：rdi(第1参, 0x80000000, *(ULONG64*)FnOpen, &HandleSlot) */
    HandleSlot = 0;                                              // [rsp+0x80]
    InfoSlot = 0;
    if (((int (__fastcall *)(__int64, unsigned int, ULONG64, __int64 *,
                             __int64, __int64))FnQuery)(
             ObjectHandle,
             0x80000000u,
             *(ULONG64 *)FnOpen,                                 // 0x1400104DA（取 rsi 指向的值）
             &HandleSlot, 0, 0) < 0)                             // 0x1400104FA
        return Result;

    /* 取对象信息 */
    if ((char)GetDeviceObjectFromFileObject((ULONG64)HandleSlot, (ULONG64 *)&InfoSlot, 0) != 1)  // 0x14001051E（call 0x14002DCD0）
        goto L_CLOSE;

    /* ---- 分支一：GT 0x194 ---- */
    if (GtRead((GLOBAL_TABLE_INDEX)0x194) != 0)                  // 0x140010535
    {
        ObjInfo = (__int64 *)InfoSlot;
        if (ObjInfo && ObjInfo[1] == GtRead((GLOBAL_TABLE_INDEX)0x194))   // 0x14001054B
        {
            __int64 *Opened = (__int64 *)HandleSlot;
            ProcessBody = Opened[3];   // +0x18                         // 0x14001055D
            Secondary   = Opened[4];   // +0x20                         // 0x140010561
            if (ProcessBody && Secondary)                            // 0x140010565/56E
            {
                *(ULONG *)(GtRead((GLOBAL_TABLE_INDEX)0x325) + ProcessBody) = 1;   // 0x140010583
                {
                    __int64 Next = *(__int64 *)(GtRead((GLOBAL_TABLE_INDEX)0x329) + ProcessBody);  // 0x140010593
                    if (Next && ((char (__fastcall *)(__int64))FnValidate)(Next))               // 0x14001059F
                    {
                        *(ULONG *)(GtRead((GLOBAL_TABLE_INDEX)0x326) + Next) = 1;               // 0x1400105B1
                        if (Flag == One)                                                     // 0x1400105B5
                            *(WORD *)(GtRead((GLOBAL_TABLE_INDEX)0x327) + Next) = 0;           // 0x1400105C6
                        Result = 0;                                                          // 0x1400105CB
                    }
                }
                if (((char (__fastcall *)(__int64))FnValidate)(Secondary))                   // 0x1400105D1
                {
                    __int64 Leaf = *(__int64 *)(GtRead((GLOBAL_TABLE_INDEX)0x32A) + Secondary);  // 0x1400105E7
                    if (Leaf && ((char (__fastcall *)(__int64))FnValidate)(Leaf))                // 0x1400105F7
                    {
                        *(ULONG *)(GtRead((GLOBAL_TABLE_INDEX)0x32B) + Leaf) = 1;                // 0x140010693/698
                        Result = 0;                                                              // 0x140010693
                    }
                }
                goto L_CLOSE;
            }
        }
    }

    /* ---- 分支二：GT 0x195 ---- */
    if (GtRead((GLOBAL_TABLE_INDEX)0x195) != 0)                  // 0x140010610
    {
        ObjInfo = (__int64 *)InfoSlot;
        if (ObjInfo && ObjInfo[1] == GtRead((GLOBAL_TABLE_INDEX)0x195))   // 0x140010622
        {
            __int64 *Opened = (__int64 *)HandleSlot;
            __int64 Leaf = Opened[3];                                 // +0x18，0x140010630
            if (Leaf)
            {
                USHORT Type = *(USHORT *)Leaf;                        // 0x140010639
                if ((USHORT)(Type - 0x502) <= 2                        // 0x140010644/648
                    || (USHORT)(Type - 0xD02) <= 3)                    // 0x140010683
                {
                    *(ULONG *)(GtRead((GLOBAL_TABLE_INDEX)0x32B) + Leaf) = 1;   // 0x140010698
                    Result = 0;
                }
            }
        }
    }
    else if (GtRead((GLOBAL_TABLE_INDEX)0x2A3) != 0)             // 0x14001064F
    {
        ObjInfo = (__int64 *)InfoSlot;
        if (ObjInfo && ObjInfo[1] == GtRead((GLOBAL_TABLE_INDEX)0x2A3))   // 0x140010661
        {
            __int64 *Opened = (__int64 *)HandleSlot;
            __int64 Leaf = Opened[3];                                 // 0x14001066F
            if (Leaf && (USHORT)(*(USHORT *)Leaf - 0xD02) <= 3)        // 0x140010678/683
            {
                *(ULONG *)(GtRead((GLOBAL_TABLE_INDEX)0x32B) + Leaf) = 1;
                Result = 0;
            }
        }
    }

L_CLOSE:
    ((void (__fastcall *)(__int64))FnClose)(HandleSlot);          // 0x1400106A4
    return Result;                                                // 0x1400106A7
}