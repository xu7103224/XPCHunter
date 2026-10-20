// DispatchDeviceControl — IRP_MJ_DEVICE_CONTROL 分发
// 对应原始驱动 0x1400823EC（0x26C 字节 / 108 条指令）
//
// 【重写 2026-10-20】旧实现完全是自创协议：它读 Irp->AssociatedIrp.MasterIrp
//   并要求 Type == 0x20202020（IRP_TYPE_MAGIC），而原始驱动**从不**看 MasterIrp。
//   后果：任何按原始协议构造的请求都被判为 STATUS_INVALID_PARAMETER(87)——
//   实机联调 xpch_probe 时 283 条命令全部返回 87，设备能打开但一条命令都发不通。
//
// 原始流程（逐条对照）：
//   0x140082439  cmp [rax+10h], 30h      ; InputBufferLength 必须 == 0x30
//   0x140082443  test rdi,rdi            ; SystemBuffer 非空
//   0x14008244C  ebx = [rax+18h]         ; IoControlCode
//   0x14008244F  ecx = 1E0h; GtRead      ; rax = GT[0x1E0]（设备名派生密钥）
//   0x140082459  cmp eax, ebx; jnz 拒    ; **IoControlCode 必须等于 GT[0x1E0]**
//   0x140082464  DecryptInputBuffer(buf) ; ~(b ^ GT[0x1E1])，0x30 字节
//   0x140082469  cmp [rdi], 20240810h    ; Magic
//   0x140082491  MD5(buf, 0x28)          ; 对明文前 0x28 字节
//   0x1400824BE  cmp eax, [rdi+28h]      ; 校验和（只取 DWORD）
//   0x14008251E..52C  Command=[rdi+4]，范围 [0x20,0x13A]
//   0x140082532  GtRead(0x304)           ; 驱动就绪标志；未就绪时只放行 0x22
//   0x14008254F  InitCallbackFunctions / GtWrite(0x353,1)
//   0x140082570  CheckProcessAccess()
//   0x140082579  add ebx,-0x20; ecx = ebx+0x921; GtRead  ; 命令表
//   0x14008258F  GtRead(0x355)           ; 重入锁，非 0 则拒
//   0x1400825AB..5BA  Handler(OutBuf, OutSize, Ctx, CtxSize)
//   0x1400825BF  GtWrite(0x355, 0)
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;
    ULONG InputLength;
    ULONG IoControlCode;
    PVOID Buffer;
    ULONG ExpectedCode;
    UCHAR KeyByte;
    UCHAR Digest[16];
    MD5_CONTEXT Md5;
    ULONG Command;
    ULONG Index;
    __int64 Handler;
    BOOLEAN Result = FALSE;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
    Buffer = Irp->AssociatedIrp.SystemBuffer;

    /* 0x140082439 / 0x140082443 */
    if (InputLength != 0x30 || Buffer == NULL)
        goto Complete;

    /* 0x14008244C..45B：IoControlCode 必须等于设备名派生的 GT[0x1E0] */
    ExpectedCode = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x1E0);
    if (ExpectedCode != IoControlCode)
        goto Complete;

    /* 0x140082464：原地解密 0x30 字节（自反异或） */
    KeyByte = (UCHAR)GtRead((GLOBAL_TABLE_INDEX)0x1E1);
    DecryptInputBuffer((PUCHAR)Buffer, KeyByte);

    /* 0x140082469：Magic */
    if (*(ULONG *)Buffer != 0x20240810u)
        goto Complete;

    /* 0x140082491..4C1：MD5(明文前 0x28 字节) 的前 4 字节 == [buf+0x28] */
    Md5InitContext(&Md5);
    Md5Update(&Md5, (PUCHAR)Buffer, 0x28);
    Md5Final(&Md5, Digest);
    if (*(ULONG *)Digest != *(ULONG *)((PUCHAR)Buffer + 0x28))
        goto Complete;

    /* 0x14008251E..52C：命令号与范围 */
    Command = *(ULONG *)((PUCHAR)Buffer + 4);
    if (Command - 0x20u > 0x11Au)
        goto Complete;

    /* 0x140082532..547：驱动就绪标志，未就绪时只放行查询命令 0x22 */
    if (GtRead((GLOBAL_TABLE_INDEX)0x304) == 0 && Command != 0x22u)
        goto Complete;

    /* 0x14008254F..56B：非 0x22 时先初始化回调并置已初始化标志 */
    if (Command != 0x22u)
    {
        InitCallbackFunctions();
        if (GtRead((GLOBAL_TABLE_INDEX)0x353) == 0)
            GtWrite((GLOBAL_TABLE_INDEX)0x353, 1);
    }

    /* 0x140082570..577：进程访问校验 */
    if (CheckProcessAccess() != 1)
        goto Complete;

    /* 0x140082579..58D：命令表 GT[0x921 + (Command - 0x20)] */
    Index = Command - 0x20u;
    Handler = GtRead((GLOBAL_TABLE_INDEX)(0x921u + Index));
    if (Handler == 0)
        goto Complete;

    /* 0x14008258F..5A6：重入锁 */
    if (GtRead((GLOBAL_TABLE_INDEX)0x355) != 0)
        goto Complete;
    GtWrite((GLOBAL_TABLE_INDEX)0x355, 1);

    /* 0x1400825AB..5BA：调用处理函数
       rcx = [buf+0x10]（ContextPointer）
       rdx = [buf+0x20]（OutputSize）
       r8  = [buf+0x18]（ExtraPointer）
       r9  = [buf+0x24]（ContextSize）         */
    Result = ((__int64 (__fastcall *)(ULONG64, ULONG, ULONG64, ULONG))Handler)(
                 *(ULONG64 *)((PUCHAR)Buffer + 0x10),
                 *(ULONG *)((PUCHAR)Buffer + 0x20),
                 *(ULONG64 *)((PUCHAR)Buffer + 0x18),
                 *(ULONG *)((PUCHAR)Buffer + 0x24)) != 0;

    /* 0x1400825BF..5C6：清重入锁 */
    GtWrite((GLOBAL_TABLE_INDEX)0x355, 0);

Complete:
    Status = Result ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}