// InitUSBPortSyscallTable  0x140055914  231 bytes
// 初始化 USB 端口系统调用表。分配 GT 15824 的全局表项，读取 usbport.sys 文件，调用 ParseUSBPortSyscallStubs 解析系统调用桩，从 PE 导出目录复制 16 字节原始代码到服务表条目，调用 FillExportEntrySlot 填充导出条目槽。
// 初始化 USB Port 系统调用表。分配全局表空间，读取 USB Port 驱动文件，解析其系统调用存根函数和导出表，填充系统调用条目（名称和地址），并注册到导出条目槽中。
// 初始化USB端口系统调用表
// 查找系统调用回调表：查找系统调用回调表的地址
// 初始化系统调用回调导出2：初始化系统调用回调的导出表版本2
// 初始化 USB 端口系统调用表：初始化 USB 端口的系统调用表
void InitUSBPortSyscallTable()
{
  char v0; // bl
  __int64 *v1; // rdi
  __int64 v2; // rsi
  unsigned int *v3; // rdx
  __int64 v4; // r8
  __int64 v5; // rcx
  unsigned int v6; // [rsp+30h] [rbp+8h] BYREF
  char *v7; // [rsp+38h] [rbp+10h] BYREF

  v0 = 0;
  v1 = GtAlloc(GtEprocessField202|GtFwpsDispatchTableBase|0x3400);
  v2 = GtRead(GtFwpsDispatchTableBase|GtSubsystemConfigBase|GtEprocessField08);
  if ( v2 && ReadUSBPortDriverFile(&v7, &v6) )
  {
    if ( ParseUSBPortSyscallStubs((__int64)v7, v6, (__int64)v1) == 1 && ParseNtExportDir((__int64)v7, v6, v2, 0) == 1 )
    {
      v3 = (unsigned int *)v1 + 1;
      v4 = 28;
      do
      {
        v5 = *v3;
        *(v3 - 1) = 0;
        if ( (_DWORD)v5 && (int)v5 + 16 <= v6 )
        {
          *(v3 - 1) = 1;
          *(_OWORD *)(v3 + 3) = *(_OWORD *)&v7[v5];
        }
        v3 += 12;
        --v4;
      }
      while ( v4 );
      v0 = 1;
      GtWrite(GtFwpsDispatchTableBase|GtSubsystemConfigBase|GtEprocessField10, 1);
    }
    ExFree(v7);
    if ( v0 == 1 )
      FillExportEntrySlot((__int64)v1);
  }
}
