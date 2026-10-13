// OpenWin32kSysSection — 打开 win32k 的节对象
// 对应原始驱动 0x1400174F8（124 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：读 GtWin32kBase / GtWin32kSize
//   做有效性检查后直接返回基址。注释称"返回 Win32k 基址作为节对象句柄"，
//   与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始读 GT 0x421D（= GtRtlInitUnicodeStringFunc）而我方读 0x80F；
//   逐条反汇编核对后确认（原始函数体里根本没有 GtRead）。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x1400174F8（全部指令）：
//   sub rsp,0x58 ; 存入 stack cookie
//   [rsp+0x44] = 0                          ; 第 5 个栈参 = 0
//   rcx = [rsp+0x20]                        ; 指向待构造的 Unicode 缓冲
//   依次写入 9 个 DWORD，拼出 L"\FileSystem\FltMgr"（18 个字符）：
//     0x46005C 0x6C0069 0x530065 0x730079 0x650074
//     0x5C006D 0x6C0046 0x4D0074 0x720067
//   call 0x140078F48                        ; = OpenFileSection(缓冲)
//   校验 stack cookie ; add rsp,0x58 ; ret
// 【说明】本函数**不访问全局表**：差分里看到的 GT 0x421D 读
//   发生在被调用的 OpenFileSection（0x140078F48）内部——
//   后者开头即读 0x421D/0x421A/0x4223/0x4160 四个函数指针槽
//   （= GtRtlInitUnicodeStringFunc / GtIoCreateFileFunc /
//      GtCloseHandleFunc / GtDriverObjectListHead，枚举值已逐一核对吻合）。
// 【返回值】OpenFileSection 的返回值（文件节对象句柄；失败为 0）。
__int64 OpenWin32kSysSection(void)
{
    WCHAR PathBuffer[20];

    // L"\FileSystem\FltMgr" —— 与原始驱动逐 DWORD 一致（9 个 DWORD = 18 字符）
    PathBuffer[0] = 0x005C; PathBuffer[1] = 0x0046;   // \F
    PathBuffer[2] = 0x0069; PathBuffer[3] = 0x006C;   // il
    PathBuffer[4] = 0x0065; PathBuffer[5] = 0x0053;   // eS
    PathBuffer[6] = 0x0079; PathBuffer[7] = 0x0073;   // ys
    PathBuffer[8] = 0x0074; PathBuffer[9] = 0x0065;   // te
    PathBuffer[10] = 0x006D; PathBuffer[11] = 0x005C; // m\
    PathBuffer[12] = 0x0046; PathBuffer[13] = 0x006C; // Fl
    PathBuffer[14] = 0x0074; PathBuffer[15] = 0x004D; // tM
    PathBuffer[16] = 0x0067; PathBuffer[17] = 0x0072; // gr
    PathBuffer[18] = 0;                               // 结尾（原始 [rsp+0x44]=0）

    return OpenFileSection((__int64)PathBuffer);      // 0x14001755D
}
