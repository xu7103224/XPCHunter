# RegisterCommPortReplyCallback  ea=0x140019898  size=62
0x140019898: push    rbx
0x14001989A: sub     rsp, 20h
0x14001989E: mov     ecx, 42CEh; Index
0x1400198A3: xor     ebx, ebx
0x1400198A5: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400198AA: test    rax, rax
0x1400198AD: jz      short loc_1400198CE
0x1400198AF: lea     r8, g_CommPortContext
0x1400198B6: lea     rcx, MiniFilterCommPortReplyDone; Minifilter 通信端口回复完成回调。根据消息大小分发处理：大小为 26 时检查文件路径是否存在，大小为 1 时检查全局表 741 并查询文件信息，其他大小通过位测试掩码判断是否返回访问被拒。
0x1400198BD: xor     edx, edx
0x1400198BF: call    rax
0x1400198C1: movzx   ebx, bl
0x1400198C4: mov     edx, 1
0x1400198C9: test    eax, eax
0x1400198CB: cmovns  ebx, edx
0x1400198CE: mov     al, bl
0x1400198D0: add     rsp, 20h
0x1400198D4: pop     rbx
0x1400198D5: retn