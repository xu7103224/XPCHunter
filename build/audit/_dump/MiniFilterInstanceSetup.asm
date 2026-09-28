# MiniFilterInstanceSetup  ea=0x1400129CC  size=179
0x1400129CC: mov     rax, rsp; Minifilter 实例设置回调。检查缓冲区有效性，调用 OpenMiniFilterVolumeFile 打开卷文件并枚举上下文。
0x1400129CF: mov     [rax+8], rbx
0x1400129D3: mov     [rax+10h], rsi
0x1400129D7: mov     [rax+18h], rdi
0x1400129DB: mov     [rax+20h], r14
0x1400129DF: push    r15
0x1400129E1: sub     rsp, 30h
0x1400129E5: mov     esi, r9d
0x1400129E8: mov     rdi, r8
0x1400129EB: xor     ebx, ebx
0x1400129ED: test    r8, r8
0x1400129F0: jz      short loc_140012A5A
0x1400129F2: cmp     esi, 70h ; 'p'
0x1400129F5: jbe     short loc_140012A5A
0x1400129F7: mov     rax, cs:MmUserProbeAddress
0x1400129FE: mov     rcx, [rax]
0x140012A01: cmp     r8, rcx
0x140012A04: jnb     short loc_140012A5A
0x140012A06: lea     rax, [rsi+r8]
0x140012A0A: cmp     rax, rcx
0x140012A0D: jnb     short loc_140012A5A
0x140012A0F: lea     r15d, [rbx+1]
0x140012A13: mov     r8d, r15d; Alignment
0x140012A16: mov     edx, esi; Length
0x140012A18: mov     rcx, rdi; Address
0x140012A1B: call    cs:ProbeForWrite
0x140012A21: mov     r8d, esi; Size
0x140012A24: xor     edx, edx; Val
0x140012A26: mov     rcx, rdi; Dst
0x140012A29: call    memset
0x140012A2E: mov     [rdi], ebx
0x140012A30: mov     ecx, 914h; Index
0x140012A35: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012A3A: cmp     eax, 1771h
0x140012A3F: jb      short loc_140012A5A
0x140012A41: mov     edx, esi
0x140012A43: mov     rcx, rdi
0x140012A46: call    OpenMiniFilterVolumeFile; 打开 Minifilter 卷文件。解码编码的驱动路径，创建文件对象，打开卷句柄，分配缓冲区后调用 EnumMiniFilterContextList 枚举该卷上的上下文列表。
0x140012A4B: movzx   eax, bl
0x140012A4E: cmp     [rdi], ebx
0x140012A50: cmovnz  eax, r15d
0x140012A54: mov     bl, al
0x140012A56: mov     [rsp+38h+var_18], al
0x140012A5A: jmp     short loc_140012A62
0x140012A5C: xor     bl, bl
0x140012A5E: mov     [rsp+38h+var_18], bl
0x140012A62: mov     al, bl
0x140012A64: mov     rbx, [rsp+38h+arg_0]
0x140012A69: mov     rsi, [rsp+38h+arg_8]
0x140012A6E: mov     rdi, [rsp+38h+arg_10]
0x140012A73: mov     r14, [rsp+38h+arg_18]
0x140012A78: add     rsp, 30h
0x140012A7C: pop     r15
0x140012A7E: retn