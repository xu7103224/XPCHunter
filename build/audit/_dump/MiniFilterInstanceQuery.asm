# MiniFilterInstanceQuery  ea=0x140012B78  size=175
0x140012B78: mov     [rsp+arg_0], rbx; Minifilter 实例查询回调。验证输入缓冲区，检查地址有效性，调用 RemoveMiniFilterContextNode 移除指定的上下文节点。
0x140012B7D: mov     [rsp+arg_8], rsi
0x140012B82: push    rdi
0x140012B83: sub     rsp, 40h
0x140012B87: mov     rdi, rcx
0x140012B8A: xor     ebx, ebx
0x140012B8C: test    rcx, rcx
0x140012B8F: jz      short loc_140012C0D
0x140012B91: cmp     edx, 10h
0x140012B94: jnz     short loc_140012C0D
0x140012B96: mov     rax, cs:MmUserProbeAddress
0x140012B9D: mov     rcx, [rax]
0x140012BA0: cmp     rdi, rcx
0x140012BA3: jnb     short loc_140012C0D
0x140012BA5: lea     rax, [rdi+10h]
0x140012BA9: cmp     rax, rcx
0x140012BAC: jnb     short loc_140012C0D
0x140012BAE: lea     esi, [rbx+1]
0x140012BB1: mov     r8d, esi; Alignment
0x140012BB4: lea     edx, [rbx+10h]; Length
0x140012BB7: mov     rcx, rdi; Address
0x140012BBA: call    cs:ProbeForRead
0x140012BC0: movups  xmm0, xmmword ptr [rdi]
0x140012BC3: movups  [rsp+48h+var_20], xmm0
0x140012BC8: mov     rax, cs:MmSystemRangeStart
0x140012BCF: mov     rcx, [rax]
0x140012BD2: movq    rax, xmm0
0x140012BD7: cmp     rax, rcx
0x140012BDA: jbe     short loc_140012C0D
0x140012BDC: cmp     qword ptr [rsp+48h+var_20+8], rcx
0x140012BE1: jbe     short loc_140012C0D
0x140012BE3: mov     ecx, 914h; Index
0x140012BE8: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012BED: cmp     eax, 1771h
0x140012BF2: jb      short loc_140012C0D
0x140012BF4: lea     rcx, [rsp+48h+var_20]
0x140012BF9: call    RemoveMiniFilterContextNode; 移除 Minifilter 上下文节点。在指定上下文链表中查找匹配的节点（按 ContextNode[1] 匹配），找到后从链表中摘除。
0x140012BFE: movzx   ecx, bl
0x140012C01: cmp     al, sil
0x140012C04: cmovz   ecx, esi
0x140012C07: mov     bl, cl
0x140012C09: mov     [rsp+48h+var_28], cl
0x140012C0D: jmp     short loc_140012C15
0x140012C0F: xor     bl, bl
0x140012C11: mov     [rsp+48h+var_28], bl
0x140012C15: mov     al, bl
0x140012C17: mov     rbx, [rsp+48h+arg_0]
0x140012C1C: mov     rsi, [rsp+48h+arg_8]
0x140012C21: add     rsp, 40h
0x140012C25: pop     rdi
0x140012C26: retn