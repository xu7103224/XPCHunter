# InitPESectionReadContext  ea=0x14008A7E4  size=95
0x14008A7E4: mov     r10, [rsp+arg_38]
0x14008A7E9: movsxd  rax, edx
0x14008A7EC: add     rax, rcx
0x14008A7EF: mov     [r10+8], rcx
0x14008A7F3: mov     [r10+18h], r8d
0x14008A7F7: mov     [r10+10h], rax
0x14008A7FB: mov     eax, [rsp+arg_20]
0x14008A7FF: mov     [r10+1Ch], r8d
0x14008A803: mov     [r10+40h], eax
0x14008A807: mov     rax, [rsp+arg_28]
0x14008A80C: mov     [r10+28h], r9
0x14008A810: mov     [r10+30h], rax
0x14008A814: mov     rax, [rsp+arg_30]
0x14008A819: mov     [r10+38h], rax
0x14008A81D: cmp     r8d, 2
0x14008A821: jz      short loc_14008A830
0x14008A823: lea     rax, unk_140096A50
0x14008A82A: mov     [r10+20h], r8d
0x14008A82E: jmp     short loc_14008A83F
0x14008A830: lea     rax, unk_140097E50
0x14008A837: mov     dword ptr [r10+20h], 1
0x14008A83F: mov     [r10], rax
0x14008A842: retn