# AllocBufferAndSendIoControl  ea=0x140075D94  size=436
0x140075D94: push    rbx
0x140075D96: push    rsi
0x140075D97: push    rdi
0x140075D98: push    r12
0x140075D9A: push    r13
0x140075D9C: push    r14
0x140075D9E: push    r15
0x140075DA0: sub     rsp, 0C0h
0x140075DA7: mov     rax, cs:__security_cookie
0x140075DAE: xor     rax, rsp
0x140075DB1: mov     [rsp+0F8h+var_48], rax
0x140075DB9: mov     [rsp+0F8h+var_A4], r9d
0x140075DBE: mov     rbx, r8
0x140075DC1: mov     [rsp+0F8h+var_90], rbx
0x140075DC6: mov     r13, rdx
0x140075DC9: mov     r12, rcx
0x140075DCC: mov     r14, [rsp+0F8h+Dst]
0x140075DD4: mov     esi, dword ptr [rsp+0F8h+NumberOfBytes]
0x140075DDB: mov     r15, [rsp+0F8h+arg_38]
0x140075DE3: mov     edi, 0C0000001h
0x140075DE8: mov     [rsp+0F8h+var_A8], edi
0x140075DEC: and     [rsp+0F8h+var_A0], 0
0x140075DF2: mov     ecx, 914h; Index
0x140075DF7: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140075DFC: cmp     eax, 42EEh
0x140075E01: jnb     loc_140075F23
0x140075E07: mov     ecx, 914h; Index
0x140075E0C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140075E11: cmp     eax, 42EEh
0x140075E16: jnb     short loc_140075E53
0x140075E18: and     [rsp+0F8h+var_B8], 0
0x140075E1E: mov     [rsp+0F8h+var_C0], r15
0x140075E23: mov     [rsp+0F8h+var_C8], esi
0x140075E27: mov     [rsp+0F8h+var_D0], r14
0x140075E2C: mov     eax, [rsp+0F8h+arg_20]
0x140075E33: mov     [rsp+0F8h+var_D8], eax
0x140075E37: mov     r9d, [rsp+0F8h+var_A4]
0x140075E3C: xor     r8d, r8d
0x140075E3F: mov     rdx, rbx
0x140075E42: mov     rcx, r13
0x140075E45: call    r12
0x140075E48: mov     edi, eax
0x140075E4A: mov     [rsp+0F8h+var_A8], eax
0x140075E4E: jmp     loc_140075EFE
0x140075E53: cmp     esi, 40h ; '@'
0x140075E56: ja      short loc_140075E64
0x140075E58: lea     rbx, [rsp+0F8h+P]
0x140075E5D: mov     [rsp+0F8h+var_A0], rbx
0x140075E62: jmp     short loc_140075E80
0x140075E64: mov     rdx, rsi; NumberOfBytes
0x140075E67: mov     ecx, 9; PoolType
0x140075E6C: mov     r8d, 42424D43h; Tag
0x140075E72: call    cs:ExAllocatePoolWithQuotaTag
0x140075E78: mov     rbx, rax
0x140075E7B: mov     [rsp+0F8h+var_A0], rax
0x140075E80: test    rbx, rbx
0x140075E83: jz      short loc_140075EFE
0x140075E85: and     [rsp+0F8h+var_B8], 0
0x140075E8B: lea     rax, [rsp+0F8h+MaxCount]
0x140075E90: mov     [rsp+0F8h+var_C0], rax
0x140075E95: mov     [rsp+0F8h+var_C8], esi
0x140075E99: mov     [rsp+0F8h+var_D0], rbx
0x140075E9E: mov     ecx, [rsp+0F8h+arg_20]
0x140075EA5: mov     [rsp+0F8h+var_D8], ecx
0x140075EA9: mov     r9d, [rsp+0F8h+var_A4]
0x140075EAE: xor     r8d, r8d
0x140075EB1: mov     rdx, [rsp+0F8h+var_90]
0x140075EB6: mov     rcx, r13
0x140075EB9: call    r12
0x140075EBC: mov     edi, eax
0x140075EBE: mov     [rsp+0F8h+var_A8], eax
0x140075EC2: test    eax, eax
0x140075EC4: js      short loc_140075EE0
0x140075EC6: mov     eax, dword ptr [rsp+0F8h+MaxCount]
0x140075ECA: mov     [r15], eax
0x140075ECD: cmp     esi, eax
0x140075ECF: cmova   esi, eax
0x140075ED2: mov     r8d, esi; MaxCount
0x140075ED5: mov     rdx, rbx; Src
0x140075ED8: mov     rcx, r14; Dst
0x140075EDB: call    memmove
0x140075EE0: lea     rax, [rsp+0F8h+P]
0x140075EE5: cmp     rbx, rax
0x140075EE8: jz      short loc_140075EFE
0x140075EEA: mov     edx, 42424D43h; Tag
0x140075EEF: mov     rcx, rbx; P
0x140075EF2: call    cs:ExFreePoolWithTag
0x140075EF8: and     [rsp+0F8h+var_A0], 0
0x140075EFE: jmp     short loc_140075F23
0x140075F00: mov     rcx, [rsp+0F8h+var_A0]; P
0x140075F05: test    rcx, rcx
0x140075F08: jz      short loc_140075F1F
0x140075F0A: lea     rax, [rsp+0F8h+P]
0x140075F0F: cmp     rcx, rax
0x140075F12: jz      short loc_140075F1F
0x140075F14: mov     edx, 42424D43h; Tag
0x140075F19: call    cs:ExFreePoolWithTag
0x140075F1F: mov     edi, [rsp+0F8h+var_A8]
0x140075F23: mov     eax, edi
0x140075F25: mov     rcx, [rsp+0F8h+var_48]
0x140075F2D: xor     rcx, rsp; StackCookie
0x140075F30: call    __security_check_cookie
0x140075F35: add     rsp, 0C0h
0x140075F3C: pop     r15
0x140075F3E: pop     r14
0x140075F40: pop     r13
0x140075F42: pop     r12
0x140075F44: pop     rdi
0x140075F45: pop     rsi
0x140075F46: pop     rbx
0x140075F47: retn