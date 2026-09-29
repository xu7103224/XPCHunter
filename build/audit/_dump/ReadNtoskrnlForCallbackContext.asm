# ReadNtoskrnlForCallbackContext  ea=0x14003E80C  size=285
0x14003E80C: mov     [rsp-8+arg_10], rbx
0x14003E811: mov     [rsp-8+arg_18], rsi
0x14003E816: push    rbp
0x14003E817: push    rdi
0x14003E818: push    r14
0x14003E81A: lea     rbp, [rsp-47h]
0x14003E81F: sub     rsp, 0A0h
0x14003E826: mov     rax, cs:__security_cookie
0x14003E82D: xor     rax, rsp
0x14003E830: mov     [rbp+57h+var_20], rax
0x14003E834: mov     eax, 790073h
0x14003E839: mov     rsi, rdx
0x14003E83C: mov     rdi, rcx
0x14003E83F: xor     ebx, ebx
0x14003E841: lea     r8, [rbp+57h+MaxCount]
0x14003E845: lea     rdx, [rbp+57h+Src]
0x14003E849: lea     r14d, [rbx+1]
0x14003E84D: lea     rcx, [rbp+57h+var_70]; int
0x14003E851: mov     [rbp+57h+var_70], 53005Ch
0x14003E858: mov     r9b, r14b
0x14003E85B: mov     [rbp+57h+var_6C], 730079h
0x14003E862: mov     [rbp+57h+var_68], 650074h
0x14003E869: mov     [rbp+57h+var_64], 52006Dh
0x14003E870: mov     [rbp+57h+var_60], 6F006Fh
0x14003E877: mov     [rbp+57h+var_5C], 5C0074h
0x14003E87E: mov     [rbp+57h+var_58], eax
0x14003E881: mov     [rbp+57h+var_54], 740073h
0x14003E888: mov     [rbp+57h+var_50], 6D0065h
0x14003E88F: mov     [rbp+57h+var_4C], 320033h
0x14003E896: mov     [rbp+57h+var_48], 64005Ch
0x14003E89D: mov     [rbp+57h+var_44], 690072h
0x14003E8A4: mov     [rbp+57h+var_40], 650076h
0x14003E8AB: mov     [rbp+57h+var_3C], 730072h
0x14003E8B2: mov     [rbp+57h+var_38], 6D005Ch
0x14003E8B9: mov     [rbp+57h+var_34], 660073h
0x14003E8C0: mov     [rbp+57h+var_30], 2E0073h
0x14003E8C7: mov     [rbp+57h+var_2C], eax
0x14003E8CA: mov     [rbp+57h+var_28], 73h ; 's'
0x14003E8D1: call    ReadFileRawData
0x14003E8D6: test    eax, eax
0x14003E8D8: jnz     short loc_14003E903
0x14003E8DA: mov     edx, dword ptr [rbp+57h+MaxCount]; MaxCount
0x14003E8DD: mov     rcx, [rbp+57h+Src]; Src
0x14003E8E1: mov     r9, rsi
0x14003E8E4: mov     r8, rdi
0x14003E8E7: mov     [rsp+0B0h+var_90], ebx
0x14003E8EB: call    ReadNtFileToBuffer; 读取 PE 文件到缓冲区。解析 PE 头并按节对齐展开，重定位适配到目标基址。
0x14003E8F0: mov     rcx, [rbp+57h+Src]
0x14003E8F4: movzx   ebx, bl
0x14003E8F7: cmp     al, r14b
0x14003E8FA: cmovz   ebx, r14d
0x14003E8FE: call    ExFree
0x14003E903: mov     al, bl
0x14003E905: mov     rcx, [rbp+57h+var_20]
0x14003E909: xor     rcx, rsp; StackCookie
0x14003E90C: call    __security_check_cookie
0x14003E911: lea     r11, [rsp+0B0h+var_10]
0x14003E919: mov     rbx, [r11+30h]
0x14003E91D: mov     rsi, [r11+38h]
0x14003E921: mov     rsp, r11
0x14003E924: pop     r14
0x14003E926: pop     rdi
0x14003E927: pop     rbp
0x14003E928: retn