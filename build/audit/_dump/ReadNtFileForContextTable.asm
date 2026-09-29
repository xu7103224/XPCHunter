# ReadNtFileForContextTable  ea=0x1400475C8  size=293
0x1400475C8: mov     [rsp-8+arg_10], rbx; 读取上下文表驱动文件。通过编码路径解码 ntoskrnl 文件路径，调用 ReadFileRawData 读取，然后用 ReadNtFileToBuffer 解析 PE 格式。
0x1400475CD: mov     [rsp-8+arg_18], rsi
0x1400475D2: push    rbp
0x1400475D3: push    rdi
0x1400475D4: push    r14
0x1400475D6: lea     rbp, [rsp-47h]
0x1400475DB: sub     rsp, 0B0h
0x1400475E2: mov     rax, cs:__security_cookie
0x1400475E9: xor     rax, rsp
0x1400475EC: mov     [rbp+57h+var_20], rax
0x1400475F0: mov     eax, 730079h
0x1400475F5: mov     rsi, rdx
0x1400475F8: mov     rdi, rcx
0x1400475FB: xor     ebx, ebx
0x1400475FD: lea     r8, [rbp+57h+MaxCount]
0x140047601: lea     rdx, [rbp+57h+Src]
0x140047605: lea     r14d, [rbx+1]
0x140047609: lea     rcx, [rbp+57h+var_80]; int
0x14004760D: mov     [rbp+57h+var_80], 53005Ch
0x140047614: mov     r9b, r14b
0x140047617: mov     [rbp+57h+var_7C], eax
0x14004761A: mov     [rbp+57h+var_78], 650074h
0x140047621: mov     [rbp+57h+var_74], 52006Dh
0x140047628: mov     [rbp+57h+var_70], 6F006Fh
0x14004762F: mov     [rbp+57h+var_6C], 5C0074h
0x140047636: mov     [rbp+57h+var_68], 790073h
0x14004763D: mov     [rbp+57h+var_64], 740073h
0x140047644: mov     [rbp+57h+var_60], 6D0065h
0x14004764B: mov     [rbp+57h+var_5C], 320033h
0x140047652: mov     [rbp+57h+var_58], 64005Ch
0x140047659: mov     [rbp+57h+var_54], 690072h
0x140047660: mov     [rbp+57h+var_50], 650076h
0x140047667: mov     [rbp+57h+var_4C], 730072h
0x14004766E: mov     [rbp+57h+var_48], 70005Ch
0x140047675: mov     [rbp+57h+var_44], 720061h
0x14004767C: mov     [rbp+57h+var_40], 6D0074h
0x140047683: mov     [rbp+57h+var_3C], 720067h
0x14004768A: mov     [rbp+57h+var_38], 73002Eh
0x140047691: mov     [rbp+57h+var_34], rax
0x140047695: call    ReadFileRawData
0x14004769A: test    eax, eax
0x14004769C: jnz     short loc_1400476C7
0x14004769E: mov     edx, dword ptr [rbp+57h+MaxCount]; MaxCount
0x1400476A1: mov     rcx, [rbp+57h+Src]; Src
0x1400476A5: mov     r9, rsi
0x1400476A8: mov     r8, rdi
0x1400476AB: mov     [rsp+0C0h+var_A0], ebx
0x1400476AF: call    ReadNtFileToBuffer; 读取 PE 文件到缓冲区。解析 PE 头并按节对齐展开，重定位适配到目标基址。
0x1400476B4: mov     rcx, [rbp+57h+Src]
0x1400476B8: movzx   ebx, bl
0x1400476BB: cmp     al, r14b
0x1400476BE: cmovz   ebx, r14d
0x1400476C2: call    ExFree
0x1400476C7: mov     al, bl
0x1400476C9: mov     rcx, [rbp+57h+var_20]
0x1400476CD: xor     rcx, rsp; StackCookie
0x1400476D0: call    __security_check_cookie
0x1400476D5: lea     r11, [rsp+0C0h+var_10]
0x1400476DD: mov     rbx, [r11+30h]
0x1400476E1: mov     rsi, [r11+38h]
0x1400476E5: mov     rsp, r11
0x1400476E8: pop     r14
0x1400476EA: pop     rdi
0x1400476EB: pop     rbp
0x1400476EC: retn