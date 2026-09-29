# ReadNtoskrnlForCallbackCtx  ea=0x14003612C  size=344
0x14003612C: mov     [rsp-8+arg_10], rbx
0x140036131: mov     [rsp-8+arg_18], rsi
0x140036136: push    rbp
0x140036137: push    rdi
0x140036138: push    r14
0x14003613A: lea     rbp, [rsp-47h]
0x14003613F: sub     rsp, 0A0h
0x140036146: mov     rax, cs:__security_cookie
0x14003614D: xor     rax, rsp
0x140036150: mov     [rbp+57h+var_20], rax
0x140036154: mov     rdi, rcx
0x140036157: mov     r14d, 790073h
0x14003615D: mov     ecx, 914h; Index
0x140036162: mov     rsi, rdx
0x140036165: xor     ebx, ebx
0x140036167: mov     [rbp+57h+var_70], 53005Ch
0x14003616E: mov     [rbp+57h+var_58], r14d
0x140036172: mov     [rbp+57h+var_6C], 730079h
0x140036179: mov     [rbp+57h+var_68], 650074h
0x140036180: mov     [rbp+57h+var_64], 52006Dh
0x140036187: mov     [rbp+57h+var_60], 6F006Fh
0x14003618E: mov     [rbp+57h+var_5C], 5C0074h
0x140036195: mov     [rbp+57h+var_54], 740073h
0x14003619C: mov     [rbp+57h+var_50], 6D0065h
0x1400361A3: mov     [rbp+57h+var_4C], 320033h
0x1400361AA: mov     [rbp+57h+var_48], 64005Ch
0x1400361B1: mov     [rbp+57h+var_44], 690072h
0x1400361B8: mov     [rbp+57h+var_40], 650076h
0x1400361BF: mov     [rbp+57h+var_3C], 730072h
0x1400361C6: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400361CB: mov     [rbp+57h+var_28], r14d
0x1400361CF: mov     [rbp+57h+var_24], 73h ; 's'
0x1400361D6: cmp     eax, 1770h
0x1400361DB: jnb     short loc_1400361FB
0x1400361DD: mov     [rbp+57h+var_38], 66005Ch
0x1400361E4: mov     [rbp+57h+var_34], 640074h
0x1400361EB: mov     [rbp+57h+var_30], 730069h
0x1400361F2: mov     [rbp+57h+var_2C], 2E006Bh
0x1400361F9: jmp     short loc_140036217
0x1400361FB: mov     [rbp+57h+var_38], 76005Ch
0x140036202: mov     [rbp+57h+var_34], 6C006Fh
0x140036209: mov     [rbp+57h+var_30], 67006Dh
0x140036210: mov     [rbp+57h+var_2C], 2E0072h
0x140036217: mov     r14d, 1
0x14003621D: lea     r8, [rbp+57h+MaxCount]
0x140036221: lea     rdx, [rbp+57h+Src]
0x140036225: lea     rcx, [rbp+57h+var_70]; int
0x140036229: mov     r9b, r14b
0x14003622C: call    ReadFileRawData
0x140036231: test    eax, eax
0x140036233: jnz     short loc_14003625E
0x140036235: mov     edx, dword ptr [rbp+57h+MaxCount]; MaxCount
0x140036238: mov     rcx, [rbp+57h+Src]; Src
0x14003623C: mov     r9, rsi
0x14003623F: mov     r8, rdi
0x140036242: mov     [rsp+0B0h+var_90], ebx
0x140036246: call    ReadNtFileToBuffer; 读取 PE 文件到缓冲区。解析 PE 头并按节对齐展开，重定位适配到目标基址。
0x14003624B: mov     rcx, [rbp+57h+Src]
0x14003624F: movzx   ebx, bl
0x140036252: cmp     al, r14b
0x140036255: cmovz   ebx, r14d
0x140036259: call    ExFree
0x14003625E: mov     al, bl
0x140036260: mov     rcx, [rbp+57h+var_20]
0x140036264: xor     rcx, rsp; StackCookie
0x140036267: call    __security_check_cookie
0x14003626C: lea     r11, [rsp+0B0h+var_10]
0x140036274: mov     rbx, [r11+30h]
0x140036278: mov     rsi, [r11+38h]
0x14003627C: mov     rsp, r11
0x14003627F: pop     r14
0x140036281: pop     rdi
0x140036282: pop     rbp
0x140036283: retn