# ParseNtKernelDataSections  ea=0x140062884  size=842
0x140062884: mov     [rsp-8+arg_10], rbx; 解析 NT 内核数据节区。读取 GT 874(NdisIMInitializeDeviceInstanceEx 偏移)，在 ndis.sys 的 INIT 节区中遍历 PE 节区表。根据构建号分支：>=0x4A61(Win10 19041+)先找类型 1296+1368 组合，再内层扫描找 1298+1139/1140+1296 模式写入 GT 876(Win10 进程链表头)；<0x4A61 直接找 bound import+1368 组合后进入内层相同扫描逻辑。
0x140062889: push    rbp
0x14006288A: push    rsi
0x14006288B: push    rdi
0x14006288C: push    r12
0x14006288E: push    r13
0x140062890: push    r14
0x140062892: push    r15
0x140062894: lea     rbp, [rsp-0D0h]
0x14006289C: sub     rsp, 1D0h
0x1400628A3: mov     rax, cs:__security_cookie
0x1400628AA: xor     rax, rsp
0x1400628AD: mov     [rbp+100h+var_40], rax
0x1400628B4: mov     r12, rcx
0x1400628B7: mov     edi, 36Ah
0x1400628BC: mov     r14d, edx
0x1400628BF: mov     ecx, edi; Index
0x1400628C1: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400628C6: mov     rbx, rax
0x1400628C9: test    eax, eax
0x1400628CB: jnz     short loc_1400628E1
0x1400628CD: mov     edx, r14d
0x1400628D0: mov     rcx, r12
0x1400628D3: call    FindNdisIMInitializeDeviceInstanceEx; 查找 NdisIMInitializeDeviceInstanceEx 导出函数。查找名为 "NdisIMInitializeDeviceInstanceEx" 的导出函数，将偏移和地址写入 GT 874/875。
0x1400628D8: mov     ecx, edi; Index
0x1400628DA: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400628DF: mov     ebx, eax
0x1400628E1: mov     ecx, 361h; Index
0x1400628E6: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400628EB: mov     r13, rax
0x1400628EE: test    rax, rax
0x1400628F1: jz      loc_140062BA4
0x1400628F7: test    ebx, ebx
0x1400628F9: jz      loc_140062BA4
0x1400628FF: cmp     ebx, r14d
0x140062902: jnb     loc_140062BA4
0x140062908: mov     edx, r12d
0x14006290B: lea     rax, [rsp+200h+var_1B0]
0x140062910: xor     r9d, r9d
0x140062913: mov     [rsp+200h+var_1C8], rax
0x140062918: and     [rsp+200h+var_1D0], 0
0x14006291E: and     [rsp+200h+var_1D8], 0
0x140062924: or      [rsp+200h+var_1E0], 0FFFFFFFFh
0x140062929: mov     ecx, ebx
0x14006292B: lea     r8d, [r9+2]
0x14006292F: add     rcx, r12
0x140062932: sub     edx, ecx
0x140062934: add     edx, r14d
0x140062937: call    InitPESectionReadContext
0x14006293C: mov     ecx, 914h; Index
0x140062941: xor     sil, sil
0x140062944: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140062949: xor     edi, edi
0x14006294B: mov     r15d, 558h
0x140062951: lea     ebx, [rdi+1]
0x140062954: cmp     eax, 4A61h
0x140062959: jnb     loc_140062AD8
0x14006295F: lea     rdx, [rbp+100h+var_160]
0x140062963: lea     rcx, [rsp+200h+var_1B0]
0x140062968: call    ReadPESectionEntry
0x14006296D: test    eax, eax
0x14006296F: jnz     loc_140062BA4
0x140062975: mov     eax, [rbp+100h+var_70]
0x14006297B: mov     rcx, [rsp+200h+var_1A8]
0x140062980: mov     r8d, 473h
0x140062986: add     rcx, rax
0x140062989: mov     rax, [rbp+100h+var_48]
0x140062990: mov     [rsp+200h+var_1A8], rcx
0x140062995: movzx   edx, word ptr [rax+6]
0x140062999: movzx   eax, dx
0x14006299C: sub     ax, r8w
0x1400629A0: cmp     ax, bx
0x1400629A3: jbe     loc_140062AC5
0x1400629A9: cmp     sil, bl
0x1400629AC: jnz     loc_140062AC8
0x1400629B2: cmp     r15w, dx
0x1400629B6: jnz     loc_140062AC8
0x1400629BC: mov     eax, [rbp+100h+var_128]
0x1400629BF: xor     r15d, r15d
0x1400629C2: sub     eax, r12d
0x1400629C5: add     eax, ecx
0x1400629C7: test    eax, eax
0x1400629C9: jz      loc_140062BA4
0x1400629CF: cmp     eax, r14d
0x1400629D2: jnb     loc_140062BA4
0x1400629D8: mov     ecx, eax
0x1400629DA: mov     edx, r12d
0x1400629DD: lea     rax, [rsp+200h+var_1B0]
0x1400629E2: mov     [rsp+200h+var_1C8], rax
0x1400629E7: add     rcx, r12
0x1400629EA: mov     [rsp+200h+var_1D0], r15
0x1400629EF: sub     edx, ecx
0x1400629F1: lea     r8d, [r15+2]
0x1400629F5: xor     r9d, r9d
0x1400629F8: add     edx, r14d
0x1400629FB: mov     [rsp+200h+var_1D8], r15
0x140062A00: or      [rsp+200h+var_1E0], 0FFFFFFFFh
0x140062A05: call    InitPESectionReadContext
0x140062A0A: mov     sil, [rsp+200h+var_1C0]
0x140062A0F: mov     edi, r15d
0x140062A12: lea     rdx, [rbp+100h+var_160]
0x140062A16: lea     rcx, [rsp+200h+var_1B0]
0x140062A1B: call    ReadPESectionEntry
0x140062A20: test    eax, eax
0x140062A22: jnz     loc_140062BA4
0x140062A28: mov     eax, [rbp+100h+var_70]
0x140062A2E: mov     rcx, [rsp+200h+var_1A8]
0x140062A33: add     rcx, rax
0x140062A36: mov     rax, [rbp+100h+var_48]
0x140062A3D: mov     [rsp+200h+var_1A8], rcx
0x140062A42: movzx   edx, word ptr [rax+6]
0x140062A46: mov     eax, 512h
0x140062A4B: cmp     ax, dx
0x140062A4E: jnz     loc_140062B53
0x140062A54: cmp     [rbp+100h+var_D8], 40000h
0x140062A5C: jnz     loc_140062B86
0x140062A62: cmp     [rbp+100h+var_E8], r15d
0x140062A66: jz      loc_140062B86
0x140062A6C: cmp     [rbp+100h+var_110], 40h ; '@'
0x140062A71: jnz     loc_140062B86
0x140062A77: cmp     [rbp+100h+var_108], ebx
0x140062A7A: jnz     loc_140062B86
0x140062A80: lea     rdx, [rbp+100h+var_160]
0x140062A84: lea     rcx, [rsp+200h+var_1B0]
0x140062A89: call    ReadPESectionEntry
0x140062A8E: test    eax, eax
0x140062A90: jnz     loc_140062B86
0x140062A96: mov     rax, [rbp+100h+var_48]
0x140062A9D: movzx   ecx, word ptr [rax+6]
0x140062AA1: mov     eax, 473h
0x140062AA6: sub     cx, ax
0x140062AA9: cmp     cx, bx
0x140062AAC: ja      loc_140062B86
0x140062AB2: mov     eax, [rbp+100h+var_70]
0x140062AB8: mov     sil, bl
0x140062ABB: add     [rsp+200h+var_1A8], rax
0x140062AC0: jmp     loc_140062B86
0x140062AC5: mov     sil, bl
0x140062AC8: add     edi, ebx
0x140062ACA: cmp     edi, 64h ; 'd'
0x140062ACD: jnb     loc_140062BA4
0x140062AD3: jmp     loc_14006295F
0x140062AD8: lea     rdx, [rbp+100h+var_160]
0x140062ADC: lea     rcx, [rsp+200h+var_1B0]
0x140062AE1: call    ReadPESectionEntry
0x140062AE6: test    eax, eax
0x140062AE8: jnz     loc_140062BA4
0x140062AEE: mov     eax, [rbp+100h+var_70]
0x140062AF4: mov     rcx, [rsp+200h+var_1A8]
0x140062AF9: add     rcx, rax
0x140062AFC: mov     rax, [rbp+100h+var_48]
0x140062B03: mov     [rsp+200h+var_1A8], rcx
0x140062B08: movzx   edx, word ptr [rax+6]
0x140062B0C: mov     eax, 510h
0x140062B11: cmp     ax, dx
0x140062B14: jnz     short loc_140062B3B
0x140062B16: cmp     [rbp+100h+var_110], 40h ; '@'
0x140062B1B: jnz     short loc_140062B3B
0x140062B1D: test    [rbp+100h+var_140], 8
0x140062B21: jz      short loc_140062B3B
0x140062B23: cmp     [rbp+100h+var_D8], 20000h
0x140062B2B: jnz     short loc_140062B3B
0x140062B2D: cmp     [rbp+100h+var_E8], 188h
0x140062B34: jnz     short loc_140062B3B
0x140062B36: mov     sil, bl
0x140062B39: jmp     short loc_140062B4A
0x140062B3B: cmp     sil, bl
0x140062B3E: jnz     short loc_140062B4A
0x140062B40: cmp     r15w, dx
0x140062B44: jz      loc_1400629BC
0x140062B4A: add     edi, ebx
0x140062B4C: cmp     edi, 64h ; 'd'
0x140062B4F: jnb     short loc_140062BA4
0x140062B51: jmp     short loc_140062AD8
0x140062B53: cmp     sil, bl
0x140062B56: jnz     short loc_140062B86
0x140062B58: mov     eax, 510h
0x140062B5D: cmp     ax, dx
0x140062B60: jnz     short loc_140062B86
0x140062B62: cmp     [rbp+100h+var_D8], 40000h
0x140062B6A: jnz     short loc_140062B86
0x140062B6C: mov     eax, [rbp+100h+var_E8]
0x140062B6F: test    eax, eax
0x140062B71: jz      short loc_140062B86
0x140062B73: cmp     [rbp+100h+var_110], 40h ; '@'
0x140062B78: jnz     short loc_140062B86
0x140062B7A: sub     eax, r12d
0x140062B7D: add     eax, ecx
0x140062B7F: jz      short loc_140062B86
0x140062B81: cmp     eax, r14d
0x140062B84: jb      short loc_140062B95
0x140062B86: add     edi, ebx
0x140062B88: cmp     edi, 0C8h
0x140062B8E: jnb     short loc_140062BA4
0x140062B90: jmp     loc_140062A12
0x140062B95: mov     edx, eax
0x140062B97: mov     ecx, 36Ch; Index
0x140062B9C: add     rdx, r13; Value
0x140062B9F: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140062BA4: mov     rcx, [rbp+100h+var_40]
0x140062BAB: xor     rcx, rsp; StackCookie
0x140062BAE: call    __security_check_cookie
0x140062BB3: mov     rbx, [rsp+200h+arg_10]
0x140062BBB: add     rsp, 1D0h
0x140062BC2: pop     r15
0x140062BC4: pop     r14
0x140062BC6: pop     r13
0x140062BC8: pop     r12
0x140062BCA: pop     rdi
0x140062BCB: pop     rsi
0x140062BCC: pop     rbp
0x140062BCD: retn