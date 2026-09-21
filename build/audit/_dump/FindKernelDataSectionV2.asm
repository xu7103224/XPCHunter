# FindKernelDataSectionV2  ea=0x1400130C4  size=551
0x1400130C4: mov     rax, rsp; 查找内核数据节 V2。读取多个全局表数据（PE 基址、镜像基址、节表偏移等），遍历 PE 节表查找数据节，进行版本适配（>= 0x1DB0）。
0x1400130C7: mov     [rax+8], rbx
0x1400130CB: mov     [rax+10h], rsi
0x1400130CF: mov     [rax+18h], rdi
0x1400130D3: mov     [rax+20h], r12
0x1400130D7: push    rbp
0x1400130D8: push    r14
0x1400130DA: push    r15
0x1400130DC: lea     rbp, [rax-0D8h]
0x1400130E3: sub     rsp, 1C0h
0x1400130EA: mov     rax, cs:__security_cookie
0x1400130F1: xor     rax, rsp
0x1400130F4: mov     [rbp+0D0h+var_20], rax
0x1400130FB: mov     ecx, 20h ; ' '; Index
0x140013100: xor     r15b, r15b
0x140013103: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013108: mov     ecx, 21h ; '!'; Index
0x14001310D: mov     r12, rax
0x140013110: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013115: mov     ecx, 3; Index
0x14001311A: mov     rsi, rax
0x14001311D: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013122: mov     ecx, 4222h; Index
0x140013127: mov     rdi, rax
0x14001312A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001312F: mov     ecx, 176h; Index
0x140013134: mov     rbx, rax
0x140013137: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001313C: mov     rcx, rax
0x14001313F: test    r12, r12
0x140013142: jz      loc_1400132BB
0x140013148: test    esi, esi
0x14001314A: jz      loc_1400132BB
0x140013150: test    rdi, rdi
0x140013153: jz      loc_1400132BB
0x140013159: test    ebx, ebx
0x14001315B: jz      loc_1400132BB
0x140013161: cmp     rax, rdi
0x140013164: jbe     loc_1400132BB
0x14001316A: sub     eax, edi
0x14001316C: cmp     eax, esi
0x14001316E: jnb     loc_1400132BB
0x140013174: mov     edx, eax
0x140013176: add     rax, rdi
0x140013179: cmp     rcx, rax
0x14001317C: jnz     loc_1400132BB
0x140013182: lea     rcx, [rdx+r12]
0x140013186: lea     rax, [rsp+1D0h+var_190]
0x14001318B: xor     r9d, r9d
0x14001318E: mov     qword ptr [rsp+1D0h+var_198], rax
0x140013193: and     [rsp+1D0h+var_1A0], 0
0x140013199: and     [rsp+1D0h+var_1A8], 0
0x14001319F: or      dword ptr [rsp+1D0h+var_1B0], 0FFFFFFFFh
0x1400131A4: mov     edx, r12d
0x1400131A7: lea     r8d, [r9+2]
0x1400131AB: sub     edx, ecx
0x1400131AD: add     edx, esi
0x1400131AF: call    InitPESectionReadContext
0x1400131B4: xor     ebx, ebx
0x1400131B6: xor     r14d, r14d
0x1400131B9: lea     rdx, [rbp+0D0h+var_140]
0x1400131BD: lea     rcx, [rsp+1D0h+var_190]
0x1400131C2: call    ReadPESectionEntry
0x1400131C7: test    eax, eax
0x1400131C9: jnz     loc_1400132BB
0x1400131CF: mov     eax, [rbp+0D0h+var_50]
0x1400131D5: add     [rsp+1D0h+var_188], rax
0x1400131DA: mov     rax, [rbp+0D0h+var_28]
0x1400131E1: movzx   ecx, word ptr [rax+6]
0x1400131E5: mov     eax, 43Eh
0x1400131EA: cmp     ax, cx
0x1400131ED: jnz     short loc_140013208
0x1400131EF: cmp     [rbp+0D0h+var_B8], 80000h
0x1400131F7: jnz     short loc_140013208
0x1400131F9: cmp     [rbp+0D0h+var_D0], 2
0x1400131FE: jnz     short loc_140013208
0x140013200: mov     r15b, 1
0x140013203: jmp     loc_140013293
0x140013208: mov     eax, 558h
0x14001320D: cmp     ax, cx
0x140013210: jnz     short loc_140013248
0x140013212: test    [rbp+0D0h+var_F0], 4000000h
0x14001321A: jz      short loc_140013248
0x14001321C: cmp     [rbp+0D0h+var_108], 0
0x140013220: jz      short loc_140013248
0x140013222: mov     ecx, 914h; Index
0x140013227: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001322C: cmp     eax, 4F7Ch
0x140013231: jnz     short loc_140013239
0x140013233: cmp     r15b, 1
0x140013237: jnz     short loc_140013243
0x140013239: mov     ebx, [rbp+0D0h+var_108]
0x14001323C: sub     ebx, r12d
0x14001323F: add     ebx, dword ptr [rsp+1D0h+var_188]
0x140013243: xor     r15b, r15b
0x140013246: jmp     short loc_140013293
0x140013248: mov     eax, 53Dh
0x14001324D: cmp     ax, cx
0x140013250: jnz     short loc_140013293
0x140013252: cmp     [rbp+0D0h+var_B8], 800000h
0x14001325A: jnz     short loc_140013293
0x14001325C: cmp     dword ptr [rbp+0D0h+var_D0], 11h
0x140013260: jnz     short loc_140013293
0x140013262: cmp     [rbp+0D0h+var_F0], 20h ; ' '
0x140013267: jnz     short loc_140013293
0x140013269: cmp     [rbp+0D0h+var_E8], 1
0x14001326D: jnz     short loc_140013293
0x14001326F: lea     rdx, [rbp+0D0h+var_140]
0x140013273: lea     rcx, [rsp+1D0h+var_190]
0x140013278: call    ReadPESectionEntry
0x14001327D: test    eax, eax
0x14001327F: jnz     short loc_140013293
0x140013281: mov     rax, [rbp+0D0h+var_28]
0x140013288: mov     ecx, 558h
0x14001328D: cmp     cx, [rax+6]
0x140013291: jz      short loc_1400132A4
0x140013293: inc     r14d
0x140013296: cmp     r14d, 200h
0x14001329D: jnb     short loc_1400132BB
0x14001329F: jmp     loc_1400131B9
0x1400132A4: test    ebx, ebx
0x1400132A6: jz      short loc_1400132BB
0x1400132A8: cmp     ebx, esi
0x1400132AA: jnb     short loc_1400132BB
0x1400132AC: mov     edx, ebx
0x1400132AE: mov     ecx, 180h; Index
0x1400132B3: add     rdx, rdi; Value
0x1400132B6: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400132BB: mov     rcx, [rbp+0D0h+var_20]
0x1400132C2: xor     rcx, rsp; StackCookie
0x1400132C5: call    __security_check_cookie
0x1400132CA: lea     r11, [rsp+1D0h+var_10]
0x1400132D2: mov     rbx, [r11+20h]
0x1400132D6: mov     rsi, [r11+28h]
0x1400132DA: mov     rdi, [r11+30h]
0x1400132DE: mov     r12, [r11+38h]
0x1400132E2: mov     rsp, r11
0x1400132E5: pop     r15
0x1400132E7: pop     r14
0x1400132E9: pop     rbp
0x1400132EA: retn