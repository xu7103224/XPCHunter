# ReadPESectionEntry  ea=0x14008A54C  size=662
0x14008A54C: mov     [rsp+arg_0], rbx
0x14008A551: mov     [rsp+arg_8], rbp
0x14008A556: mov     [rsp+arg_10], rsi
0x14008A55B: push    rdi
0x14008A55C: push    r12
0x14008A55E: push    r13
0x14008A560: push    r14
0x14008A562: push    r15
0x14008A564: sub     rsp, 20h
0x14008A568: mov     rbx, rdx
0x14008A56B: mov     rdi, rcx
0x14008A56E: mov     r8d, 120h; Size
0x14008A574: xor     edx, edx; Val
0x14008A576: mov     rcx, rbx; Dst
0x14008A579: or      esi, 0FFFFFFFFh
0x14008A57C: call    memset
0x14008A581: mov     byte ptr [rbx+28h], 0FFh
0x14008A585: lea     eax, [rsi+4]
0x14008A588: mov     [rbx+24h], eax
0x14008A58B: xor     r15d, r15d
0x14008A58E: mov     [rbx+20h], r15d
0x14008A592: mov     eax, [rdi+18h]
0x14008A595: mov     ebp, r15d
0x14008A598: mov     [rbx], eax
0x14008A59A: mov     eax, [rdi+1Ch]
0x14008A59D: mov     [rbx+4], eax
0x14008A5A0: mov     eax, [rdi+20h]
0x14008A5A3: mov     [rbx+8], eax
0x14008A5A6: mov     eax, [rdi+40h]
0x14008A5A9: mov     [rbx+110h], eax
0x14008A5AF: mov     rax, [rdi+30h]
0x14008A5B3: mov     [rbx+10h], rax
0x14008A5B7: mov     rax, [rdi+38h]
0x14008A5BB: mov     [rbx+18h], rax
0x14008A5BF: lea     rax, off_1400A3DD0
0x14008A5C6: mov     [rbx+108h], rax
0x14008A5CD: mov     r9, [rdi+8]
0x14008A5D1: mov     r8, [rdi]
0x14008A5D4: cmp     r9, [rdi+10h]
0x14008A5D8: jnb     loc_14008A7C3
0x14008A5DE: lea     r12d, [rsi+2]
0x14008A5E2: lea     r14d, [rsi+3]
0x14008A5E6: lea     r13d, [rsi+5]
0x14008A5EA: movzx   r10d, byte ptr [r9]
0x14008A5EE: mov     eax, r10d
0x14008A5F1: lea     rcx, [r10+r10*4]
0x14008A5F5: lea     rdx, [r8+rcx*4]
0x14008A5F9: movzx   eax, word ptr [rdx+4]
0x14008A5FD: cmp     ax, 6
0x14008A601: ja      loc_14008A727
0x14008A607: mov     ecx, 0FFFFh
0x14008A60C: cmp     cx, ax
0x14008A60F: jz      loc_14008A720
0x14008A615: mov     ecx, [rbx+20h]
0x14008A618: add     ebp, r12d
0x14008A61B: test    cl, 40h
0x14008A61E: jnz     loc_14008A717
0x14008A624: mov     r11d, 5
0x14008A62A: cmp     r11w, ax
0x14008A62E: jz      loc_14008A6E9
0x14008A634: and     ecx, 0FFFFFFBFh
0x14008A637: mov     [rbx+28h], al
0x14008A63A: mov     [rbx+20h], ecx
0x14008A63D: cmp     r15w, ax
0x14008A641: jnz     short loc_14008A663
0x14008A643: test    r14b, cl
0x14008A646: jnz     loc_14008A717
0x14008A64C: or      ecx, r14d
0x14008A64F: cmp     [rbx], r15d
0x14008A652: mov     eax, r15d
0x14008A655: setz    al
0x14008A658: mov     [rbx+20h], ecx
0x14008A65B: mov     [rbx+8], eax
0x14008A65E: jmp     loc_14008A701
0x14008A663: cmp     r12w, ax
0x14008A667: jnz     short loc_14008A692
0x14008A669: test    r12b, cl
0x14008A66C: jnz     loc_14008A717
0x14008A672: or      ecx, r12d
0x14008A675: mov     [rbx+20h], ecx
0x14008A678: mov     ecx, [rbx]
0x14008A67A: test    ecx, ecx
0x14008A67C: jnz     short loc_14008A684
0x14008A67E: mov     [rbx+4], r12d
0x14008A682: jmp     short loc_14008A701
0x14008A684: mov     eax, r15d
0x14008A687: cmp     ecx, r12d
0x14008A68A: setnz   al
0x14008A68D: mov     [rbx+4], eax
0x14008A690: jmp     short loc_14008A701
0x14008A692: cmp     r13w, ax
0x14008A696: jnz     short loc_14008A6A2
0x14008A698: test    cl, 30h
0x14008A69B: jnz     short loc_14008A717
0x14008A69D: or      ecx, 10h
0x14008A6A0: jmp     short loc_14008A6E4
0x14008A6A2: mov     r11d, 3
0x14008A6A8: cmp     r11w, ax
0x14008A6AC: jnz     short loc_14008A6B8
0x14008A6AE: test    cl, 30h
0x14008A6B1: jnz     short loc_14008A717
0x14008A6B3: or      ecx, 20h
0x14008A6B6: jmp     short loc_14008A6E4
0x14008A6B8: cmp     r14w, ax
0x14008A6BC: jnz     short loc_14008A6DC
0x14008A6BE: test    cl, 8
0x14008A6C1: jnz     short loc_14008A717
0x14008A6C3: movzx   eax, word ptr [rdx+8]
0x14008A6C7: add     eax, 0FFFFFFF7h
0x14008A6CA: mov     [rbx+24h], eax
0x14008A6CD: cmp     [rbx], r14d
0x14008A6D0: jnz     short loc_14008A6D7
0x14008A6D2: cmp     eax, r13d
0x14008A6D5: jl      short loc_14008A701
0x14008A6D7: or      ecx, 8
0x14008A6DA: jmp     short loc_14008A6E4
0x14008A6DC: test    r13b, cl
0x14008A6DF: jnz     short loc_14008A717
0x14008A6E1: or      ecx, r13d
0x14008A6E4: mov     [rbx+20h], ecx
0x14008A6E7: jmp     short loc_14008A701
0x14008A6E9: or      ecx, 40h
0x14008A6EC: mov     [rbx+20h], ecx
0x14008A6EF: movzx   eax, word ptr [rdx+8]
0x14008A6F3: add     eax, 0FFFFFFCEh
0x14008A6F6: mov     [rbx+2Ch], eax
0x14008A6F9: test    al, 8
0x14008A6FB: jz      short loc_14008A701
0x14008A6FD: mov     [rbx+8], r14d
0x14008A701: add     r9, r12
0x14008A704: cmp     r9, [rdi+10h]
0x14008A708: jb      loc_14008A5EA
0x14008A70E: or      [rbx+100h], r13d
0x14008A715: jmp     short loc_14008A727
0x14008A717: or      [rbx+100h], r14d
0x14008A71E: jmp     short loc_14008A727
0x14008A720: or      [rbx+100h], r12d
0x14008A727: mov     eax, [rbx+100h]
0x14008A72D: test    eax, eax
0x14008A72F: jnz     short loc_14008A790
0x14008A731: mov     [rbx+0E4h], r10b
0x14008A738: mov     rax, [rdi+28h]
0x14008A73C: add     rax, [rdi+8]
0x14008A740: mov     [rbx+2Ah], bp
0x14008A744: mov     [rbx+0E8h], rax
0x14008A74B: mov     rdx, [rdi+10h]
0x14008A74F: movzx   eax, r10b
0x14008A753: lea     rcx, [rax+rax*4]
0x14008A757: lea     r8, [r8+rcx*4]
0x14008A75B: lea     rcx, [r9+1]
0x14008A75F: mov     r9, rbx
0x14008A762: call    DispatchInstructionDecode
0x14008A767: cmp     eax, esi
0x14008A769: jz      short loc_14008A787
0x14008A76B: inc     eax
0x14008A76D: add     eax, ebp
0x14008A76F: mov     [rbx+0F0h], eax
0x14008A775: mov     eax, [rbx+20h]
0x14008A778: test    r13b, al
0x14008A77B: jz      short loc_14008A7C0
0x14008A77D: mov     rcx, rbx
0x14008A780: call    ClassifyPESectionType
0x14008A785: jmp     short loc_14008A7C0
0x14008A787: or      [rbx+100h], r13d
0x14008A78E: jmp     short loc_14008A7C3
0x14008A790: cmp     eax, r14d
0x14008A793: jnz     short loc_14008A7C3
0x14008A795: mov     rax, [rdi+28h]
0x14008A799: add     rax, [rdi+8]
0x14008A79D: mov     [rbx+100h], r15d
0x14008A7A4: mov     [rbx+0F0h], r12d
0x14008A7AB: mov     [rbx+0E8h], rax
0x14008A7B2: lea     rax, [r8+0B40h]
0x14008A7B9: mov     [rbx+118h], rax
0x14008A7C0: mov     esi, r15d
0x14008A7C3: mov     rbx, [rsp+48h+arg_0]
0x14008A7C8: mov     rbp, [rsp+48h+arg_8]
0x14008A7CD: mov     eax, esi
0x14008A7CF: mov     rsi, [rsp+48h+arg_10]
0x14008A7D4: add     rsp, 20h
0x14008A7D8: pop     r15
0x14008A7DA: pop     r14
0x14008A7DC: pop     r13
0x14008A7DE: pop     r12
0x14008A7E0: pop     rdi
0x14008A7E1: retn