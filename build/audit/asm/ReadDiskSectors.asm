0x140078a30  48 8b c4                 mov      rax, rsp
0x140078a33  48 89 58 08              mov      qword ptr [rax + 8], rbx
0x140078a37  48 89 70 10              mov      qword ptr [rax + 0x10], rsi
0x140078a3b  48 89 78 18              mov      qword ptr [rax + 0x18], rdi
0x140078a3f  55                       push     rbp
0x140078a40  41 54                    push     r12
0x140078a42  41 55                    push     r13
0x140078a44  41 56                    push     r14
0x140078a46  41 57                    push     r15
0x140078a48  48 8d a8 28 ff ff ff     lea      rbp, [rax - 0xd8]
0x140078a4f  48 81 ec b0 01 00 00     sub      rsp, 0x1b0
0x140078a56  48 8b 05 2b b6 02 00     mov      rax, qword ptr [rip + 0x2b62b]
0x140078a5d  48 33 c4                 xor      rax, rsp
0x140078a60  48 89 85 a0 00 00 00     mov      qword ptr [rbp + 0xa0], rax
0x140078a67  33 c0                    xor      eax, eax
0x140078a69  b9 65 42 00 00           mov      ecx, 0x4265
0x140078a6e  44 8b f8                 mov      r15d, eax
0x140078a71  e8 86 14 fb ff           call     0x140029efc
0x140078a76  b9 2e 43 00 00           mov      ecx, 0x432e
0x140078a7b  48 89 45 c0              mov      qword ptr [rbp - 0x40], rax
0x140078a7f  e8 78 14 fb ff           call     0x140029efc
0x140078a84  b9 31 43 00 00           mov      ecx, 0x4331
0x140078a89  48 89 44 24 78           mov      qword ptr [rsp + 0x78], rax
0x140078a8e  e8 69 14 fb ff           call     0x140029efc
0x140078a93  b9 ea 41 00 00           mov      ecx, 0x41ea
0x140078a98  4c 8b e8                 mov      r13, rax
0x140078a9b  48 89 45 98              mov      qword ptr [rbp - 0x68], rax
0x140078a9f  e8 58 14 fb ff           call     0x140029efc
0x140078aa4  b9 34 43 00 00           mov      ecx, 0x4334
0x140078aa9  48 8b f0                 mov      rsi, rax
0x140078aac  48 89 45 b0              mov      qword ptr [rbp - 0x50], rax
0x140078ab0  e8 47 14 fb ff           call     0x140029efc
0x140078ab5  b9 59 42 00 00           mov      ecx, 0x4259
0x140078aba  48 8b d8                 mov      rbx, rax
0x140078abd  48 89 45 80              mov      qword ptr [rbp - 0x80], rax
0x140078ac1  e8 36 14 fb ff           call     0x140029efc
0x140078ac6  b9 5c 42 00 00           mov      ecx, 0x425c
0x140078acb  48 89 44 24 68           mov      qword ptr [rsp + 0x68], rax
0x140078ad0  e8 27 14 fb ff           call     0x140029efc
0x140078ad5  b9 5a 41 00 00           mov      ecx, 0x415a
0x140078ada  4c 8b f0                 mov      r14, rax
0x140078add  48 89 45 b8              mov      qword ptr [rbp - 0x48], rax
0x140078ae1  e8 16 14 fb ff           call     0x140029efc
0x140078ae6  b9 c6 41 00 00           mov      ecx, 0x41c6
0x140078aeb  48 8b f8                 mov      rdi, rax
0x140078aee  48 89 45 90              mov      qword ptr [rbp - 0x70], rax
0x140078af2  e8 05 14 fb ff           call     0x140029efc
0x140078af7  b9 23 42 00 00           mov      ecx, 0x4223
0x140078afc  48 89 45 88              mov      qword ptr [rbp - 0x78], rax
0x140078b00  e8 f7 13 fb ff           call     0x140029efc
0x140078b05  41 8d 4f 30              lea      ecx, [r15 + 0x30]
0x140078b09  4c 8b e0                 mov      r12, rax
0x140078b0c  48 89 44 24 58           mov      qword ptr [rsp + 0x58], rax
0x140078b11  e8 e6 13 fb ff           call     0x140029efc
0x140078b16  33 c9                    xor      ecx, ecx
0x140078b18  48 89 45 a0              mov      qword ptr [rbp - 0x60], rax
0x140078b1c  48 39 4c 24 78           cmp      qword ptr [rsp + 0x78], rcx
0x140078b21  0f 84 ee 03 00 00        je       0x140078f15
0x140078b27  4d 85 ed                 test     r13, r13
0x140078b2a  0f 84 e5 03 00 00        je       0x140078f15
0x140078b30  45 33 ed                 xor      r13d, r13d
0x140078b33  48 85 f6                 test     rsi, rsi
0x140078b36  0f 84 d9 03 00 00        je       0x140078f15
0x140078b3c  48 85 db                 test     rbx, rbx
0x140078b3f  0f 84 d0 03 00 00        je       0x140078f15
0x140078b45  4c 39 6c 24 68           cmp      qword ptr [rsp + 0x68], r13
0x140078b4a  0f 84 c5 03 00 00        je       0x140078f15
0x140078b50  4d 85 f6                 test     r14, r14
0x140078b53  0f 84 bc 03 00 00        je       0x140078f15
0x140078b59  48 85 ff                 test     rdi, rdi
0x140078b5c  0f 84 b3 03 00 00        je       0x140078f15
0x140078b62  4c 39 6d 88              cmp      qword ptr [rbp - 0x78], r13
0x140078b66  0f 84 a9 03 00 00        je       0x140078f15
0x140078b6c  4d 85 e4                 test     r12, r12
0x140078b6f  0f 84 a0 03 00 00        je       0x140078f15
0x140078b75  83 f8 ff                 cmp      eax, -1
0x140078b78  0f 84 97 03 00 00        je       0x140078f15
0x140078b7e  b9 50 00 6f 00           mov      ecx, 0x6f0050
0x140078b83  ba 00 20 00 00           mov      edx, 0x2000
0x140078b88  48 c7 45 44 72 00 74 00  mov      qword ptr [rbp + 0x44], 0x740072
0x140078b90  89 4d 40                 mov      dword ptr [rbp + 0x40], ecx
0x140078b93  89 8d 90 00 00 00        mov      dword ptr [rbp + 0x90], ecx
0x140078b99  41 8d 4f 01              lea      ecx, [r15 + 1]
0x140078b9d  c7 45 60 41 00 4c 00     mov      dword ptr [rbp + 0x60], 0x4c0041
0x140078ba4  c7 45 64 50 00 43 00     mov      dword ptr [rbp + 0x64], 0x430050
0x140078bab  c7 45 68 20 00 50 00     mov      dword ptr [rbp + 0x68], 0x500020
0x140078bb2  c7 45 6c 6f 00 72 00     mov      dword ptr [rbp + 0x6c], 0x72006f
0x140078bb9  c7 45 70 74 00 00 00     mov      dword ptr [rbp + 0x70], 0x74
0x140078bc0  c7 45 78 5c 00 57 00     mov      dword ptr [rbp + 0x78], 0x57005c
0x140078bc7  c7 45 7c 69 00 6e 00     mov      dword ptr [rbp + 0x7c], 0x6e0069
0x140078bce  c7 85 80 00 00 00 64 00 6f 00 mov      dword ptr [rbp + 0x80], 0x6f0064
0x140078bd8  c7 85 84 00 00 00 77 00 73 00 mov      dword ptr [rbp + 0x84], 0x730077
0x140078be2  c7 85 88 00 00 00 5c 00 41 00 mov      dword ptr [rbp + 0x88], 0x41005c
0x140078bec  c7 85 8c 00 00 00 70 00 69 00 mov      dword ptr [rbp + 0x8c], 0x690070
0x140078bf6  48 c7 85 94 00 00 00 72 00 74 00 mov      qword ptr [rbp + 0x94], 0x740072
0x140078c01  c7 45 50 63 73 72 73     mov      dword ptr [rbp + 0x50], 0x73727363
0x140078c08  c7 45 54 73 2e 65 78     mov      dword ptr [rbp + 0x54], 0x78652e73
0x140078c0f  c7 45 58 65 00 00 00     mov      dword ptr [rbp + 0x58], 0x65
0x140078c16  e8 e5 ed ff ff           call     0x140077a00
0x140078c1b  48 8b f8                 mov      rdi, rax
0x140078c1e  48 85 c0                 test     rax, rax
0x140078c21  0f 84 ee 02 00 00        je       0x140078f15
0x140078c27  41 8d 4f 10              lea      ecx, [r15 + 0x10]
0x140078c2b  e8 c8 1b 00 00           call     0x14007a7f8
0x140078c30  4c 8b f0                 mov      r14, rax
0x140078c33  48 89 45 c8              mov      qword ptr [rbp - 0x38], rax
0x140078c37  48 85 c0                 test     rax, rax
0x140078c3a  0f 84 cd 02 00 00        je       0x140078f0d
0x140078c40  8b 00                    mov      eax, dword ptr [rax]
0x140078c42  41 8b dd                 mov      ebx, r13d
0x140078c45  49 8d 76 08              lea      rsi, [r14 + 8]
0x140078c49  89 44 24 64              mov      dword ptr [rsp + 0x64], eax
0x140078c4d  89 5c 24 60              mov      dword ptr [rsp + 0x60], ebx
0x140078c51  85 c0                    test     eax, eax
0x140078c53  0f 84 ac 02 00 00        je       0x140078f05
0x140078c59  44 8a 6c 24 40           mov      r13b, byte ptr [rsp + 0x40]
0x140078c5e  44 8b 74 24 64           mov      r14d, dword ptr [rsp + 0x64]
0x140078c63  b8 00 02 00 00           mov      eax, 0x200
0x140078c68  33 c9                    xor      ecx, ecx
0x140078c6a  48 89 4d e8              mov      qword ptr [rbp - 0x18], rcx
0x140078c6e  48 89 4d f0              mov      qword ptr [rbp - 0x10], rcx
0x140078c72  0f 57 c0                 xorps    xmm0, xmm0
0x140078c75  c7 45 e0 30 00 00 00     mov      dword ptr [rbp - 0x20], 0x30
0x140078c7c  89 45 f8                 mov      dword ptr [rbp - 8], eax
0x140078c7f  4c 8d 4d d0              lea      r9, [rbp - 0x30]
0x140078c83  f3 0f 7f 45 00           movdqu   xmmword ptr [rbp], xmm0
0x140078c88  0f b7 06                 movzx    eax, word ptr [rsi]
0x140078c8b  48 89 4d d8              mov      qword ptr [rbp - 0x28], rcx
0x140078c8f  4c 8d 45 e0              lea      r8, [rbp - 0x20]
0x140078c93  48 8d 4c 24 70           lea      rcx, [rsp + 0x70]
0x140078c98  ba 40 00 00 00           mov      edx, 0x40
0x140078c9d  48 89 45 d0              mov      qword ptr [rbp - 0x30], rax
0x140078ca1  ff 54 24 78              call     qword ptr [rsp + 0x78]
0x140078ca5  33 c9                    xor      ecx, ecx
0x140078ca7  85 c0                    test     eax, eax
0x140078ca9  0f 88 c8 01 00 00        js       0x140078e77
0x140078caf  48 89 4c 24 48           mov      qword ptr [rsp + 0x48], rcx
0x140078cb4  b9 14 09 00 00           mov      ecx, 0x914
0x140078cb9  e8 3e 12 fb ff           call     0x140029efc
0x140078cbe  0f b7 56 06              movzx    edx, word ptr [rsi + 6]
0x140078cc2  45 33 e4                 xor      r12d, r12d
0x140078cc5  3d b0 1d 00 00           cmp      eax, 0x1db0
0x140078cca  41 8b cc                 mov      ecx, r12d
0x140078ccd  b8 00 02 00 00           mov      eax, 0x200
0x140078cd2  0f 43 c8                 cmovae   ecx, eax
0x140078cd5  c7 44 24 30 02 00 00 00  mov      dword ptr [rsp + 0x30], 2
0x140078cdd  4c 8d 4c 24 50           lea      r9, [rsp + 0x50]
0x140078ce2  89 4c 24 28              mov      dword ptr [rsp + 0x28], ecx
0x140078ce6  48 8b 4c 24 70           mov      rcx, qword ptr [rsp + 0x70]
0x140078ceb  49 83 c8 ff              or       r8, 0xffffffffffffffff
0x140078cef  44 89 64 24 20           mov      dword ptr [rsp + 0x20], r12d
0x140078cf4  ff 55 98                 call     qword ptr [rbp - 0x68]
0x140078cf7  8b d8                    mov      ebx, eax
0x140078cf9  85 c0                    test     eax, eax
0x140078cfb  78 08                    js       0x140078d05
0x140078cfd  41 b4 01                 mov      r12b, 1
0x140078d00  e9 b6 00 00 00           jmp      0x140078dbb
0x140078d05  33 c0                    xor      eax, eax
0x140078d07  b9 14 09 00 00           mov      ecx, 0x914
0x140078d0c  44 8a e8                 mov      r13b, al
0x140078d0f  e8 e8 11 fb ff           call     0x140029efc
0x140078d14  3d 70 17 00 00           cmp      eax, 0x1770
0x140078d19  0f 82 9c 00 00 00        jb       0x140078dbb
0x140078d1f  0f b7 0e                 movzx    ecx, word ptr [rsi]
0x140078d22  48 8d 54 24 48           lea      rdx, [rsp + 0x48]
0x140078d27  ff 55 90                 call     qword ptr [rbp - 0x70]
0x140078d2a  8b d8                    mov      ebx, eax
0x140078d2c  85 c0                    test     eax, eax
0x140078d2e  0f 88 30 01 00 00        js       0x140078e64
0x140078d34  0f b7 46 06              movzx    eax, word ptr [rsi + 6]
0x140078d38  b9 14 09 00 00           mov      ecx, 0x914
0x140078d3d  48 89 44 24 50           mov      qword ptr [rsp + 0x50], rax
0x140078d42  e8 b5 11 fb ff           call     0x140029efc
0x140078d47  48 8b 4c 24 48           mov      rcx, qword ptr [rsp + 0x48]
0x140078d4c  3d b0 1d 00 00           cmp      eax, 0x1db0
0x140078d51  72 17                    jb       0x140078d6a
0x140078d53  48 8b 45 c0              mov      rax, qword ptr [rbp - 0x40]
0x140078d57  48 85 c0                 test     rax, rax
0x140078d5a  74 0e                    je       0x140078d6a
0x140078d5c  48 39 08                 cmp      qword ptr [rax], rcx
0x140078d5f  75 09                    jne      0x140078d6a
0x140078d61  48 81 4c 24 50 00 00 00 80 or       qword ptr [rsp + 0x50], 0xffffffff80000000
0x140078d6a  e8 85 f0 ff ff           call     0x140077df4
0x140078d6f  48 8b 4c 24 48           mov      rcx, qword ptr [rsp + 0x48]
0x140078d74  48 8d 55 10              lea      rdx, [rbp + 0x10]
0x140078d78  88 44 24 40              mov      byte ptr [rsp + 0x40], al
0x140078d7c  ff 54 24 68              call     qword ptr [rsp + 0x68]
0x140078d80  48 8b 4c 24 50           mov      rcx, qword ptr [rsp + 0x50]
0x140078d85  33 c0                    xor      eax, eax
0x140078d87  45 33 c9                 xor      r9d, r9d
0x140078d8a  45 33 c0                 xor      r8d, r8d
0x140078d8d  48 89 44 24 28           mov      qword ptr [rsp + 0x28], rax
0x140078d92  48 8d 45 a8              lea      rax, [rbp - 0x58]
0x140078d96  ba 00 00 00 80           mov      edx, 0x80000000
0x140078d9b  48 89 44 24 20           mov      qword ptr [rsp + 0x20], rax
0x140078da0  41 b5 01                 mov      r13b, 1
0x140078da3  ff 55 88                 call     qword ptr [rbp - 0x78]
0x140078da6  33 d2                    xor      edx, edx
0x140078da8  85 c0                    test     eax, eax
0x140078daa  78 0f                    js       0x140078dbb
0x140078dac  48 8b 4d a8              mov      rcx, qword ptr [rbp - 0x58]
0x140078db0  48 3b 4e 08              cmp      rcx, qword ptr [rsi + 8]
0x140078db4  0f 44 da                 cmove    ebx, edx
0x140078db7  ff 54 24 58              call     qword ptr [rsp + 0x58]
0x140078dbb  33 c0                    xor      eax, eax
0x140078dbd  85 db                    test     ebx, ebx
0x140078dbf  0f 88 91 00 00 00        js       0x140078e56
0x140078dc5  48 8b 4c 24 50           mov      rcx, qword ptr [rsp + 0x50]
0x140078dca  48 8b 5d b0              mov      rbx, qword ptr [rbp - 0x50]
0x140078dce  8d 50 02                 lea      edx, [rax + 2]
0x140078dd1  41 b9 00 20 00 00        mov      r9d, 0x2000
0x140078dd7  4c 8b c7                 mov      r8, rdi
0x140078dda  48 89 44 24 20           mov      qword ptr [rsp + 0x20], rax
0x140078ddf  ff d3                    call     rbx
0x140078de1  85 c0                    test     eax, eax
0x140078de3  78 71                    js       0x140078e56
0x140078de5  48 8b 4f 08              mov      rcx, qword ptr [rdi + 8]
0x140078de9  48 85 c9                 test     rcx, rcx
0x140078dec  74 68                    je       0x140078e56
0x140078dee  48 8d 55 40              lea      rdx, [rbp + 0x40]
0x140078df2  41 b8 04 00 00 00        mov      r8d, 4
0x140078df8  e8 0f 4c 00 00           call     0x14007da0c
0x140078dfd  85 c0                    test     eax, eax
0x140078dff  74 17                    je       0x140078e18
0x140078e01  48 8b 4f 08              mov      rcx, qword ptr [rdi + 8]
0x140078e05  48 8d 55 60              lea      rdx, [rbp + 0x60]
0x140078e09  41 b8 09 00 00 00        mov      r8d, 9
0x140078e0f  e8 f8 4b 00 00           call     0x14007da0c
0x140078e14  85 c0                    test     eax, eax
0x140078e16  75 3e                    jne      0x140078e56
0x140078e18  48 8b 4c 24 50           mov      rcx, qword ptr [rsp + 0x50]
0x140078e1d  33 c0                    xor      eax, eax
0x140078e1f  41 b9 00 20 00 00        mov      r9d, 0x2000
0x140078e25  8d 50 01                 lea      edx, [rax + 1]
0x140078e28  4c 8b c7                 mov      r8, rdi
0x140078e2b  48 89 44 24 20           mov      qword ptr [rsp + 0x20], rax
0x140078e30  ff d3                    call     rbx
0x140078e32  85 c0                    test     eax, eax
0x140078e34  78 20                    js       0x140078e56
0x140078e36  48 8b 4f 08              mov      rcx, qword ptr [rdi + 8]
0x140078e3a  48 85 c9                 test     rcx, rcx
0x140078e3d  74 17                    je       0x140078e56
0x140078e3f  48 8d 55 78              lea      rdx, [rbp + 0x78]
0x140078e43  41 b8 10 00 00 00        mov      r8d, 0x10
0x140078e49  e8 4e 4b 00 00           call     0x14007d99c
0x140078e4e  85 c0                    test     eax, eax
0x140078e50  75 04                    jne      0x140078e56
0x140078e52  44 0f b7 3e              movzx    r15d, word ptr [rsi]
0x140078e56  41 80 fc 01              cmp      r12b, 1
0x140078e5a  75 5d                    jne      0x140078eb9
0x140078e5c  48 8b 4c 24 50           mov      rcx, qword ptr [rsp + 0x50]
0x140078e61  ff 55 80                 call     qword ptr [rbp - 0x80]
0x140078e64  4c 8b 64 24 58           mov      r12, qword ptr [rsp + 0x58]
0x140078e69  48 8b 4c 24 70           mov      rcx, qword ptr [rsp + 0x70]
0x140078e6e  ff 55 80                 call     qword ptr [rbp - 0x80]
0x140078e71  8b 5c 24 60              mov      ebx, dword ptr [rsp + 0x60]
0x140078e75  33 c9                    xor      ecx, ecx
0x140078e77  4d 85 ff                 test     r15, r15
0x140078e7a  74 6d                    je       0x140078ee9
0x140078e7c  48 8d 54 24 48           lea      rdx, [rsp + 0x48]
0x140078e81  49 8b cf                 mov      rcx, r15
0x140078e84  ff 55 90                 call     qword ptr [rbp - 0x70]
0x140078e87  33 c9                    xor      ecx, ecx
0x140078e89  85 c0                    test     eax, eax
0x140078e8b  78 59                    js       0x140078ee6
0x140078e8d  8b 4d a0                 mov      ecx, dword ptr [rbp - 0x60]
0x140078e90  48 8d 55 50              lea      rdx, [rbp + 0x50]
0x140078e94  41 b8 10 00 00 00        mov      r8d, 0x10
0x140078e9a  48 03 4c 24 48           add      rcx, qword ptr [rsp + 0x48]
0x140078e9f  e8 7c 49 00 00           call     0x14007d820
0x140078ea4  33 c9                    xor      ecx, ecx
0x140078ea6  85 c0                    test     eax, eax
0x140078ea8  74 57                    je       0x140078f01
0x140078eaa  44 8b f9                 mov      r15d, ecx
0x140078ead  48 8b 4c 24 48           mov      rcx, qword ptr [rsp + 0x48]
0x140078eb2  41 ff d4                 call     r12
0x140078eb5  33 c9                    xor      ecx, ecx
0x140078eb7  eb 30                    jmp      0x140078ee9
0x140078eb9  41 80 fd 01              cmp      r13b, 1
0x140078ebd  75 a5                    jne      0x140078e64
0x140078ebf  48 8d 4d 10              lea      rcx, [rbp + 0x10]
0x140078ec3  ff 55 b8                 call     qword ptr [rbp - 0x48]
0x140078ec6  44 38 6c 24 40           cmp      byte ptr [rsp + 0x40], r13b
0x140078ecb  75 0a                    jne      0x140078ed7
0x140078ecd  48 8b 4c 24 48           mov      rcx, qword ptr [rsp + 0x48]
0x140078ed2  e8 f5 ef ff ff           call     0x140077ecc
0x140078ed7  48 8b 4c 24 48           mov      rcx, qword ptr [rsp + 0x48]
0x140078edc  4c 8b 64 24 58           mov      r12, qword ptr [rsp + 0x58]
0x140078ee1  41 ff d4                 call     r12
0x140078ee4  eb 83                    jmp      0x140078e69
0x140078ee6  4c 8b f9                 mov      r15, rcx
0x140078ee9  ff c3                    inc      ebx
0x140078eeb  48 83 c6 18              add      rsi, 0x18
0x140078eef  b8 00 02 00 00           mov      eax, 0x200
0x140078ef4  89 5c 24 60              mov      dword ptr [rsp + 0x60], ebx
0x140078ef8  41 3b de                 cmp      ebx, r14d
0x140078efb  0f 82 69 fd ff ff        jb       0x140078c6a
0x140078f01  4c 8b 75 c8              mov      r14, qword ptr [rbp - 0x38]
0x140078f05  49 8b ce                 mov      rcx, r14
0x140078f08  e8 27 eb ff ff           call     0x140077a34
0x140078f0d  48 8b cf                 mov      rcx, rdi
0x140078f10  e8 1f eb ff ff           call     0x140077a34
0x140078f15  41 8b c7                 mov      eax, r15d
0x140078f18  48 8b 8d a0 00 00 00     mov      rcx, qword ptr [rbp + 0xa0]
0x140078f1f  48 33 cc                 xor      rcx, rsp
0x140078f22  e8 89 39 01 00           call     0x14008c8b0
0x140078f27  4c 8d 9c 24 b0 01 00 00  lea      r11, [rsp + 0x1b0]
0x140078f2f  49 8b 5b 30              mov      rbx, qword ptr [r11 + 0x30]
0x140078f33  49 8b 73 38              mov      rsi, qword ptr [r11 + 0x38]
0x140078f37  49 8b 7b 40              mov      rdi, qword ptr [r11 + 0x40]
0x140078f3b  49 8b e3                 mov      rsp, r11
0x140078f3e  41 5f                    pop      r15
0x140078f40  41 5e                    pop      r14
0x140078f42  41 5d                    pop      r13
0x140078f44  41 5c                    pop      r12
0x140078f46  5d                       pop      rbp
0x140078f47  c3                       ret      