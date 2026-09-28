# InitImageNotify  ea=0x1400723EC  size=690
0x1400723EC: mov     rax, rsp
0x1400723EF: mov     [rax+8], rbx
0x1400723F3: mov     [rax+10h], rsi
0x1400723F7: mov     [rax+18h], rdi
0x1400723FB: mov     [rax+20h], r12
0x1400723FF: push    rbp
0x140072400: push    r14
0x140072402: push    r15
0x140072404: lea     rbp, [rax-38h]
0x140072408: sub     rsp, 120h
0x14007240F: mov     rax, cs:__security_cookie
0x140072416: xor     rax, rsp
0x140072419: mov     [rbp+30h+var_20], rax
0x14007241D: mov     ecx, 61h ; 'a'; Index
0x140072422: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072427: mov     rbx, rax
0x14007242A: call    cs:IoGetCurrentProcess
0x140072430: xor     r12d, r12d
0x140072433: cmp     rax, rbx
0x140072436: cmovz   rbx, r12
0x14007243A: test    rbx, rbx
0x14007243D: jz      short loc_14007244C
0x14007243F: lea     rdx, [rsp+130h+ApcState]; ApcState
0x140072444: mov     rcx, rbx; PROCESS
0x140072447: call    KeStackAttachProcess
0x14007244C: mov     ecx, 21h ; '!'; Index
0x140072451: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072456: mov     ecx, 3; Index
0x14007245B: mov     r15, rax
0x14007245E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072463: mov     r14, rax
0x140072466: test    r15d, r15d
0x140072469: jz      loc_14007265D
0x14007246F: test    rax, rax
0x140072472: jz      loc_14007265D
0x140072478: lea     rcx, [rsp+130h+Dst]; Dst
0x14007247D: xor     edx, edx; Val
0x14007247F: mov     r8d, 0B4h; Size
0x140072485: call    memset
0x14007248A: mov     [rsp+130h+Dst], 41F2h
0x140072492: mov     [rsp+130h+Index], 16Eh
0x14007249A: mov     [rsp+130h+var_D8], 39h ; '9'
0x1400724A2: mov     [rsp+130h+var_D4], 41F5h
0x1400724AA: mov     [rsp+130h+var_D0], 16Fh
0x1400724B2: mov     [rsp+130h+var_CC], 3Ah ; ':'
0x1400724BA: mov     [rsp+130h+var_C8], 41F8h
0x1400724C2: mov     [rsp+130h+var_C4], 170h
0x1400724CA: mov     [rsp+130h+var_C0], 3Bh ; ';'
0x1400724D2: mov     [rsp+130h+var_BC], 41FBh
0x1400724DA: mov     [rsp+130h+var_B8], 171h
0x1400724E2: mov     [rsp+130h+var_B4], 3Ch ; '<'
0x1400724EA: mov     [rbp+30h+var_B0], 4204h
0x1400724F1: mov     [rbp+30h+var_AC], 172h
0x1400724F8: mov     [rbp+30h+var_A8], 3Dh ; '='
0x1400724FF: mov     [rbp+30h+var_A4], 4207h
0x140072506: mov     [rbp+30h+var_A0], 173h
0x14007250D: mov     [rbp+30h+var_9C], 3Eh ; '>'
0x140072514: mov     [rbp+30h+var_98], 420Ah
0x14007251B: mov     [rbp+30h+var_94], 174h
0x140072522: mov     [rbp+30h+var_90], 3Fh ; '?'
0x140072529: mov     [rbp+30h+var_8C], 420Dh
0x140072530: mov     [rbp+30h+var_88], 175h
0x140072537: mov     [rbp+30h+var_84], 40h ; '@'
0x14007253E: mov     [rbp+30h+var_80], 4210h
0x140072545: mov     [rbp+30h+var_7C], 176h
0x14007254C: mov     [rbp+30h+var_78], 41h ; 'A'
0x140072553: mov     [rbp+30h+var_74], 4213h
0x14007255A: mov     [rbp+30h+var_70], 177h
0x140072561: mov     [rbp+30h+var_6C], 42h ; 'B'
0x140072568: mov     [rbp+30h+var_68], 4216h
0x14007256F: mov     [rbp+30h+var_64], 178h
0x140072576: mov     [rbp+30h+var_60], 43h ; 'C'
0x14007257D: mov     [rbp+30h+var_5C], 42ACh
0x140072584: mov     [rbp+30h+var_58], 290h
0x14007258B: mov     [rbp+30h+var_54], 63h ; 'c'
0x140072592: mov     [rbp+30h+var_50], 42AFh
0x140072599: mov     [rbp+30h+var_4C], 291h
0x1400725A0: mov     [rbp+30h+var_48], 64h ; 'd'
0x1400725A7: mov     [rbp+30h+var_44], 42B2h
0x1400725AE: mov     [rbp+30h+var_40], 292h
0x1400725B5: mov     [rbp+30h+var_3C], 65h ; 'e'
0x1400725BC: mov     esi, r12d
0x1400725BF: mov     eax, esi
0x1400725C1: lea     rdi, [rax+rax*2]
0x1400725C5: mov     ecx, [rsp+rdi*4+130h+Dst]
0x1400725C9: test    ecx, ecx
0x1400725CB: jnz     short loc_1400725DB
0x1400725CD: cmp     [rsp+rdi*4+130h+Index], r12d
0x1400725D2: jnz     short loc_1400725DB
0x1400725D4: cmp     [rsp+rdi*4+130h+var_D8], r12d
0x1400725D9: jz      short loc_140072606
0x1400725DB: call    FindKernelPESectionByType
0x1400725E0: test    eax, eax
0x1400725E2: jz      short loc_140072602
0x1400725E4: mov     ecx, eax
0x1400725E6: call    ResolveSyscallToAddress
0x1400725EB: test    eax, eax
0x1400725ED: jz      short loc_140072602
0x1400725EF: cmp     eax, r15d
0x1400725F2: jnb     short loc_140072602
0x1400725F4: mov     ecx, [rsp+rdi*4+130h+Index]; Index
0x1400725F8: mov     edx, eax
0x1400725FA: add     rdx, r14; Value
0x1400725FD: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140072602: inc     esi
0x140072604: jmp     short loc_1400725BF
0x140072606: call    SelectMiniFilterCleanupCallback; 选择 Minifilter 清理回调。版本 >= 0x4A61 时调用 MiniFilterPostWrite，否则调用 MiniFilterPreCleanup。
0x14007260B: call    FindKernelDataSectionForReadMemory
0x140072610: call    FindKernelDataSectionV3Dispatch; 内核数据节 V3 查找分发。版本检查（>= 0x1DB0），条件满足时调用 ParseNtKernelDataSectionsV2。
0x140072615: call    SelectMiniFilterCallbackByVersion; 根据版本选择 Minifilter 回调。版本 <= 0x23F0 时调用 MiniFilterPostCreate，>= 0x42EE 时调用 MiniFilterPreCreate，否则调用 MiniFilterPreRead。
0x14007261A: call    SelectMiniFilterWriteReadCallback; 选择 Minifilter 写/读回调。版本 > 0x23F0 时调用 MiniFilterPreWrite，否则调用 MiniFilterPostRead。
0x14007261F: call    FindKernelDataSectionForStringParam
0x140072624: call    FindKernelDataSectionForOpenSection
0x140072629: call    FindKernelDataSectionV2Dispatch; 内核数据节 V2 查找分发。版本检查（>= 0x1DB0），条件满足时调用 FindKernelDataSectionV2。
0x14007262E: call    FindKernelDataSectionDispatch; 内核数据节查找分发。根据版本号选择不同的查找策略，版本 0x1DB0-0x1DB1 时调用 FindKernelDataSectionByCode。
0x140072633: call    ClearImageNotifySectionOffset
0x140072638: mov     ecx, 914h; Index
0x14007263D: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072642: cmp     eax, 1770h
0x140072647: jb      short loc_14007265D
0x140072649: call    FindKernelInitSection; 查找内核 INIT 节。遍历 PE 文件的节表查找 INIT 节（标志 0x545 为 INIT 节），计算 INIT 节结束位置，写入全局表 GT 索引 0x183。
0x14007264E: call    FindKernelDataSectionByDebug
0x140072653: call    FindKernelDataSectionByData; 通过 DATA 节查找内核数据节。遍历 PE 节表匹配子类型（2=CODE, 9=DATA, 1=混合），定位数据节偏移，写入全局表 GT 索引 0x197 和 0x912。
0x140072658: call    InitImageNotifyWin7; Win7 镜像通知初始化分发。版本检查（>= 0x1DB0），条件满足时调用 InitImageNotifyCallbackWin7。
0x14007265D: call    SelectMiniFilterDirEnumCallback; 选择 Minifilter 目录枚举回调。版本 < 0x23F0 时调用 MiniFilterPreDirEnum，>= 0x2800 时调用 MiniFilterPreClose，否则调用 MiniFilterPreSetInfo。
0x140072662: test    rbx, rbx
0x140072665: jz      short loc_140072671
0x140072667: lea     rcx, [rsp+130h+ApcState]; ApcState
0x14007266C: call    KeUnstackDetachProcess
0x140072671: mov     rcx, [rbp+30h+var_20]
0x140072675: xor     rcx, rsp; StackCookie
0x140072678: call    __security_check_cookie
0x14007267D: lea     r11, [rsp+130h+var_10]
0x140072685: mov     rbx, [r11+20h]
0x140072689: mov     rsi, [r11+28h]
0x14007268D: mov     rdi, [r11+30h]
0x140072691: mov     r12, [r11+38h]
0x140072695: mov     rsp, r11
0x140072698: pop     r15
0x14007269A: pop     r14
0x14007269C: pop     rbp
0x14007269D: retn