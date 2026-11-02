; ============================================================================
; sgdt.asm — 读取 GDTR
;
; 原版驱动 0x14000171F 的 ReadGdtr 只有两条指令：
;     sgdt fword ptr [rcx]
;     ret
;
; MSVC 在 x64 上提供 __sidt 但不提供 __sgdt（实测 LNK2001 无法解析），
; 也无法用内联汇编（x64 不支持 __asm）。只能用 MASM 提供这一个入口，
; 保证与原始指令完全一致。
;
; 约定：rcx = 输出缓冲（10 字节：u16 limit + u64 base），与 sgdt 的
;       fword 目标一致。
; ============================================================================

.code

ReadGdtrAsm PROC
    sgdt fword ptr [rcx]
    ret
ReadGdtrAsm ENDP

END
