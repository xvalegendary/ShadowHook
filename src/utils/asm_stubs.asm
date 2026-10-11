.code
PUBLIC asm_flush_instruction_cache
PUBLIC asm_get_rip
PUBLIC asm_cpuid
PUBLIC asm_cpuid_ex
PUBLIC asm_read_cs
PUBLIC asm_read_ss
PUBLIC asm_read_rflags


asm_flush_instruction_cache PROC
    test rdx, rdx
    jz flush_done
    mov r8, rcx
    add r8, rdx
    jc flush_done
    and rcx, -64
flush_loop:
    clflush [rcx]
    add rcx, 64
    cmp rcx, r8
    jb flush_loop
    mfence
flush_done:
    ret
asm_flush_instruction_cache ENDP


asm_get_rip PROC
    lea rax, asm_get_rip
    ret
asm_get_rip ENDP

; RCX=leaf, RDX=uint32_t[4]
asm_cpuid PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    mov r8, rdx
    mov eax, ecx
    xor ecx, ecx
    cpuid
    mov [r8], eax
    mov [r8+4], ebx
    mov [r8+8], ecx
    mov [r8+12], edx
    pop rbx
    ret
asm_cpuid ENDP

; RCX=leaf, RDX=subleaf, R8=uint32_t[4].
asm_cpuid_ex PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    mov eax, ecx
    mov ecx, edx
    cpuid
    mov [r8], eax
    mov [r8+4], ebx
    mov [r8+8], ecx
    mov [r8+12], edx
    pop rbx
    ret
asm_cpuid_ex ENDP

asm_read_cs PROC
    xor eax, eax
    mov ax, cs
    ret
asm_read_cs ENDP
asm_read_ss PROC
    xor eax, eax
    mov ax, ss
    ret
asm_read_ss ENDP
asm_read_rflags PROC FRAME
    pushfq
    .allocstack 8
    .endprolog
    mov rax, [rsp]
    add rsp, 8
    ret
asm_read_rflags ENDP
END
