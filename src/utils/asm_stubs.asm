.code

PUBLIC asm_flush_instruction_cache
PUBLIC asm_get_rip
PUBLIC asm_read_cr0
PUBLIC asm_write_cr0
PUBLIC asm_read_cr3
PUBLIC asm_read_cr4
PUBLIC asm_write_cr4
PUBLIC asm_read_msr
PUBLIC asm_write_msr
PUBLIC asm_invlpg
PUBLIC asm_disable_interrupts
PUBLIC asm_enable_interrupts
PUBLIC asm_read_dr7
PUBLIC asm_write_dr7
PUBLIC asm_cpuid
PUBLIC asm_read_cs
PUBLIC asm_read_ss
PUBLIC asm_read_rflags

asm_flush_instruction_cache PROC
    push rbp
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    add rdi, rsi
    cmp rdi, rsi
    jle flush_done
    and rsi, -64
flush_loop:
    clflush [rsi]
    add rsi, 64
    cmp rsi, rdi
    jl flush_loop
    mfence
    sfence
flush_done:
    pop rdi
    pop rsi
    pop rbp
    ret
asm_flush_instruction_cache ENDP

asm_get_rip PROC
    call rip_label
rip_label:
    pop rax
    sub rax, 5
    ret
asm_get_rip ENDP

asm_read_cr0 PROC
    mov rax, cr0
    ret
asm_read_cr0 ENDP

asm_write_cr0 PROC
    mov cr0, rcx
    ret
asm_write_cr0 ENDP

asm_read_cr3 PROC
    mov rax, cr3
    ret
asm_read_cr3 ENDP

asm_read_cr4 PROC
    mov rax, cr4
    ret
asm_read_cr4 ENDP

asm_write_cr4 PROC
    mov cr4, rcx
    ret
asm_write_cr4 ENDP

asm_read_msr PROC
    rdmsr
    shl rdx, 32
    or rax, rdx
    ret
asm_read_msr ENDP

asm_write_msr PROC
    mov r8, rdx
    mov eax, r8d
    shr r8, 32
    mov edx, r8d
    wrmsr
    ret
asm_write_msr ENDP

asm_invlpg PROC
    invlpg [rcx]
    ret
asm_invlpg ENDP

asm_disable_interrupts PROC
    pushfq
    cli
    pop rax
    mov [rsp-8], rax
    ret
asm_disable_interrupts ENDP

asm_enable_interrupts PROC
    sti
    ret
asm_enable_interrupts ENDP

asm_read_dr7 PROC
    mov rax, dr7
    ret
asm_read_dr7 ENDP

asm_write_dr7 PROC
    mov dr7, rcx
    ret
asm_write_dr7 ENDP

asm_cpuid PROC
    push rbx
    push rsi
    mov eax, ecx
    mov esi, edx
    cpuid
    mov [rsi], eax
    mov [rsi+4], ebx
    mov [rsi+8], ecx
    mov [rsi+12], edx
    pop rsi
    pop rbx
    ret
asm_cpuid ENDP

asm_read_cs PROC
    mov ax, cs
    ret
asm_read_cs ENDP

asm_read_ss PROC
    mov ax, ss
    ret
asm_read_ss ENDP

asm_read_rflags PROC
    pushfq
    pop rax
    ret
asm_read_rflags ENDP

END