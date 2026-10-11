.code
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
PUBLIC asm_restore_interrupts
PUBLIC asm_read_dr7
PUBLIC asm_write_dr7
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

asm_disable_interrupts PROC FRAME
    pushfq
    .allocstack 8
    .endprolog
    cli
    mov rax, [rsp]
    add rsp, 8
    ret
asm_disable_interrupts ENDP
asm_enable_interrupts PROC
    sti
    ret
asm_enable_interrupts ENDP

asm_restore_interrupts PROC
    test rcx, 200h
    jz interrupts_off
    sti
    ret
interrupts_off:
    cli
    ret
asm_restore_interrupts ENDP
asm_read_dr7 PROC
    mov rax, dr7
    ret
asm_read_dr7 ENDP
asm_write_dr7 PROC
    mov dr7, rcx
    ret
asm_write_dr7 ENDP
END
