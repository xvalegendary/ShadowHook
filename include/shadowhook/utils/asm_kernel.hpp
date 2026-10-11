#pragma once
#include <cstdint>
#if !defined(SHADOWHOOK_KERNEL_MODE)
#error This header requires a kernel-mode driver target.
#endif
extern "C" {
std::uint64_t asm_disable_interrupts();
void asm_enable_interrupts();
void asm_restore_interrupts(std::uint64_t previous_flags);
std::uint64_t asm_read_cr0();
void asm_write_cr0(std::uint64_t value);
std::uint64_t asm_read_cr3();
std::uint64_t asm_read_cr4();
void asm_write_cr4(std::uint64_t value);
std::uint64_t asm_read_msr(std::uint32_t index);
void asm_write_msr(std::uint32_t index, std::uint64_t value);
void asm_invlpg(void* page);
std::uint64_t asm_read_dr7();
void asm_write_dr7(std::uint64_t value);
}
