#pragma once
#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace shadowhook::asm_stubs {
#pragma pack(push, 1)
    struct jmp_abs {
        std::uint8_t opcode;
        std::uint8_t modrm;
        std::uint32_t disp;
        std::uint64_t target;
    };
    struct call_abs { 
        std::uint8_t opcode;
        std::uint8_t modrm;
        std::uint32_t disp;
        std::uint64_t target;
    };
    struct mov_rax_imm64 {
        std::uint8_t opcode[2];
        std::uint64_t value;
    };
#pragma pack(pop)
    static_assert(sizeof(jmp_abs) == 14);
    static_assert(sizeof(call_abs) == 14);
    static_assert(sizeof(mov_rax_imm64) == 10);

    enum class branch_kind : std::uint8_t { none, call, jump, conditional };
    struct insn_info {
        std::size_t length{};
        bool is_relative{};
        std::size_t rel_offset{};
        std::size_t rel_size{};
        bool is_rip_relative{};
        std::size_t rip_disp_offset{};
        branch_kind branch{ branch_kind::none };
        std::uint8_t condition{}; 
    };


    insn_info decode(const std::uint8_t* code, std::size_t available) noexcept;
    void write_jmp_abs(void* src, const void* dst) noexcept;
    void write_call_abs_safe(void* src, const void* dst) noexcept;
    void write_nop(void* dst, std::size_t count) noexcept;
    extern "C" void __cdecl asm_flush_instruction_cache(void* addr, std::size_t size);
} // namespace shadowhook::asm_stubs
