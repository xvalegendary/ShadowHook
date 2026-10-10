#pragma once
#include <cstdint>
#include <windows.h>

namespace shadowhook::asm_stubs {

#pragma pack(push, 1)

    struct jmp_abs {
        uint8_t  opcode;
        uint8_t  modrm;
        uint32_t disp;
        uint64_t target;
    };

    static_assert(sizeof(jmp_abs) == 14, "jmp_abs must be 14 bytes");

    struct call_abs {
        uint8_t  opcode;
        uint8_t  modrm;
        uint32_t disp;
        uint64_t target;
    };

    static_assert(sizeof(call_abs) == 14, "call_abs must be 14 bytes");

    struct mov_rax_imm64 {
        uint8_t  opcode[2];
        uint64_t value;
    };

#pragma pack(pop)

    struct insn_info {
        size_t  length;
        bool    is_relative;
        size_t  rel_offset;
        size_t  rel_size;
        bool    is_rip_relative;
        size_t  rip_disp_offset;
    };

    void write_jmp_abs(void* src, void* dst);
    void write_call_abs(void* src, void* dst);
    void write_nop(void* dst, size_t count);

    insn_info decode(uint8_t* code, size_t max);

    extern "C" void __cdecl asm_flush_instruction_cache(void* addr, size_t size);

} // namespace shadowhook::asm_stubs