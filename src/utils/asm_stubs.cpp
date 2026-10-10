#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::asm_stubs {

    void write_jmp_abs(void* src, void* dst) {
        auto* p = (jmp_abs*)src;
        p->opcode = 0xFF;
        p->modrm = 0x25;
        p->disp = 0x00;
        p->target = (uint64_t)dst;
        FlushInstructionCache(GetCurrentProcess(), src, sizeof(jmp_abs));
    }

    void write_call_abs(void* src, void* dst) {
        auto* p = (call_abs*)src;
        p->opcode = 0xFF;
        p->modrm = 0x15;
        p->disp = 0x00;
        p->target = (uint64_t)dst;
        FlushInstructionCache(GetCurrentProcess(), src, sizeof(call_abs));
    }

    void write_nop(void* dst, size_t count) {
        memset(dst, 0x90, count);
        FlushInstructionCache(GetCurrentProcess(), dst, count);
    }

    enum opcode_flags : uint8_t {
        OP_NONE = 0,
        OP_MODRM = 1,
        OP_IMM8 = 2,
        OP_IMM16 = 4,
        OP_IMM32 = 8,
        OP_IMM64 = 16,
        OP_REL8 = 32,
        OP_REL32 = 64,
        OP_INVALID = 128
    };

    static const uint8_t table_1[256] = {
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_IMM32, OP_MODRM | OP_IMM32, OP_INVALID, OP_IMM8, OP_MODRM | OP_IMM8, OP_INVALID, OP_INVALID,
        OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
        OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM32, OP_INVALID, OP_MODRM | OP_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        0, 0, 0, 0, 0, 0, 0, 0, OP_INVALID, 0, 0, 0, 0, 0, 0, OP_IMM64,
        OP_IMM64, OP_IMM64, OP_IMM64, 0, 0, 0, 0, 0, OP_IMM8, OP_IMM32, 0, 0, 0, 0, 0, 0,
        OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM32, OP_IMM32, OP_IMM32, OP_IMM32, OP_IMM32, OP_IMM32, OP_IMM32, OP_IMM32,
        OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_IMM16, 0, OP_INVALID, OP_INVALID, OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM32, OP_IMM16 | OP_IMM8, 0, OP_IMM16, 0, 0, OP_IMM8, OP_INVALID, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_INVALID, 0, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_REL32, OP_REL32, OP_INVALID, OP_REL8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, 0, 0, OP_INVALID, OP_INVALID
    };

    static const uint8_t table_2[256] = {
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_MODRM, OP_INVALID, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_MODRM, OP_MODRM, OP_INVALID, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID,
        OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID,
        OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8,
        OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_REL8, OP_INVALID, OP_MODRM, OP_MODRM, OP_MODRM, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID, OP_INVALID,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
        OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM
    };

    static bool is_prefix(uint8_t b) {
        return b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 ||
            b == 0x66 || b == 0x67;
    }

    insn_info decode(uint8_t* code, size_t max) {
        insn_info info = { 0, false, 0, 0, false, 0 };
        if (!code || !max) return info;

        size_t len = 0;
        bool has_66 = false;
        bool rex_w = false;

        while (len < max && is_prefix(code[len])) {
            if (code[len] == 0x66) has_66 = true;
            len++;
        }

        if (len >= max) return info;

        if ((code[len] & 0xF0) == 0x40) {
            if (code[len] & 0x08) rex_w = true;
            len++;
            if (len >= max) return info;
        }

        uint8_t op = code[len++];
        bool is_2byte = false;

        if (op == 0x0F) {
            is_2byte = true;
            if (len >= max) return info;
            op = code[len++];

            if (op >= 0x80 && op <= 0x8F) {
                info.length = len + 4;
                info.is_relative = true;
                info.rel_offset = len;
                info.rel_size = 4;
                return info;
            }
        }

        uint8_t flags = is_2byte ? table_2[op] : table_1[op];
        if (flags & OP_INVALID) return info;

        if (flags & OP_REL8) {
            info.length = len + 1;
            info.is_relative = true;
            info.rel_offset = len;
            info.rel_size = 1;
            return info;
        }

        if (flags & OP_REL32) {
            info.length = len + 4;
            info.is_relative = true;
            info.rel_offset = len;
            info.rel_size = 4;
            return info;
        }

        if (flags & OP_MODRM) {
            if (len >= max) return info;
            uint8_t modrm = code[len++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (rm == 4) {
                    if (len >= max) return info;
                    uint8_t sib = code[len++];
                    if (mod == 0 && (sib & 7) == 5) {
                        len += 4;
                    }
                }
                if (mod == 0 && rm == 5) {
                    info.is_rip_relative = true;
                    info.rip_disp_offset = len;
                    len += 4;
                }
                else if (mod == 1) {
                    len += 1;
                }
                else if (mod == 2) {
                    len += 4;
                }
            }
        }

        if (flags & OP_IMM8) len += 1;
        if (flags & OP_IMM16) len += 2;
        if (flags & OP_IMM32) len += (has_66 && !rex_w) ? 2 : 4;
        if (flags & OP_IMM64) len += 8;

        info.length = len;
        return info;
    }

} // namespace shadowhook::asm_stubs