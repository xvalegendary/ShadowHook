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

    static bool is_prefix(uint8_t b) {
        return b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 ||
            b == 0x66 || b == 0x67;
    }

    size_t insn_length(uint8_t* code, size_t max) {
        if (!code || !max) return 0;

        size_t len = 0;
        bool has_66 = false;
        bool rex_w = false;

        while (len < max && is_prefix(code[len])) {
            if (code[len] == 0x66) has_66 = true;
            len++;
        }

        if (len >= max) return 0;

        if ((code[len] & 0xF0) == 0x40) {
            if (code[len] & 0x08) rex_w = true;
            len++;
            if (len >= max) return 0;
        }

        uint8_t op = code[len++];

        if (op == 0x0F) {
            if (len >= max) return 0;
            op = code[len++];

            if (op >= 0x80 && op <= 0x8F) return len + 4;

            if (len >= max) return 0;
            uint8_t modrm = code[len++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 0 && rm == 4) {
                    if (len >= max) return 0;
                    uint8_t sib = code[len++];
                    if ((sib & 7) == 5) len += 4;
                }
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                else if (rm == 4) {
                    if (len >= max) return 0;
                    len++;
                }
            }

            if (op == 0x00 || op == 0x01 || op == 0xBA || op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 || op == 0xA4 || op == 0xAC) {
                len += 1;
            }

            return len;
        }

        if (op == 0xF6 || op == 0xF7) {
            if (len >= max) return 0;
            uint8_t modrm = code[len++];
            uint8_t reg = (modrm >> 3) & 7;
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 0 && rm == 4) {
                    if (len >= max) return 0;
                    uint8_t sib = code[len++];
                    if ((sib & 7) == 5) len += 4;
                }
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                else if (rm == 4) {
                    if (len >= max) return 0;
                    len++;
                }
            }

            if ((reg == 0 || reg == 1) && op == 0xF6) len += 1;
            if ((reg == 0 || reg == 1) && op == 0xF7) len += 4;

            return len;
        }

        if (op >= 0xE0 && op <= 0xE3) return len + 1;
        if (op == 0xE8 || op == 0xE9) return len + 4;
        if (op == 0xEB) return len + 1;
        if (op >= 0x70 && op <= 0x7F) return len + 1;

        if (op == 0x68) return len + 4;
        if (op == 0x6A) return len + 1;

        if (op == 0xC2) return len + 2;
        if (op == 0xC8) return len + 3;
        if (op == 0xCA || op == 0xCB || op == 0xC3 || op == 0xC9 || op == 0xCC || op == 0xCE || op == 0xCF || op == 0x90 || op == 0xF4 || op == 0xF5 || op == 0xF8 || op == 0xF9 || op == 0xFA || op == 0xFB || op == 0xFC || op == 0xFD || op == 0x9B || op == 0x9C || op == 0x9D || op == 0x9E || op == 0x9F) return len;
        if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3 || op == 0x6B || op == 0x80 || op == 0x82 || op == 0x83 || op == 0xA0 || op == 0xA8 || op == 0xB0 || op == 0xB8 || op == 0xC6) {
            if (len >= max) return 0;
            uint8_t modrm = code[len++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 0 && rm == 4) {
                    if (len >= max) return 0;
                    uint8_t sib = code[len++];
                    if ((sib & 7) == 5) len += 4;
                }
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                else if (rm == 4) {
                    if (len >= max) return 0;
                    len++;
                }
            }

            if (op == 0xC0 || op == 0xC1 || op == 0x6B || op == 0x80 || op == 0x82 || op == 0x83 || op == 0xA0 || op == 0xA8 || op == 0xB0 || op == 0xC6) len += 1;
            if (op == 0xB8) len += 8;
            return len;
        }

        if (op == 0xC7 || op == 0x69 || op == 0x81) {
            if (len >= max) return 0;
            uint8_t modrm = code[len++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 0 && rm == 4) {
                    if (len >= max) return 0;
                    uint8_t sib = code[len++];
                    if ((sib & 7) == 5) len += 4;
                }
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                else if (rm == 4) {
                    if (len >= max) return 0;
                    len++;
                }
            }

            len += (has_66 && !rex_w) ? 2 : 4;
            return len;
        }

        if (op == 0xF6 || op == 0xF7 || op == 0x8F || op == 0xFF || (op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) || (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) || (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) || (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) || (op >= 0x62 && op <= 0x63) || (op >= 0x84 && op <= 0x8D) || (op >= 0xA4 && op <= 0xA7) || (op >= 0xAC && op <= 0xAF) || (op >= 0xB2 && op <= 0xB7) || (op >= 0xD8 && op <= 0xDF)) {
            if (len >= max) return 0;
            uint8_t modrm = code[len++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod != 3) {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 0 && rm == 4) {
                    if (len >= max) return 0;
                    uint8_t sib = code[len++];
                    if ((sib & 7) == 5) len += 4;
                }
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                else if (rm == 4) {
                    if (len >= max) return 0;
                    len++;
                }
            }
            return len;
        }

        return len;
    }

} // namespace shadowhook::asm_stubs