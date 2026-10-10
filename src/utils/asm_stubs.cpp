#include "shadowhook/utils/asm_stubs.hpp"
#include <cstring>

namespace shadowhook::asm_stubs {
    namespace {
        struct parse_result {
            bool ok{ false };
            std::size_t displacement_offset{};
            bool rip_relative{};
            std::uint8_t reg{};
        };

        bool is_legacy_prefix(std::uint8_t b) noexcept {
            switch (b) {
            case 0xF0: case 0xF2: case 0xF3: case 0x2E: case 0x36:
            case 0x3E: case 0x26: case 0x64: case 0x65: case 0x66:
            case 0x67: return true;
            default: return false;
            }
        }

        bool consume(std::size_t& cursor, std::size_t n, std::size_t limit) noexcept {
            if (n > limit - cursor) return false;
            cursor += n;
            return cursor <= 15;
        }

        parse_result read_modrm(const std::uint8_t* bytes, std::size_t& pos,
            std::size_t limit, bool address_override) noexcept {
            parse_result out{};
            if (pos >= limit || pos >= 15) return out;
            const auto m = bytes[pos++];
            const auto mod = static_cast<std::uint8_t>(m >> 6);
            const auto rm = static_cast<std::uint8_t>(m & 7);
            out.reg = static_cast<std::uint8_t>((m >> 3) & 7);
            if (mod != 3) {
                if (rm == 4) {
                    if (pos >= limit || pos >= 15) return out;
                    const auto sib = bytes[pos++];
                    if (mod == 0 && (sib & 7) == 5) {
                        out.displacement_offset = pos;
                        if (!consume(pos, 4, limit)) return out;
                    }
                }
                else if (mod == 0 && rm == 5) {
                    out.displacement_offset = pos;
                    out.rip_relative = !address_override;
                    if (!consume(pos, 4, limit)) return out;
                }
                if (mod == 1 && !consume(pos, 1, limit)) return out;
                if (mod == 2 && !consume(pos, 4, limit)) return out;
            }
            out.ok = true;
            return out;
        }

        void set_branch(insn_info& result, std::size_t offset, std::size_t len,
            branch_kind kind, std::uint8_t cc = 0) noexcept {
            result.is_relative = true;
            result.rel_offset = offset;
            result.rel_size = len;
            result.branch = kind;
            result.condition = cc;
        }
    } // namespace

    insn_info decode(const std::uint8_t* code, std::size_t available) noexcept {
        insn_info fail{};
        if (!code || available == 0) return fail;
        const auto limit = available < 15 ? available : 15;
        std::size_t pos = 0;
        bool operand16 = false, address_override = false, rex_w = false;
        bool has_lock = false, has_rep = false;
        while (pos < limit && is_legacy_prefix(code[pos])) {
            const auto p = code[pos++];
            if (p == 0x66) operand16 = true;
            if (p == 0x67) address_override = true;
            if (p == 0xF0) has_lock = true;
            if (p == 0xF2 || p == 0xF3) has_rep = true;
        }
      
        if (has_lock) return fail;
        while (pos < limit && code[pos] >= 0x40 && code[pos] <= 0x4F) {
            rex_w = (code[pos++] & 8) != 0;
        }
        if (pos >= limit) return fail;
        const auto op = code[pos++];
        std::uint8_t op2 = 0;
        bool two_byte = false, modrm = false, group_f6 = false, group_f7 = false;
        std::size_t imm_size = 0;
        insn_info result{};
        if (op == 0xC4 || op == 0xC5 || op == 0x62 || op == 0x8F ) {
            if (op != 0x8F) return fail;
        }
        if (op == 0x0F) {
            if (pos >= limit) return fail;
            two_byte = true;
            op2 = code[pos++];
            if (op2 == 0x38 || op2 == 0x3A) return fail;
            // CET ENDBR64: F3 0F 1E FA
            if (op2 == 0x1E && has_rep && pos < limit && code[pos] == 0xFA) {
                ++pos;
                result.length = pos;
                return result;
            }
            if (op2 >= 0x80 && op2 <= 0x8F) {
                if (operand16 || !consume(pos, 4, limit)) return fail;
                set_branch(result, pos - 4, 4, branch_kind::conditional, op2 & 15);
                result.length = pos;
                return result;
            }
            if (op2 == 0x1F || (op2 >= 0x40 && op2 <= 0x4F) ||
                (op2 >= 0x90 && op2 <= 0x9F) ||
                op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29 ||
                op2 == 0x2E || op2 == 0x2F || op2 == 0x6F || op2 == 0x7F ||
                op2 == 0xAF || op2 == 0xB0 || op2 == 0xB1 ||
                op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
                op2 == 0xBA || op2 == 0x70 || op2 == 0x71 ||
                op2 == 0x72 || op2 == 0x73 || op2 == 0xA4 || op2 == 0xAC) {
                modrm = true;
                if (op2 == 0xBA || op2 == 0x70 || op2 == 0x71 || op2 == 0x72 ||
                    op2 == 0x73 || op2 == 0xA4 || op2 == 0xAC) imm_size = 1;
            }
            else if (op2 == 0x31 || op2 == 0xA2 || op2 == 0x05 || op2 == 0x0B) {
                // rdtsc, cpuid, syscall, ud2
            }
            else return fail;
        }
        else if (op >= 0x70 && op <= 0x7F) {
            if (!consume(pos, 1, limit)) return fail;
            set_branch(result, pos - 1, 1, branch_kind::conditional, op & 15);
            result.length = pos;
            return result;
        }
        else if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
            const auto bytes = op == 0xEB ? 1u : 4u;
            if (operand16 || !consume(pos, bytes, limit)) return fail;
            set_branch(result, pos - bytes, bytes, op == 0xE8 ? branch_kind::call : branch_kind::jump);
            result.length = pos;
            return result;
        }
        else if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0xC3 ||
            op == 0xCC || op == 0x9C || op == 0x9D || op == 0x9E || op == 0x9F || op == 0x98 || op == 0x99) {
            // push/pop reg, nop, ret, int3, pushfq/popfq, cwde/cdqe, cdq/cqo
        }
        else if (op == 0xC2 || op == 0x68) {
            imm_size = op == 0xC2 ? 2 : (operand16 ? 2 : 4);
        }
        else if (op == 0x6A || (op >= 0xB0 && op <= 0xB7) || op == 0xA8) {
            imm_size = 1;
        }
        else if (op >= 0xB8 && op <= 0xBF) {
            imm_size = rex_w ? 8 : (operand16 ? 2 : 4);
        }
        else if (op == 0xA9) {
            imm_size = operand16 ? 2 : 4;
        }
        else if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B ||
            op == 0x8D || op == 0x8C || op == 0x8E || op == 0x8F ||
            op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 ||
            op == 0x63 || op == 0xFE || op == 0xFF ||
            (op <= 0x3B && (op & 7) <= 3)) {
            modrm = true;
        }
        else if (op == 0xC6 || op == 0xC7 || op == 0x80 || op == 0x81 ||
            op == 0x83 || op == 0x69 || op == 0x6B || op == 0xC0 || op == 0xC1 ||
            (op >= 0xD0 && op <= 0xD3)) {
            modrm = true;
            if (op == 0xC6 || op == 0x80 || op == 0x83 || op == 0x6B || op == 0xC0 || op == 0xC1) imm_size = 1;
            if (op == 0xC7 || op == 0x81 || op == 0x69) imm_size = operand16 ? 2 : 4;
        }
        else if (op == 0xF6 || op == 0xF7) {
            modrm = true;
            group_f6 = op == 0xF6;
            group_f7 = op == 0xF7;
        }
        else {
            return fail; // unknown
        }
        if (has_rep && !((op == 0x90) || (two_byte && (op2 == 0x10 || op2 == 0x11 || op2 == 0x6F || op2 == 0x7F)))) return fail;
        if (modrm) {
            const auto r = read_modrm(code, pos, limit, address_override);
            if (!r.ok) return fail;
            if (r.rip_relative) {
                result.is_rip_relative = true;
                result.rip_disp_offset = r.displacement_offset;
            }
            if ((group_f6 || group_f7) && r.reg == 0)
                imm_size = group_f6 ? 1 : (operand16 ? 2 : 4);
            if ((group_f6 || group_f7) && r.reg == 1) return fail;
        }
        if (!consume(pos, imm_size, limit)) return fail;
        result.length = pos;
        return result;
    }

    void write_jmp_abs(void* src, const void* dst) noexcept {
        auto* p = static_cast<std::uint8_t*>(src);
        p[0] = 0xFF; p[1] = 0x25;
        std::memset(p + 2, 0, 4);
        const auto address = reinterpret_cast<std::uint64_t>(dst);
        std::memcpy(p + 6, &address, 8);
    }

    void write_call_abs_safe(void* src, const void* dst) noexcept {
        // call qword ptr [rip+2]; jmp +8; dq dst
        auto* p = static_cast<std::uint8_t*>(src);
        const std::uint8_t head[] = { 0xFF, 0x15, 0x02, 0, 0, 0, 0xEB, 0x08 };
        std::memcpy(p, head, sizeof(head));
        const auto address = reinterpret_cast<std::uint64_t>(dst);
        std::memcpy(p + sizeof(head), &address, 8);
    }

    void write_nop(void* dst, std::size_t count) noexcept {
        std::memset(dst, 0x90, count);
    }
} // namespace shadowhook::asm_stubs
