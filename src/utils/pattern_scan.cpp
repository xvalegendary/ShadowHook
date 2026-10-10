#include "shadowhook/utils/pattern_scan.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <cstring>
#include <psapi.h>
#include <limits>

namespace shadowhook {
    module_info pattern_scanner::get_module(const char* name) {
        module_info result{};
        const HMODULE mod = GetModuleHandleA(name);
        if (!mod) return result;
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return result;
        result.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        result.size = mi.SizeOfImage;
        if (name) {
            std::strncpy(result.name, name, sizeof(result.name) - 1);
            result.name[sizeof(result.name) - 1] = '\0';
        }
        return result;
    }

    module_info pattern_scanner::get_kernel_module(const char*) {
        SH_LOG_WARN("kernel addresses are not readable from this user-mode scanner");
        return {}; 
    }

    pattern_result pattern_scanner::find(uintptr_t base, size_t size,
        const char* pattern, const char* mask) {
        if (!base || !pattern || !mask) return {};
        const auto len = std::strlen(mask);
        if (!len || len > size) return {};
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        for (size_t i = 0; i <= size - len; ++i) {
            bool matches = true;
            for (size_t j = 0; j != len; ++j) {
                if (mask[j] == 'x' && bytes[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                    matches = false;
                    break;
                }
            }
            if (matches) return { base + i, len, true };
        }
        return {};
    }

    pattern_result pattern_scanner::find_in_module(const char* module,
        const char* pattern, const char* mask) {
        const auto mod = get_module(module);
        if (!mod.base) return {};
        return find(mod.base, mod.size, pattern, mask);
    }
    pattern_result pattern_scanner::find_in_kernel(const char*, const char*, const char*) {
        SH_LOG_WARN("kernel pattern scan not available in user mode");
        return {};
    }
    std::vector<pattern_result> pattern_scanner::find_all(uintptr_t base, size_t size,
        const char* pattern, const char* mask) {
        std::vector<pattern_result> out;
        if (!base || !pattern || !mask) return out;
        const auto len = std::strlen(mask);
        if (!len || len > size) return out;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(base);
        for (size_t i = 0; i <= size - len; ++i) {
            bool matches = true;
            for (size_t j = 0; j != len; ++j) {
                if (mask[j] == 'x' && bytes[i + j] != static_cast<std::uint8_t>(pattern[j])) {
                    matches = false;
                    break;
                }
            }
            if (matches) out.push_back({ base + i, len, true });
        }
        return out;
    }
    uintptr_t pattern_scanner::resolve_call(uintptr_t site) {
        if (!site) return 0;
        const auto* p = reinterpret_cast<const std::uint8_t*>(site);
        if (p[0] != 0xE8) return 0;
        std::int32_t disp{};
        std::memcpy(&disp, p + 1, sizeof(disp));
        return static_cast<uintptr_t>(static_cast<std::intptr_t>(site + 5) + disp);
    }
    uintptr_t pattern_scanner::resolve_lea(uintptr_t site) {
        if (!site) return 0;
        const auto* p = reinterpret_cast<const std::uint8_t*>(site);
        if (p[0] != 0x48 || p[1] != 0x8D || p[2] != 0x05) return 0;
        std::int32_t disp{};
        std::memcpy(&disp, p + 3, sizeof(disp));
        return static_cast<uintptr_t>(static_cast<std::intptr_t>(site + 7) + disp);
    }
    uintptr_t pattern_scanner::find_ref(uintptr_t base, size_t size,
        uintptr_t target, size_t ref_size) {
        if (!base || !ref_size || ref_size > sizeof(uintptr_t) || ref_size > size) return 0;
        const auto* data = reinterpret_cast<const std::uint8_t*>(base);
        for (size_t i = 0; i <= size - ref_size; ++i) {
            uintptr_t value{};
            std::memcpy(&value, data + i, ref_size);
            if (value == target) return base + i;
        }
        return 0;
    }
    void offset_resolver::add_pattern(const char* name, const char* pattern,
        const char* mask, int32_t offset) {
        if (!name || !pattern || !mask) return;
        entries_.push_back({ name, pattern, mask, offset, 0, false });
    }
    uintptr_t offset_resolver::resolve(const char* name) {
        if (!name) return 0;
        for (auto& x : entries_)
            if (x.name == name && x.found) return x.resolved + x.extra_offset;
        return 0;
    }
    void offset_resolver::resolve_all() {
        for (auto& e : entries_) { e.found = false; e.resolved = 0; }
        SH_LOG_WARN("offset_resolver::resolve_all: kernel scan disabled in user-mode build");
    }
    void offset_resolver::dump() const {
        for (const auto& e : entries_)
            SH_LOG_INFO("%-32s %s %p", e.name.c_str(), e.found ? "[+]" : "[-]",
                reinterpret_cast<void*>(e.found ? e.resolved + e.extra_offset : 0));
    }
} // namespace shadowhook
