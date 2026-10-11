#include "shadowhook/utils/pattern_scan.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/memory.hpp"
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

    namespace {
        bool matches_at(const std::uint8_t* bytes, const char* pattern,
                        const char* mask, std::size_t len) {
            __try {
                for (std::size_t j = 0; j < len; ++j)
                    if (mask[j] == 'x' && bytes[j] != static_cast<std::uint8_t>(pattern[j]))
                        return false;
                return true;
            } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }
        std::vector<pattern_result> scan(std::uintptr_t base, std::size_t size,
                                        const char* pattern, const char* mask, bool first) {
            std::vector<pattern_result> out;
            if (!base || !size || size > UINTPTR_MAX - base || !pattern || !mask) return out;
            const auto len = std::strlen(mask);
            if (!len || len > size) return out;
            for (std::size_t j = 0; j < len; ++j)
                if (mask[j] != 'x' && mask[j] != '?') return out;
            const auto end = base + size;
            auto cursor = base;
            std::uintptr_t readable_begin{};

            auto scan_run = [&](std::uintptr_t stop) {
                if (!readable_begin || stop - readable_begin < len) return false;
                for (auto p = readable_begin; p <= stop - len; ++p) {
                    if (matches_at(reinterpret_cast<const std::uint8_t*>(p), pattern, mask, len)) {
                        out.push_back({p, len, true});
                        if (first) return true;
                    }
                }
                return false;
            };
            while (cursor < end) {
                MEMORY_BASIC_INFORMATION m{};
                if (VirtualQuery(reinterpret_cast<void*>(cursor), &m, sizeof(m)) != sizeof(m)) break;
                const auto region = reinterpret_cast<std::uintptr_t>(m.BaseAddress);
                if (cursor < region || cursor - region >= m.RegionSize) break;
                const auto stop = cursor + std::min<std::size_t>(end - cursor, m.RegionSize - (cursor - region));
                const bool readable = memory::readable_range(reinterpret_cast<void*>(cursor), 1);
                if (readable) { if (!readable_begin) readable_begin = cursor; }
                else {
                    if (scan_run(cursor)) return out;
                    readable_begin = 0;
                }
                cursor = stop;
            }
            scan_run(cursor);
            return out;
        }
        std::uintptr_t relative_target(std::uintptr_t site, std::size_t size, std::int32_t disp) {
            if (size > UINTPTR_MAX - site) return 0;
            const auto next = site + size;
            if (disp < 0) {
                const auto distance = static_cast<std::uint64_t>(-static_cast<std::int64_t>(disp));
                return distance <= next ? next - distance : 0;
            }
            return static_cast<std::uint32_t>(disp) <= UINTPTR_MAX - next ? next + disp : 0;
        }
    }
    pattern_result pattern_scanner::find(uintptr_t base, size_t size,
                                        const char* pattern, const char* mask) {
        const auto out = scan(base, size, pattern, mask, true);
        return out.empty() ? pattern_result{} : out.front();
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
        return scan(base, size, pattern, mask, false);
    }
    uintptr_t pattern_scanner::resolve_call(uintptr_t site) {
        std::uint8_t bytes[5]{};
        if (!memory::readable_range(reinterpret_cast<void*>(site), sizeof(bytes)) ||
            !memory::safe_copy(bytes, reinterpret_cast<void*>(site), sizeof(bytes)) || bytes[0] != 0xE8) return 0;
        std::int32_t disp{};
        std::memcpy(&disp, bytes + 1, sizeof(disp));
        return relative_target(site, sizeof(bytes), disp);
    }
    uintptr_t pattern_scanner::resolve_lea(uintptr_t site) {
        std::uint8_t bytes[7]{};
        if (!memory::readable_range(reinterpret_cast<void*>(site), sizeof(bytes)) ||
            !memory::safe_copy(bytes, reinterpret_cast<void*>(site), sizeof(bytes)) ||
            bytes[0] != 0x48 || bytes[1] != 0x8D || bytes[2] != 0x05) return 0;
        std::int32_t disp{};
        std::memcpy(&disp, bytes + 3, sizeof(disp));
        return relative_target(site, sizeof(bytes), disp);
    }
    uintptr_t pattern_scanner::find_ref(uintptr_t base, size_t size, uintptr_t target, size_t ref_size) {
        if (!ref_size || ref_size > sizeof(target) || ref_size > size) return 0;
        if (ref_size < sizeof(target) && target >> (ref_size * 8)) return 0;
        char mask[sizeof(target) + 1]{};
        std::memset(mask, 'x', ref_size);
        const auto result = find(base, size, reinterpret_cast<const char*>(&target), mask);
        return result.found ? result.address : 0;
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
