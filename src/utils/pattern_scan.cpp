#include "shadowhook/utils/pattern_scan.hpp"
#include "shadowhook/utils/logger.hpp"
#include <psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace shadowhook {

    module_info pattern_scanner::get_module(const char* name) {
        module_info info = {};
        HMODULE hmod = GetModuleHandleA(name);
        if (!hmod) {
            hmod = LoadLibraryA(name);
            if (!hmod) {
                SH_LOG_ERROR("module '%s' not found", name);
                return info;
            }
        }
        MODULEINFO mi;
        if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
            info.base = (uintptr_t)mi.lpBaseOfDll;
            info.size = mi.SizeOfImage;
            strncpy(info.name, name, sizeof(info.name) - 1);
        }
        return info;
    }

    module_info pattern_scanner::get_kernel_module(const char* name) {
        module_info info = {};

        auto ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return info;

        auto NtQSI = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (!NtQSI) return info;

        ULONG needed = 0;
        NtQSI(11, nullptr, 0, &needed);
        if (!needed) return info;

        auto* buf = (uint8_t*)malloc(needed);
        if (!buf) return info;

        NTSTATUS status = NtQSI(11, buf, needed, &needed);
        if (status >= 0) {
            auto* mods = (RTL_PROCESS_MODULES*)buf;
            for (ULONG i = 0; i < mods->NumberOfModules; i++) {
                const char* mod_name = (const char*)buf + mods->Modules[i].OffsetToFileName;
                if (_stricmp(mod_name, name) == 0) {
                    info.base = (uintptr_t)mods->Modules[i].ImageBase;
                    info.size = mods->Modules[i].ImageSize;
                    strncpy(info.name, name, sizeof(info.name) - 1);
                    break;
                }
            }
        }
        free(buf);
        return info;
    }

    pattern_result pattern_scanner::find(uintptr_t base, size_t size,
        const char* pattern, const char* mask) {
        pattern_result result = {};
        size_t pat_len = strlen(mask);

        auto* data = (const uint8_t*)base;
        for (size_t i = 0; i <= size - pat_len; i++) {
            bool found = true;
            for (size_t j = 0; j < pat_len; j++) {
                if (mask[j] == 'x' && data[i + j] != (uint8_t)pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                result.address = base + i;
                result.size = pat_len;
                result.found = true;
                SH_LOG_DEBUG("pattern found at 0x%016llX", (unsigned long long)result.address);
                return result;
            }
        }

        SH_LOG_VERBOSE("pattern not found (mask len=%zu)", pat_len);
        return result;
    }

    pattern_result pattern_scanner::find_in_module(const char* module,
        const char* pattern, const char* mask) {
        auto info = get_module(module);
        if (!info.base) {
            SH_LOG_ERROR("cannot scan '%s' - module not loaded", module);
            return {};
        }
        return find(info.base, info.size, pattern, mask);
    }

    pattern_result pattern_scanner::find_in_kernel(const char* module,
        const char* pattern, const char* mask) {
        auto info = get_kernel_module(module);
        if (!info.base) {
            SH_LOG_ERROR("cannot scan kernel '%s'", module);
            return {};
        }
        return find(info.base, info.size, pattern, mask);
    }

    std::vector<pattern_result> pattern_scanner::find_all(uintptr_t base, size_t size,
        const char* pattern, const char* mask) {
        std::vector<pattern_result> results;
        size_t pat_len = strlen(mask);
        auto* data = (const uint8_t*)base;

        for (size_t i = 0; i <= size - pat_len; i++) {
            bool found = true;
            for (size_t j = 0; j < pat_len; j++) {
                if (mask[j] == 'x' && data[i + j] != (uint8_t)pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                results.push_back({ base + i, pat_len, true });
            }
        }
        return results;
    }

    uintptr_t pattern_scanner::resolve_call(uintptr_t call_site) {
        uint8_t* p = (uint8_t*)call_site;
        if (p[0] != 0xE8) return 0;

        int32_t rel = *(int32_t*)(p + 1);
        return call_site + 5 + rel;
    }

    uintptr_t pattern_scanner::resolve_lea(uintptr_t insn_site) {
        uint8_t* p = (uint8_t*)insn_site;
        if (p[0] != 0x48 || p[1] != 0x8D) return 0;

        int32_t rel = *(int32_t*)(p + 3);
        return insn_site + 7 + rel;
    }

    uintptr_t pattern_scanner::find_ref(uintptr_t base, size_t size,
        uintptr_t target, size_t ref_size) {
        auto* data = (const uint8_t*)base;
        for (size_t i = 0; i <= size - ref_size; i++) {
            uintptr_t val = 0;
            memcpy(&val, data + i, ref_size);
            if (val == target) {
                return base + i;
            }
        }
        return 0;
    }

    void offset_resolver::add_pattern(const char* name, const char* pattern,
        const char* mask, int32_t offset) {
        entries_.push_back({ name, pattern, mask, offset, 0, false });
    }

    uintptr_t offset_resolver::resolve(const char* name) {
        for (auto& e : entries_) {
            if (e.name == name) {
                return e.resolved + e.extra_offset;
            }
        }
        return 0;
    }

    void offset_resolver::resolve_all() {
        for (auto& e : entries_) {
            auto info = pattern_scanner::get_kernel_module("ntoskrnl.exe");
            if (!info.base) continue;

            auto r = pattern_scanner::find(info.base, info.size, e.pattern.c_str(), e.mask.c_str());
            if (r.found) {
                e.resolved = r.address;
                e.found = true;
                SH_LOG_INFO("resolved '%s' -> 0x%016llX", e.name.c_str(), (unsigned long long)e.resolved);
            }
            else {
                SH_LOG_WARN("failed to resolve '%s'", e.name.c_str());
            }
        }
    }

    void offset_resolver::dump() const {
        SH_LOG_INFO("=== offset dump ===");
        for (const auto& e : entries_) {
            SH_LOG_INFO("  %-32s %s 0x%016llX",
                e.name.c_str(),
                e.found ? "[+]" : "[-]",
                (unsigned long long)(e.resolved + e.extra_offset));
        }
    }

} // namespace shadowhook