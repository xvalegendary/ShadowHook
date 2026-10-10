#define NOMINMAX
#include "shadowhook/utils/memory.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <limits>
#include <cstdint>
#include <cstring>

namespace shadowhook::memory {
    bool safe_copy(void* dst, const void* src, size_t size) {
        if (!dst || !src || !size) return false;
        __try { std::memcpy(dst, src, size); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SH_LOG_ERROR("safe_copy: exception (dst=%p, src=%p)", dst, src);
            return false;
        }
    }

    bool protect(void* addr, size_t size, DWORD new_prot, DWORD* old_prot) {
        return addr && size && old_prot && VirtualProtect(addr, size, new_prot, old_prot) != 0;
    }

    bool is_executable(void* addr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!addr || VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        auto p = mbi.Protect & 0xff;
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
            p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    void* allocate_rwx(size_t size) {
        return size ? VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) : nullptr;
    }

    void* allocate_rwx_near(void* target, size_t size) {
        if (!target || !size) return nullptr;
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const auto gran = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
        if (!gran || (gran & (gran - 1)) != 0) return nullptr;
        constexpr std::uintptr_t range = 0x70000000ULL; 
        const auto origin = reinterpret_cast<std::uintptr_t>(target);
        const auto system_min = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const auto system_max = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
        const auto min_addr = origin > range ? std::max(system_min, origin - range) : system_min;
        const auto max_addr = origin > system_max - std::min(range, system_max)
            ? system_max : std::min(system_max, origin + range);
        const auto aligned = origin & ~(gran - 1);

        const auto try_address = [&](std::uintptr_t p) -> void* {
            if (p < min_addr || p > max_addr || p > system_max || size > system_max - p) return nullptr;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi)) != sizeof(mbi)) return nullptr;
            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            if (mbi.State != MEM_FREE || p < base || (p - base) > mbi.RegionSize) return nullptr;
            if (size > mbi.RegionSize - (p - base)) return nullptr;
       
            return VirtualAlloc(reinterpret_cast<void*>(p), size,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            };

        for (std::uintptr_t distance = 0; distance <= range; distance += gran) {
            if (aligned >= distance) {
                if (void* p = try_address(aligned - distance)) return p;
            }
            if (distance && aligned <= system_max - distance) {
                if (void* p = try_address(aligned + distance)) return p;
            }
        }
        return nullptr; 
    }

    void free_rwx(void* addr) {
        if (addr) VirtualFree(addr, 0, MEM_RELEASE);
    }
} // namespace shadowhook::memory
