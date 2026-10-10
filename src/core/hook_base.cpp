#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/logger.hpp"
#include <cstring>
namespace shadowhook {
    hook_base::entry* hook_base::find_entry(void* target) {
        for (auto& x : hooks_) if (x.target == target) return &x;
        return nullptr;
    }
    const hook_base::entry* hook_base::find_entry(void* target) const {
        for (const auto& x : hooks_) if (x.target == target) return &x;
        return nullptr;
    }
    bool hook_base::save_bytes(void* dst, const void* src, size_t size) {
        if (!dst || !src || !size) return false;
        std::memcpy(dst, src, size); 
        return true;
    }
    bool hook_base::restore_bytes(void* dst, const entry* e) {
        if (!dst || !e || !e->patch_size || e->patch_size > sizeof(e->saved_bytes)) return false;
        DWORD previous{};
        if (!VirtualProtect(dst, e->patch_size, PAGE_EXECUTE_READWRITE, &previous)) return false;
        std::memcpy(dst, e->saved_bytes, e->patch_size);
        const bool flushed = FlushInstructionCache(GetCurrentProcess(), dst, e->patch_size) != 0;
        DWORD discarded{};
        const bool restored = VirtualProtect(dst, e->patch_size, previous, &discarded) != 0;
        return flushed && restored;
    }
    bool hook_base::protect(void* addr, size_t size, DWORD* old) {
        return addr && size && old && VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, old) != 0;
    }
} // namespace shadowhook
