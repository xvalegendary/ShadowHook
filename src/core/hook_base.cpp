#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook {

    hook_base::entry* hook_base::find_entry(void* target) {
        for (auto& e : hooks_) {
            if (e.target == target) return &e;
        }
        return nullptr;
    }

    const hook_base::entry* hook_base::find_entry(void* target) const {
        for (const auto& e : hooks_) {
            if (e.target == target) return &e;
        }
        return nullptr;
    }

    bool hook_base::save_bytes(void* dst, const void* src, size_t size) {
        if (!dst || !src || !size || size > sizeof(entry::saved_bytes)) return false;

        DWORD old;
        if (!protect(const_cast<void*>(src), size, &old)) {
            SH_LOG_ERROR("protect failed for save (addr=%p, size=%zu)", src, size);
            return false;
        }

        memcpy(dst, src, size);
        DWORD tmp;
        protect(const_cast<void*>(src), size, &tmp);
        return true;
    }

    bool hook_base::restore_bytes(void* dst, const entry* e) {
        if (!dst || !e) return false;

        DWORD old;
        if (!protect(dst, e->patch_size, &old)) {
            SH_LOG_ERROR("protect failed for restore (addr=%p)", dst);
            return false;
        }

        memcpy(dst, e->saved_bytes, e->patch_size);
        DWORD tmp;
        protect(dst, e->patch_size, &tmp);
        return true;
    }

    bool hook_base::protect(void* addr, size_t size, DWORD* old) {
        return VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, old) != 0;
    }

} // namespace shadowhook