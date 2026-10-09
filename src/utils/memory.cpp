#include "shadowhook/utils/memory.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::memory {

    bool safe_copy(void* dst, const void* src, size_t size) {
        if (!dst || !src || !size) return false;

        __try {
            memcpy(dst, src, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SH_LOG_ERROR("safe_copy: SEH exception (dst=%p, src=%p, size=%zu)", dst, src, size);
            return false;
        }
    }

    bool protect(void* addr, size_t size, DWORD new_prot, DWORD* old_prot) {
        if (!addr || !size) return false;
        return VirtualProtect(addr, size, new_prot, old_prot) != 0;
    }

    bool is_executable(void* addr) {
        if (!addr) return false;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    void* allocate_rwx(size_t size) {
        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    void free_rwx(void* addr) {
        if (addr) VirtualFree(addr, 0, MEM_RELEASE);
    }

} // namespace shadowhook::memory