#include "shadowhook/ring0/page_shadow.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/asm_stubs.hpp"

namespace shadowhook::ring0 {

    page_shadow::page_shadow() {
        SH_LOG_INFO("[page_shadow] backend created");
    }

    page_shadow::~page_shadow() {
        uninstall_all();
    }

    void* page_shadow::allocate_shadow(void* original_page) {
        void* shadow = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shadow) {
            SH_LOG_ERROR("[page_shadow] shadow alloc failed");
            return nullptr;
        }
        memcpy(shadow, original_page, 0x1000);
        SH_LOG_VERBOSE("[page_shadow] shadow page at %p (orig=%p)", shadow, original_page);
        return shadow;
    }

    void page_shadow::destroy_shadow(void* shadow_page) {
        if (shadow_page) {
            VirtualFree(shadow_page, 0, MEM_RELEASE);
        }
    }

    void* page_shadow::build_trampoline(void* shadow_page, void* detour,
        void* original_page, size_t offset, size_t copy_size) {
        void* trampoline = VirtualAlloc(nullptr, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline) {
            SH_LOG_ERROR("[page_shadow] trampoline alloc failed");
            return nullptr;
        }

        uint8_t* t = (uint8_t*)trampoline;

        memcpy(t, (uint8_t*)original_page + offset, copy_size);
        t += copy_size;

        uintptr_t jmp_back = (uintptr_t)original_page + offset + copy_size;
        int32_t rel = (int32_t)(jmp_back - ((uintptr_t)t + 5));

        *t++ = 0xE9;
        *(int32_t*)t = rel;
        t += 4;

        SH_LOG_VERBOSE("[page_shadow] trampoline at %p (%zu bytes + jmp)", trampoline, copy_size);
        return trampoline;
    }

    void page_shadow::destroy_trampoline(void* trampoline) {
        if (trampoline) {
            VirtualFree(trampoline, 0, MEM_RELEASE);
        }
    }

    hook_status page_shadow::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (shadow_hooks_.count(target)) {
            return hook_status::already_hooked;
        }

        void* page = (void*)((uintptr_t)target & ~0xFFFULL);
        size_t offset = (uintptr_t)target - (uintptr_t)page;

        void* shadow = allocate_shadow(page);
        if (!shadow) return hook_status::alloc_failed;

        size_t copy_size = 14;

        void* trampoline = build_trampoline(shadow, detour, page, offset, copy_size);
        if (!trampoline) {
            destroy_shadow(shadow);
            return hook_status::alloc_failed;
        }

        uint8_t* patch = (uint8_t*)shadow + offset;

        DWORD old;
        VirtualProtect(patch, 14, PAGE_EXECUTE_READWRITE, &old);

        patch[0] = 0xFF;
        patch[1] = 0x25;
        patch[2] = 0x00;
        patch[3] = 0x00;
        patch[4] = 0x00;
        patch[5] = 0x00;
        *(uint64_t*)(patch + 6) = (uint64_t)detour;

        DWORD tmp;
        VirtualProtect(patch, 14, old, &tmp);

        DWORD old2;
        VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old2);
        *(uint8_t*)target = 0xCC;
        DWORD tmp2;
        VirtualProtect(target, 1, old2, &tmp2);

        shadow_entry se = {};
        se.target = target;
        se.detour = detour;
        se.original = trampoline;
        se.original_page = page;
        se.shadow_page = shadow;
        se.trampoline = trampoline;
        se.page_offset = offset;
        se.copy_size = copy_size;
        se.patch_size = 1;
        se.saved_bytes[0] = *(uint8_t*)((uint8_t*)page + offset);
        se.active = true;

        if (original) *original = trampoline;

        shadow_hooks_[target] = se;
        hooks_.push_back({ target, detour, trampoline, 1, {}, true });

        SH_LOG_INFO("[page_shadow] hooked %p (shadow=%p, tramp=%p)",
            target, shadow, trampoline);

        return hook_status::success;
    }

    hook_status page_shadow::uninstall(void* target) {
        auto it = shadow_hooks_.find(target);
        if (it == shadow_hooks_.end()) return hook_status::not_hooked;

        auto& se = it->second;

        DWORD old;
        VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t*)target = se.saved_bytes[0];
        DWORD tmp;
        VirtualProtect(target, 1, old, &tmp);

        destroy_trampoline(se.trampoline);
        destroy_shadow(se.shadow_page);

        SH_LOG_INFO("[page_shadow] unhooked %p", target);

        shadow_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        return hook_status::success;
    }

    hook_status page_shadow::uninstall_all() {
        auto copy = shadow_hooks_;
        for (auto& [target, _] : copy) {
            uninstall(target);
        }
        return hook_status::success;
    }

    bool page_shadow::is_hooked(void* target) const {
        return shadow_hooks_.count(target) > 0;
    }

} // namespace shadowhook::ring0