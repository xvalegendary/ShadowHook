#include "shadowhook/ring3/inline_hook.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/memory.hpp"

namespace shadowhook::ring3 {

    hook_status inline_hook::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (inline_hooks_.count(target)) {
            SH_LOG_WARN("[inline_hook] %p already hooked", target);
            return hook_status::already_hooked;
        }

        size_t patch_size = 0;
        uint8_t* code_ptr = (uint8_t*)target;

        while (patch_size < 14) {
            size_t len = asm_stubs::insn_length(code_ptr + patch_size, 32);
            if (len == 0) {
                SH_LOG_ERROR("[inline_hook] failed to disassemble at %p + %zu", target, patch_size);
                return hook_status::unsupported;
            }
            patch_size += len;
        }

        void* trampoline = memory::allocate_rwx(patch_size + sizeof(asm_stubs::jmp_abs));
        if (!trampoline) {
            SH_LOG_ERROR("[inline_hook] trampoline alloc failed");
            return hook_status::alloc_failed;
        }

        memcpy(trampoline, target, patch_size);

        void* jmp_back_addr = (uint8_t*)target + patch_size;
        asm_stubs::write_jmp_abs((uint8_t*)trampoline + patch_size, jmp_back_addr);

        DWORD old;
        if (!memory::protect(target, patch_size, PAGE_EXECUTE_READWRITE, &old)) {
            memory::free_rwx(trampoline);
            return hook_status::protect_failed;
        }

        inline_entry ie = {};
        ie.target = target;
        ie.detour = detour;
        ie.trampoline = trampoline;
        ie.patch_size = patch_size;
        memcpy(ie.saved_bytes, target, patch_size);
        ie.original = trampoline;
        ie.active = true;

        asm_stubs::write_jmp_abs(target, detour);
        for (size_t i = sizeof(asm_stubs::jmp_abs); i < patch_size; i++) {
            ((uint8_t*)target)[i] = 0x90;
        }

        DWORD tmp;
        memory::protect(target, patch_size, old, &tmp);

        if (original) *original = trampoline;

        inline_hooks_[target] = ie;
        hooks_.push_back({ target, detour, trampoline, patch_size, {}, true });

        SH_LOG_INFO("[inline_hook] %p -> %p (tramp=%p, patch=%zu)", target, detour, trampoline, patch_size);
        return hook_status::success;
    }

    hook_status inline_hook::uninstall(void* target) {
        auto it = inline_hooks_.find(target);
        if (it == inline_hooks_.end()) return hook_status::not_hooked;

        auto& ie = it->second;

        DWORD old;
        if (!memory::protect(target, ie.patch_size, PAGE_EXECUTE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        memcpy(target, ie.saved_bytes, ie.patch_size);

        DWORD tmp;
        memory::protect(target, ie.patch_size, old, &tmp);

        memory::free_rwx(ie.trampoline);
        SH_LOG_INFO("[inline_hook] restored %p", target);

        inline_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        return hook_status::success;
    }

    hook_status inline_hook::uninstall_all() {
        auto copy = inline_hooks_;
        for (auto& kv : copy) {
            uninstall(kv.first);
        }
        return hook_status::success;
    }

    bool inline_hook::is_hooked(void* target) const {
        return inline_hooks_.count(target) > 0;
    }

} // namespace shadowhook::ring3