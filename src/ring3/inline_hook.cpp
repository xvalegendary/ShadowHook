#include "shadowhook/ring3/inline_hook.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/memory.hpp"
#include <algorithm>

namespace shadowhook::ring3 {

    hook_status inline_hook::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (inline_hooks_.count(target)) {
            return hook_status::already_hooked;
        }

        size_t patch_size = 0;
        uint8_t* code_ptr = (uint8_t*)target;

        while (patch_size < 14) {
            auto info = asm_stubs::decode(code_ptr + patch_size, 32);
            if (info.length == 0) {
                SH_LOG_ERROR("[inline_hook] decode failed at %p + %zu", target, patch_size);
                return hook_status::unsupported;
            }
            patch_size += info.length;
        }

      
        void* trampoline = memory::allocate_rwx_near(target, patch_size + 32);
        if (!trampoline) return hook_status::alloc_failed;

        uint8_t* t_ptr = (uint8_t*)trampoline;
        size_t t_offset = 0;
        size_t p_offset = 0;

        while (p_offset < patch_size) {
            auto info = asm_stubs::decode(code_ptr + p_offset, patch_size - p_offset);
            if (info.length == 0) {
                memory::free_rwx(trampoline);
                return hook_status::unsupported;
            }

            memcpy(t_ptr + t_offset, code_ptr + p_offset, info.length);

            if (info.is_relative) {
                if (info.rel_size == 1) {
                    int8_t rel8 = *(int8_t*)(code_ptr + p_offset + info.rel_offset);
                    uintptr_t target_addr = (uintptr_t)code_ptr + p_offset + info.length + rel8;
                    int64_t new_rel = (int64_t)target_addr - ((uintptr_t)t_ptr + t_offset + info.length);

                    if (new_rel >= INT8_MIN && new_rel <= INT8_MAX) {
                        *(int8_t*)(t_ptr + t_offset + info.rel_offset) = (int8_t)new_rel;
                    }
                    else {
            
                        memory::free_rwx(trampoline);
                        return hook_status::unsupported;
                    }
                }
                else if (info.rel_size == 4) {
                    int32_t rel = *(int32_t*)(code_ptr + p_offset + info.rel_offset);
                    uintptr_t target_addr = (uintptr_t)code_ptr + p_offset + info.length + rel;
                    int64_t new_rel = (int64_t)target_addr - ((uintptr_t)t_ptr + t_offset + info.length);

                    if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                        *(int32_t*)(t_ptr + t_offset + info.rel_offset) = (int32_t)new_rel;
                    }
                    else {
                      
                        memory::free_rwx(trampoline);
                        return hook_status::unsupported;
                    }
                }
            }

            if (info.is_rip_relative) {
                int32_t disp = *(int32_t*)(code_ptr + p_offset + info.rip_disp_offset);
                uintptr_t target_addr = (uintptr_t)code_ptr + p_offset + info.length + disp;
                int64_t new_disp = (int64_t)target_addr - ((uintptr_t)t_ptr + t_offset + info.length);

                if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                    *(int32_t*)(t_ptr + t_offset + info.rip_disp_offset) = (int32_t)new_disp;
                }
                else {
                    memory::free_rwx(trampoline);
                    return hook_status::unsupported;
                }
            }

            t_offset += info.length;
            p_offset += info.length;
        }

        asm_stubs::write_jmp_abs(t_ptr + t_offset, (uint8_t*)target + patch_size);

        DWORD old;
        if (!memory::protect(target, patch_size, PAGE_EXECUTE_READWRITE, &old)) {
            memory::free_rwx(trampoline);
            return hook_status::protect_failed;
        }

        auto* ie = new inline_entry();
        ie->target = target;
        ie->detour = detour;
        ie->trampoline = trampoline;
        ie->patch_size = patch_size;
        ie->saved_bytes_dyn.assign((uint8_t*)target, (uint8_t*)target + patch_size);
        ie->original = trampoline;
        ie->active = true;

        asm_stubs::write_jmp_abs(target, detour);
        for (size_t i = sizeof(asm_stubs::jmp_abs); i < patch_size; i++) {
            ((uint8_t*)target)[i] = 0x90;
        }

        MemoryBarrier();

        DWORD tmp;
        memory::protect(target, patch_size, old, &tmp);

        if (original) *original = trampoline;

        inline_hooks_[target] = ie;
        hooks_.push_back({ target, detour, trampoline, patch_size, true });

        SH_LOG_INFO("[inline_hook] %p -> %p (tramp=%p, patch=%zu)", target, detour, trampoline, patch_size);
        return hook_status::success;
    }

    hook_status inline_hook::uninstall(void* target) {
        auto it = inline_hooks_.find(target);
        if (it == inline_hooks_.end()) return hook_status::not_hooked;

        auto* ie = it->second;

        DWORD old;
        if (!memory::protect(target, ie->patch_size, PAGE_EXECUTE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        memcpy(target, ie->saved_bytes_dyn.data(), ie->patch_size);
        MemoryBarrier();

        DWORD tmp;
        memory::protect(target, ie->patch_size, old, &tmp);

        memory::free_rwx(ie->trampoline);
        delete ie;

        inline_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        SH_LOG_INFO("[inline_hook] restored %p", target);
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