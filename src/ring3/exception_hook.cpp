#include "shadowhook/ring3/exception_hook.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::ring3 {

    static exception_hook* g_instance = nullptr;

    exception_hook::exception_hook() : veh_handle_(nullptr) {
        g_instance = this;
        veh_handle_ = AddVectoredExceptionHandler(1, veh_handler);
        if (veh_handle_) {
            SH_LOG_INFO("[exception_veh] VEH handler registered");
        }
        else {
            SH_LOG_ERROR("[exception_veh] failed to register VEH handler");
        }
    }

    exception_hook::~exception_hook() {
        if (veh_handle_) {
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
        }
        g_instance = nullptr;
    }

    hook_status exception_hook::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (veh_hooks_.count(target)) {
            return hook_status::already_hooked;
        }

        DWORD old;
        if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old)) {
            SH_LOG_ERROR("[exception_veh] protect failed for %p", target);
            return hook_status::protect_failed;
        }

        uint8_t original_byte = *(uint8_t*)target;

        *(uint8_t*)target = 0xCC;

        DWORD tmp;
        VirtualProtect(target, 1, old, &tmp);

        veh_entry ve = {};
        ve.target = target;
        ve.detour = detour;
        ve.original = nullptr;
        ve.patch_size = 1;
        ve.saved_bytes[0] = original_byte;
        ve.target_page = get_page_base(target);
        ve.active = true;

        if (original) {
            ve.original = (void*)target;
            *original = ve.original;
        }

        veh_hooks_[target] = ve;
        hooks_.push_back({ target, detour, ve.original, 1, {original_byte, 0}, true });

        SH_LOG_INFO("[exception_veh] breakpoint set at %p (orig=0x%02X)",
            target, original_byte);

        return hook_status::success;
    }

    hook_status exception_hook::uninstall(void* target) {
        auto it = veh_hooks_.find(target);
        if (it == veh_hooks_.end()) return hook_status::not_hooked;

        auto& ve = it->second;

        DWORD old;
        if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        *(uint8_t*)target = ve.saved_bytes[0];

        DWORD tmp;
        VirtualProtect(target, 1, old, &tmp);

        SH_LOG_INFO("[exception_veh] breakpoint removed at %p", target);

        veh_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        return hook_status::success;
    }

    hook_status exception_hook::uninstall_all() {
        auto copy = veh_hooks_;
        for (auto& [target, _] : copy) {
            uninstall(target);
        }
        return hook_status::success;
    }

    bool exception_hook::is_hooked(void* target) const {
        return veh_hooks_.count(target) > 0;
    }

    LONG NTAPI exception_hook::veh_handler(PEXCEPTION_POINTERS ep) {
        if (!g_instance) return EXCEPTION_CONTINUE_SEARCH;

        if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP &&
            ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        void* ip = (void*)ep->ContextRecord->Rip;

        auto it = g_instance->veh_hooks_.find(ip);
        if (it == g_instance->veh_hooks_.end()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        auto& ve = it->second;

        uint8_t* p = (uint8_t*)ip;
        DWORD old;
        VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
        *p = ve.saved_bytes[0];
        DWORD tmp;
        VirtualProtect(p, 1, old, &tmp);

        ep->ContextRecord->EFlags |= (1 << 8);

        ep->ContextRecord->Rip = (DWORD64)ve.detour;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    bool exception_hook::make_page_guard(void* page) {
        DWORD old;
        if (!VirtualProtect(page, 1, PAGE_GUARD | PAGE_EXECUTE_READ, &old)) {
            SH_LOG_ERROR("[exception_veh] guard page failed for %p", page);
            return false;
        }
        return true;
    }

    bool exception_hook::clear_page_guard(void* page) {
        DWORD old;
        if (!VirtualProtect(page, 1, PAGE_EXECUTE_READ, &old)) return false;
        return true;
    }

} // namespace shadowhook::ring3