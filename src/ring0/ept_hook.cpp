#include "shadowhook/ring0/ept_hook.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::ring0 {

    hook_status ept_hook::install(void* target, void* detour, void** original) {
        (void)target; (void)detour; (void)original;
        SH_LOG_WARN("[ept] EPT hooking requires hypervisor backend (not available in usermode)");
        return hook_status::unsupported;
    }

    hook_status ept_hook::uninstall(void* target) {
        (void)target;
        return hook_status::unsupported;
    }

    hook_status ept_hook::uninstall_all() {
        return hook_status::unsupported;
    }

    bool ept_hook::is_hooked(void* target) const {
        (void)target;
        return false;
    }

} // namespace shadowhook::ring0