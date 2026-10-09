#include "shadowhook/ring0/ssdt_shadow.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::ring0 {

    hook_status ssdt_shadow::install(void* target, void* detour, void** original) {
        (void)target; (void)detour; (void)original;
        SH_LOG_WARN("[ssdt] SSDT hooking requires kernel backend (not available in usermode)");
        return hook_status::unsupported;
    }

    hook_status ssdt_shadow::uninstall(void* target) {
        (void)target;
        return hook_status::unsupported;
    }

    hook_status ssdt_shadow::uninstall_all() {
        return hook_status::unsupported;
    }

    bool ssdt_shadow::is_hooked(void* target) const {
        (void)target;
        return false;
    }

} // namespace shadowhook::ring0