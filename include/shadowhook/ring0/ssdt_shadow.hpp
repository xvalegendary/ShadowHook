#pragma once
#include "shadowhook/core/hook_base.hpp"

namespace shadowhook::ring0 {

    class ssdt_shadow : public hook_base {
    public:
        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::ssdt_shadow; }
        const char* name() const override { return "ssdt_shadow"; }
    };

} // namespace shadowhook::ring0