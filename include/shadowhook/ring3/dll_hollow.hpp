#pragma once
#include "shadowhook/core/hook_base.hpp"
#include <unordered_map>

namespace shadowhook::ring3 {

    class dll_hollow : public hook_base {
    public:
        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::dll_hollow; }
        const char* name() const override { return "dll_hollow"; }

    private:
        struct hollow_entry : entry {
            void** iat_slot;
            void* real_function;
        };
        std::unordered_map<void*, hollow_entry> hollow_hooks_;
    };

} // namespace shadowhook::ring3