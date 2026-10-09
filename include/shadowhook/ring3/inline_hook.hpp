#pragma once
#include "shadowhook/core/hook_base.hpp"
#include <unordered_map>

namespace shadowhook::ring3 {

    class inline_hook : public hook_base {
    public:
        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::inline_hook; }
        const char* name() const override { return "inline_hook"; }

    private:
        struct inline_entry : entry {
            void* trampoline;
            size_t patch_size;
        };
        std::unordered_map<void*, inline_entry> inline_hooks_;
    };

} // namespace shadowhook::ring3