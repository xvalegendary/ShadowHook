#pragma once
#include "shadowhook/core/hook_base.hpp"
#include <unordered_map>

namespace shadowhook::ring3 {

    class vtable_hook : public hook_base {
    public:
        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::vtable; }
        const char* name() const override { return "vtable"; }

    private:
        struct vtable_entry : entry {
            void** vtable_ptr;
            uint32_t  method_index;
            void* original_method;
        };

        std::unordered_map<void*, vtable_entry> vtable_hooks_;

        uint32_t find_vtable_index(void** vtable, void* target_method, size_t max_scan = 1024);
    };

} // namespace shadowhook::ring3