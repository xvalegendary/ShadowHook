#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/pattern_scan.hpp"
#include <unordered_map>

namespace shadowhook::ring0 {

    class iat_shadow : public hook_base {
    public:
        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::iat_shadow; }
        const char* name() const override { return "iat_shadow"; }

        struct iat_entry : entry {
            void** iat_slot;
            void* real_function;
            char      func_name[128];
            char      module_name[64];
        };

        void* resolve_import(const char* module, const char* func_name);
        static void** find_iat_entry_addr(void* module_base, const char* import_module,
            const char* func_name);

    private:
        std::unordered_map<void*, iat_entry> iat_hooks_;
    };

} // namespace shadowhook::ring0