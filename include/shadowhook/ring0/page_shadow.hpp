#pragma once
#include "shadowhook/core/hook_base.hpp"
#include <unordered_map>

namespace shadowhook::ring0 {

    class page_shadow : public hook_base {
    public:
        page_shadow();
        ~page_shadow() override;

        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::page_shadow; }
        const char* name() const override { return "page_shadow"; }

    private:
        struct shadow_entry : entry {
            void* original_page;
            void* shadow_page;
            void* trampoline;
            size_t   page_offset;
            size_t   copy_size;
        };

        std::unordered_map<void*, shadow_entry> shadow_hooks_;

        void* allocate_shadow(void* original_page);
        void  destroy_shadow(void* shadow_page);
        void* build_trampoline(void* shadow_page, void* detour,
            void* original_page, size_t offset, size_t copy_size);
        void  destroy_trampoline(void* trampoline);
    };

} // namespace shadowhook::ring0