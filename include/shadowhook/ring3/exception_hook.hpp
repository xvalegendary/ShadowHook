#pragma once
#include "shadowhook/core/hook_base.hpp"
#include <unordered_map>

namespace shadowhook::ring3 {

    class exception_hook : public hook_base {
    public:
        exception_hook();
        ~exception_hook() override;

        hook_status install(void* target, void* detour, void** original) override;
        hook_status uninstall(void* target) override;
        hook_status uninstall_all() override;
        bool is_hooked(void* target) const override;
        hook_type type() const override { return hook_type::exception_veh; }
        const char* name() const override { return "exception_veh"; }

    private:
        struct veh_entry : entry {
            void* target_page;
            uint32_t page_offset;
        };

        std::unordered_map<void*, veh_entry> veh_hooks_;
        void* veh_handle_;

        static LONG NTAPI veh_handler(PEXCEPTION_POINTERS ep);

        void* get_page_base(void* addr) const {
            return (void*)((uintptr_t)addr & ~0xFFFULL);
        }

        bool make_page_guard(void* page);
        bool clear_page_guard(void* page);
    };

} // namespace shadowhook::ring3