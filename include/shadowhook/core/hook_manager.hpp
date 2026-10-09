#pragma once
#include "hook_base.hpp"
#include <memory>
#include <unordered_map>
#include <mutex>

namespace shadowhook {

    class hook_manager {
    public:
        static hook_manager& instance();

        hook_manager(const hook_manager&) = delete;
        hook_manager& operator=(const hook_manager&) = delete;

        hook_status install(hook_type type, void* target, void* detour, void** original);
        hook_status uninstall(void* target);
        hook_status uninstall_all();
        hook_status uninstall_type(hook_type type);

        bool is_hooked(void* target) const;
        size_t total_active() const;
        void dump_status() const;

        void register_backend(std::unique_ptr<hook_base> backend);
        hook_base* get_backend(hook_type type);

    private:
        hook_manager();

        std::unordered_map<hook_type, std::unique_ptr<hook_base>> backends_;
        mutable std::mutex mutex_;

        hook_type resolve_type(void* target, hook_type preferred) const;
    };

} // namespace shadowhook