#pragma once
#include "hook_base.hpp"
#include "original_lease.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>

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
    std::shared_ptr<hook_base> get_backend(hook_type type) const;


    original_lease pin_inline_original(void* target) const;
private:
    hook_manager();
    std::unordered_map<hook_type, std::shared_ptr<hook_base>> backends_;
    mutable std::mutex mutex_;
    hook_type resolve_type(void* target, hook_type preferred) const;
};
} // namespace shadowhook
