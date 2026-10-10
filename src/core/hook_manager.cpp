#include "shadowhook/core/hook_manager.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook {
    hook_manager& hook_manager::instance() {
        static hook_manager singleton;
        return singleton;
    }
    hook_manager::hook_manager() {
        SH_LOG_INFO("hook_manager initialized");
    }
    void hook_manager::register_backend(std::unique_ptr<hook_base> candidate) {
        if (!candidate) return;
        std::lock_guard<std::mutex> lock(mutex_);
        const auto type = candidate->type();
        if (backends_.count(type)) {
            SH_LOG_WARN("backend %s already registered; refusing replacement", candidate->name());
            return;
        }
        SH_LOG_INFO("registering backend: %s", candidate->name());
        backends_.emplace(type, std::move(candidate));
    }
    hook_base* hook_manager::get_backend(hook_type type) {
        auto it = backends_.find(type);
        return it == backends_.end() ? nullptr : it->second.get();
    }
    hook_status hook_manager::install(hook_type type, void* target, void* detour, void** original) {
        if (original) *original = nullptr;
        if (!target || !detour) return hook_status::invalid_address;
        std::lock_guard<std::mutex> lock(mutex_);
        auto* backend = get_backend(type);
        if (!backend) return hook_status::unsupported;
        for (const auto& kv : backends_) {
            if (kv.second->is_hooked(target)) return hook_status::already_hooked;
        }
        return backend->install(target, detour, original);
    }
    hook_status hook_manager::uninstall(void* target) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& kv : backends_) {
            if (kv.second->is_hooked(target)) return kv.second->uninstall(target);
        }
        return hook_status::not_hooked;
    }
    hook_status hook_manager::uninstall_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto overall = hook_status::success;
        for (auto& kv : backends_) {
            if (kv.second->active_count() == 0) continue; 
            const auto result = kv.second->uninstall_all();
            if (result != hook_status::success || kv.second->active_count() != 0)
                overall = hook_status::partial;
        }
        return overall;
    }
    hook_status hook_manager::uninstall_type(hook_type type) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto* backend = get_backend(type);
        if (!backend) return hook_status::unsupported;
        if (backend->active_count() == 0) return hook_status::success;
        return backend->uninstall_all();
    }
    bool hook_manager::is_hooked(void* target) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& kv : backends_) if (kv.second->is_hooked(target)) return true;
        return false;
    }
    size_t hook_manager::total_active() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& kv : backends_) total += kv.second->active_count();
        return total;
    }
    void hook_manager::dump_status() const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& kv : backends_)
            SH_LOG_INFO("%-16s: %zu active", kv.second->name(), kv.second->active_count());
    }
    hook_type hook_manager::resolve_type(void* target, hook_type preferred) const {
        (void)target;
        return preferred;
    }
} // namespace shadowhook
