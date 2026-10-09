#include "shadowhook/core/hook_manager.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook {

    hook_manager& hook_manager::instance() {
        static hook_manager inst;
        return inst;
    }

    hook_manager::hook_manager() {
        SH_LOG_INFO("hook_manager initialized");
    }

    void hook_manager::register_backend(std::unique_ptr<hook_base> backend) {
        if (!backend) return;
        auto type = backend->type();
        std::lock_guard<std::mutex> lock(mutex_);
        SH_LOG_INFO("registering backend: %s", backend->name());
        backends_[type] = std::move(backend);
    }

    hook_base* hook_manager::get_backend(hook_type type) {
        auto it = backends_.find(type);
        return it != backends_.end() ? it->second.get() : nullptr;
    }

    hook_status hook_manager::install(hook_type type, void* target,
        void* detour, void** original) {
        if (!target || !detour) {
            SH_LOG_ERROR("install: null target or detour");
            return hook_status::invalid_address;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto* backend = get_backend(type);
        if (!backend) {
            SH_LOG_ERROR("no backend for type '%s'", type_str(type));
            return hook_status::unsupported;
        }

        if (backend->is_hooked(target)) {
            SH_LOG_WARN("target %p already hooked by %s", target, backend->name());
            return hook_status::already_hooked;
        }

        auto status = backend->install(target, detour, original);
        if (status == hook_status::success) {
            SH_LOG_INFO("[%s] hook installed: %p -> %p", backend->name(), target, detour);
        }
        else {
            SH_LOG_ERROR("[%s] install failed: %s (target=%p)", backend->name(), status_str(status), target);
        }

        return status;
    }

    hook_status hook_manager::uninstall(void* target) {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& [type, backend] : backends_) {
            if (backend->is_hooked(target)) {
                auto status = backend->uninstall(target);
                if (status == hook_status::success) {
                    SH_LOG_INFO("[%s] hook removed: %p", backend->name(), target);
                }
                else {
                    SH_LOG_ERROR("[%s] uninstall failed: %s (target=%p)", backend->name(), status_str(status), target);
                }
                return status;
            }
        }

        SH_LOG_WARN("uninstall: target %p not hooked", target);
        return hook_status::not_hooked;
    }

    hook_status hook_manager::uninstall_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        hook_status final_status = hook_status::success;

        for (auto& [type, backend] : backends_) {
            auto status = backend->uninstall_all();
            if (status != hook_status::success) {
                SH_LOG_WARN("[%s] uninstall_all returned %s", backend->name(), status_str(status));
                final_status = hook_status::partial;
            }
            else {
                SH_LOG_INFO("[%s] all hooks removed", backend->name());
            }
        }

        return final_status;
    }

    hook_status hook_manager::uninstall_type(hook_type type) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto* backend = get_backend(type);
        if (!backend) return hook_status::unsupported;

        auto status = backend->uninstall_all();
        if (status == hook_status::success) {
            SH_LOG_INFO("[%s] all hooks removed (by type)", backend->name());
        }
        return status;
    }

    bool hook_manager::is_hooked(void* target) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [type, backend] : backends_) {
            if (backend->is_hooked(target)) return true;
        }
        return false;
    }

    size_t hook_manager::total_active() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& [type, backend] : backends_) {
            total += backend->active_count();
        }
        return total;
    }

    void hook_manager::dump_status() const {
        std::lock_guard<std::mutex> lock(mutex_);
        SH_LOG_INFO("   hk status: ");
        for (const auto& [type, backend] : backends_) {
            SH_LOG_INFO("  %-16s [%s] %zu active",
                backend->name(),
                backend->active_count() > 0 ? "+" : "-",
                backend->active_count());
        }
    }

    hook_type hook_manager::resolve_type(void* target, hook_type preferred) const {
        (void)target;
        return preferred;
    }

} // namespace shadowhook