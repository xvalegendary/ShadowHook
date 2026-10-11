#include "shadowhook/core/hook_manager.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/ring3/inline_hook.hpp"

namespace shadowhook {
hook_manager& hook_manager::instance() {
    static auto* singleton = new hook_manager;
    return *singleton;
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
std::shared_ptr<hook_base> hook_manager::get_backend(hook_type type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = backends_.find(type);
    return it == backends_.end() ? nullptr : it->second;
}
hook_status hook_manager::install(hook_type type, void* target, void* detour, void** original) {
    if (original) *original = nullptr;
    if (!target || !detour) return hook_status::invalid_address;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = backends_.find(type);
    if (it == backends_.end()) return hook_status::unsupported;
    auto backend = it->second;
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
    const auto it = backends_.find(type);
    if (it == backends_.end()) return hook_status::unsupported;
    auto backend = it->second;
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
original_lease hook_manager::pin_inline_original(void* target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = backends_.find(hook_type::inline_hook);
    if (it == backends_.end()) return {};
    const auto* backend = dynamic_cast<const ring3::inline_hook*>(it->second.get());
    return backend ? backend->pin_original(target) : original_lease{};
}
std::shared_ptr<threading::execution_domain> hook_manager::inline_execution_domain() const {
    auto backend = std::dynamic_pointer_cast<ring3::inline_hook>(get_backend(hook_type::inline_hook));
    return backend ? backend->execution_domain() : nullptr;
}
threading::execution_scope hook_manager::enter_inline_execution() const {
    // Release registry/backend locks before waiting for admission. Executing
    // detours may need the registry lock to obtain their original lease.
    auto domain = inline_execution_domain();
    return domain ? domain->enter() : threading::execution_scope{};
}
hook_type hook_manager::resolve_type(void* target, hook_type preferred) const {
    (void)target;
    return preferred;
}
} // namespace shadowhook
