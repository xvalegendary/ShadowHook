#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/core/original_lease.hpp"
#include "shadowhook/utils/thread_quiescence.hpp"
#include "shadowhook/utils/memory.hpp"
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace shadowhook::ring3 {
enum class patch_state { prepared, patched, restoring, failed };
struct patch_report {
    patch_state state{patch_state::prepared};
    bool patch_installed{};
    bool bytes_known{true};
    bool cache_flushed{};
    std::vector<memory::page_protection> pages;
};
class inline_hook final : public hook_base {
public:
    explicit inline_hook(std::shared_ptr<threading::execution_domain> domain = {},
                         memory::patch_api api = {});
    ~inline_hook() override;
    hook_status install(void* target, void* detour, void** original) override;
    hook_status uninstall(void* target) override;
    hook_status uninstall_all() override;
    hook_status shutdown() { return uninstall_all(); }
    hook_status recover(void* target) { return uninstall(target); }
    bool is_hooked(void* target) const override;
    std::size_t active_count() const override;
    hook_type type() const override { return hook_type::inline_hook; }
    const char* name() const override { return "inline_hook"; }
    hook_status configure_execution(std::shared_ptr<threading::execution_domain> domain);
    std::shared_ptr<threading::execution_domain> execution_domain() const;
    original_lease pin_original(void* target) const;
    bool inspect(void* target, patch_report& report) const;
    std::size_t retired_count() const;
private:
    struct inline_entry {
        void* target{};
        void* trampoline{};
        std::shared_ptr<void> owner;
        std::shared_ptr<std::atomic<bool>> reclaim;
        std::vector<std::uint8_t> saved;
        std::vector<std::uint8_t> patch;
        std::vector<std::uint8_t> observed;
        std::vector<memory::page_protection> pages;
        patch_state state{patch_state::prepared};
        bool patch_installed{};
        bool bytes_known{true};
        bool cache_flushed{true};
        bool raw_published{};
    };
    struct runtime {
        mutable std::mutex mutex;
        std::shared_ptr<threading::execution_domain> domain;
        memory::patch_api api;
        std::unordered_map<void*, std::unique_ptr<inline_entry>> entries;
        std::size_t retired{};
    };
    std::unique_ptr<runtime> runtime_;
    hook_status apply(inline_entry& record, bool patched);
    bool healthy_locked() const;
};
} // namespace shadowhook::ring3
