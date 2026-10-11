#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/memory.hpp"
#include <mutex>
#include <unordered_map>
namespace shadowhook::ring0 {
class iat_shadow final : public hook_base {
public:
    ~iat_shadow() override;
    hook_status install(void* target, void* detour, void** original) override;
    hook_status install_module(void* module, void* target, void* detour, void** original,
                               bool all_matches = true);
    hook_status install_slot(void* module, void** slot, void* target, void* detour, void** original);
    hook_status uninstall(void* target) override;
    hook_status uninstall_all() override;
    bool is_hooked(void* target) const override;
    std::size_t active_count() const override;
    hook_type type() const override { return hook_type::iat_shadow; }
    const char* name() const override { return "iat_shadow"; }
    void* resolve_import(const char* module, const char* function);
    static void** find_iat_entry_addr(void* module, const char* import_module, const char* function);
    static std::vector<void**> find_iat_slots(void* module, void* target);
private:
    struct iat_entry {
        void** slot{};
        void* original{};
        void* detour{};
        std::vector<memory::page_protection> pages;
        bool active{};
    };
    using registry = std::unordered_map<void*, std::vector<iat_entry>>;
    std::unique_ptr<registry> records_{std::make_unique<registry>()};
    mutable std::mutex mutex_;
    hook_status install_selected(void* target, void* detour, void** original,
                                 const std::vector<void**>& slots);
    hook_status restore(iat_entry& entry);
};
} // namespace shadowhook::ring0
