#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/memory.hpp"
#include <array>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace shadowhook::ring3 {
enum class hotpatch_state { prepared, active, retired, failed };
struct hotpatch_report {
    hotpatch_state state{};
    bool entry_enabled{};
    bool preamble_written{};
    bool ever_published{};
    void* relay{};
    void* original{};
    std::vector<memory::page_protection> pages;
};

class hotpatch_hook final : public hook_base {
public:
    explicit hotpatch_hook(memory::patch_api api = {});
    ~hotpatch_hook() override;
    hook_status install(void* target, void* detour, void** original) override;
    hook_status uninstall(void* target) override;
    hook_status uninstall_all() override;
    hook_status recover(void* target) { return uninstall(target); }
    bool is_hooked(void* target) const override;
    std::size_t active_count() const override;
    bool inspect(void* target, hotpatch_report& report) const;
    static bool reserves_address(void* address);
    static bool reserves_range(void* address,std::size_t size);
    hook_type type() const override { return hook_type::hotpatch; }
    const char* name() const override { return "hotpatch"; }
private:
    struct site {
        void* entry{};
        void* allocation{};
        void* original{};
        void** route{};
        std::array<std::uint8_t,5> preamble{};
        std::vector<memory::page_protection> pages;
        hotpatch_state state{hotpatch_state::prepared};
        bool entry_enabled{};
        bool preamble_written{};
        bool ever_published{};
        std::shared_ptr<std::atomic<bool>> reserved;
    };
    struct runtime {
        mutable std::mutex mutex;
        memory::patch_api api;
        std::unordered_map<void*,std::unique_ptr<site>> sites;
    };
    std::unique_ptr<runtime> runtime_;
    hook_status prepare(site& item);
    hook_status switch_entry(site& item, bool enabled);
    hook_status retire(site& item);
};
} // namespace shadowhook::ring3

