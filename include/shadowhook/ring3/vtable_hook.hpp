#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/memory.hpp"
#include "shadowhook/utils/thread_quiescence.hpp"
#include <mutex>
#include <unordered_map>
namespace shadowhook::ring3 {
enum class vtable_mode { instance_local, shared_slot };
enum class vtable_state { prepared, installed, restoring, failed };
struct vtable_options {
    std::size_t slot{};
    std::size_t method_count{}; // ABI-provided exact count, never inferred by scanning memory
    vtable_mode mode{vtable_mode::instance_local};
    std::size_t prefix_slots{1}; // MSVC RTTI COL at [-1]; use 0 for COM/no-RTTI tables
};
struct vtable_report {
    vtable_state state{vtable_state::prepared};
    vtable_mode mode{vtable_mode::instance_local};
    std::size_t slot{},method_count{};
    void** original_table{};
    void** replacement_table{};
    bool published{};
    std::vector<memory::page_protection> pages;
};
class vtable_hook final : public hook_base {
public:
    explicit vtable_hook(std::shared_ptr<threading::execution_domain> domain={},
                         memory::patch_api api={});
    ~vtable_hook() override;
    // Compatibility only: shared slot 0. New callers must supply explicit layout.
    hook_status install(void* instance,void* detour,void** original) override;
    hook_status install_slot(void* instance,const vtable_options& options,
                             void* detour,void** original=nullptr);
    hook_status install_method(void* instance,void* method,vtable_options options,
                               void* detour,void** original=nullptr);
    hook_status uninstall(void* instance) override;
    hook_status uninstall_all() override;
    hook_status recover(void* instance) {return uninstall(instance);}
    hook_status shutdown() {return uninstall_all();}
    bool is_hooked(void* instance) const override;
    std::size_t active_count() const override;
    hook_type type() const override {return hook_type::vtable;}
    const char* name() const override {return "vtable";}
    std::shared_ptr<threading::execution_domain> execution_domain() const;
    threading::execution_scope enter_execution() const;
    bool inspect(void* instance,vtable_report& report) const;
private:
    struct record;
    struct runtime;
    std::unique_ptr<runtime> runtime_;
    hook_status install_locked(void* instance,const vtable_options& options,
                               void* detour,void** original);
    hook_status apply(record& item,bool installed);
    bool healthy_locked() const;
};
}
