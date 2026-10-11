#pragma once
#include "shadowhook/core/hook_types.hpp"
#include "shadowhook/utils/memory.hpp"
#include <memory>
namespace shadowhook::ring3 {
class breakpoint_dispatch final {
public:
    explicit breakpoint_dispatch(bool shadow=false, memory::patch_api api={});
    ~breakpoint_dispatch();
    breakpoint_dispatch(const breakpoint_dispatch&)=delete;
    hook_status install(void* target,void* detour,void** original);
    hook_status uninstall(void* target);
    hook_status uninstall_all();
    bool is_hooked(void* target) const;
    std::size_t active_count() const;
private:
    struct runtime;
    std::unique_ptr<runtime> runtime_;
};
}
