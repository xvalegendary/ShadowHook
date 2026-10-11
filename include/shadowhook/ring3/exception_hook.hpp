#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/ring3/breakpoint_dispatch.hpp"
namespace shadowhook::ring3 {
class exception_hook final : public hook_base {
public:
    exception_hook():dispatch_(false) {}
    ~exception_hook() override=default;
    hook_status install(void* t,void* d,void** o) override {return dispatch_.install(t,d,o);}
    hook_status uninstall(void* t) override {return dispatch_.uninstall(t);}
    hook_status uninstall_all() override {return dispatch_.uninstall_all();}
    bool is_hooked(void* t) const override {return dispatch_.is_hooked(t);}
    std::size_t active_count() const override {return dispatch_.active_count();}
    hook_type type() const override {return hook_type::exception_veh;}
    const char* name() const override {return "exception_veh";}
    hook_status recover(void* t) {return dispatch_.uninstall(t);}
private:
    ring3::breakpoint_dispatch dispatch_;
};
}
