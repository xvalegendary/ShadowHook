#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/ring3/breakpoint_dispatch.hpp"
namespace shadowhook::ring0 {
class page_shadow final : public hook_base {
public:
    page_shadow():dispatch_(true) {}
    ~page_shadow() override=default;
    hook_status install(void* t,void* d,void** o) override {return dispatch_.install(t,d,o);}
    hook_status uninstall(void* t) override {return dispatch_.uninstall(t);}
    hook_status uninstall_all() override {return dispatch_.uninstall_all();}
    bool is_hooked(void* t) const override {return dispatch_.is_hooked(t);}
    std::size_t active_count() const override {return dispatch_.active_count();}
    hook_type type() const override {return hook_type::page_shadow;}
    const char* name() const override {return "page_shadow";}
    hook_status recover(void* t) {return dispatch_.uninstall(t);}
private:
    ring3::breakpoint_dispatch dispatch_;
};
}
