#pragma once
#include "shadowhook/core/hook_base.hpp"
#include "shadowhook/utils/thread_quiescence.hpp"
#include "shadowhook/utils/memory.hpp"
#include <mutex>
#include <string>
#include <utility>
#include <unordered_map>
namespace shadowhook::ring3 {
struct owned_image_runtime;
class image_export final {
public:
    image_export()=default;
    image_export(image_export&& other) noexcept
        :owner_(std::move(other.owner_)),scope_(std::move(other.scope_)),
         address_(std::exchange(other.address_,nullptr)) {}
    image_export& operator=(image_export&& other) noexcept {
        if(this!=&other) {
            scope_={}; 
            owner_=std::move(other.owner_);
            scope_=std::move(other.scope_);
            address_=std::exchange(other.address_,nullptr);
        }
        return *this;
    }
    explicit operator bool() const noexcept {return address_!=nullptr && static_cast<bool>(scope_);}
    template<class Function> Function as() const noexcept {return static_cast<bool>(*this)?reinterpret_cast<Function>(address_):nullptr;}
private:
    friend class owned_dll_image;
    std::shared_ptr<owned_image_runtime> owner_; 
    threading::execution_scope scope_;
    void* address_{};
};
class owned_dll_image final {
public:
    owned_dll_image()=default;
    image_export pin_export(const char* name) const;
    void* base() const noexcept;
    std::size_t image_size() const noexcept;
private:
    friend class dll_hollow;
    std::shared_ptr<owned_image_runtime> runtime_;
};

class dll_hollow final : public hook_base {
public:
    explicit dll_hollow(memory::patch_api api={});
    ~dll_hollow() override;
    hook_status load_image(const wchar_t* path,owned_dll_image& out,std::size_t capacity=0);
    hook_status replace_image(owned_dll_image& target,const wchar_t* replacement,
                              owned_dll_image* original_snapshot=nullptr);
    hook_status restore_image(owned_dll_image& target);
    hook_status install(void*,void*,void** original) override;
    hook_status uninstall(void* target) override;
    hook_status uninstall_all() override;
    bool is_hooked(void* target) const override;
    std::size_t active_count() const override;
    hook_type type() const override {return hook_type::dll_hollow;}
    const char* name() const override {return "dll_hollow";}
private:
    struct image_backup;
    memory::patch_api api_;
    mutable std::mutex mutex_;
    using image_map=std::unordered_map<void*,std::shared_ptr<image_backup>>;
    std::unique_ptr<image_map> images_=std::make_unique<image_map>();
    hook_status restore_locked(void* target);
};
}
