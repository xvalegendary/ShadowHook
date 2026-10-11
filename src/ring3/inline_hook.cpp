#include "shadowhook/ring3/inline_hook.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/ring3/relocated_prologue.hpp"
#include "shadowhook/ring3/hotpatch_hook.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace shadowhook::ring3 {
namespace {
bool pin_image_code(void* address) {
    MEMORY_BASIC_INFORMATION info{};
    if(VirtualQuery(address,&info,sizeof(info))!=sizeof(info))return false;
    if(info.Type!=MEM_IMAGE)return true;
    HMODULE module{};
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(address),&module)!=0;
}
}
inline_hook::inline_hook(std::shared_ptr<threading::execution_domain> d, memory::patch_api api)
    : runtime_(std::make_unique<runtime>()) {
    runtime_->domain = d?std::move(d):std::make_shared<threading::execution_domain>();
    runtime_->api = api;
    if (!api.protect || !api.flush) throw std::invalid_argument("patch_api requires both functions");
    if (runtime_->domain && !runtime_->domain->bind(runtime_.get()))
        throw std::invalid_argument("execution_domain already owned or faulted");
}
inline_hook::~inline_hook() {
    try {
        if (shutdown() == hook_status::success) {
            if (runtime_->domain) runtime_->domain->unbind(runtime_.get());
            return;
        }
    } catch (...) {}
    auto* retained = runtime_.release();
    try {
        if (retained->domain) retained->domain->close();
        SH_LOG_ERROR("[inline_hook] failed shutdown: entire runtime quarantined");
    } catch (...) {} 
}
hook_status inline_hook::configure_execution(std::shared_ptr<threading::execution_domain> d) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    if (!runtime_->entries.empty() || (runtime_->domain && runtime_->domain != d)) return hook_status::busy;
    if (d && !d->bind(runtime_.get())) return hook_status::busy;
    runtime_->domain = std::move(d);
    return hook_status::success;
}
bool inline_hook::healthy_locked() const {
    for (const auto& kv : runtime_->entries)
        if (kv.second->state == patch_state::failed) return false;
    return true;
}
std::shared_ptr<threading::execution_domain> inline_hook::execution_domain() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->domain;
}
original_lease inline_hook::pin_original(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto it = runtime_->entries.find(target);
    if (it == runtime_->entries.end() || it->second->state != patch_state::patched) return {};
    return original_lease(it->second->owner, it->second->trampoline);
}
bool inline_hook::inspect(void* target, patch_report& report) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto it = runtime_->entries.find(target);
    if (it == runtime_->entries.end()) return false;
    const auto& e = *it->second;
    report = {e.state, e.patch_installed, e.bytes_known, e.cache_flushed, e.pages};
    return true;
}
std::size_t inline_hook::active_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->entries.size();
}
std::size_t inline_hook::retired_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->retired;
}
bool inline_hook::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->entries.count(target) != 0;
}
hook_status inline_hook::apply(inline_entry& e, bool patched) {
    const auto prior = e.state;
    auto& current=e.observed;
    if(!memory::safe_copy(current.data(),e.target,current.size()))return hook_status::invalid_address;
    if(e.bytes_known && current != (e.patch_installed?e.patch:e.saved)) {
        e.state=patch_state::failed;
        return hook_status::partial;
    }
    e.state = patched ? patch_state::prepared : patch_state::restoring;
    if (!memory::make_writable(e.pages, runtime_->api)) {
        const bool restored = memory::restore_pages(e.pages, runtime_->api);
        e.state = restored ? prior : patch_state::failed;
        return restored ? hook_status::protect_failed : hook_status::partial;
    }
    const auto& bytes = patched ? e.patch : e.saved;
    e.bytes_known = false;
    const bool copied = memory::safe_copy(e.target, bytes.data(), bytes.size());
    if (copied) { e.patch_installed = patched; e.bytes_known = true; }
    e.cache_flushed = copied && runtime_->api.flush(GetCurrentProcess(), e.target, bytes.size()) != 0;
    const bool restored = memory::restore_pages(e.pages, runtime_->api);
    if (!copied || !e.cache_flushed || !restored) {
        e.state = patch_state::failed;
        return hook_status::partial;
    }
    e.state = patched ? patch_state::patched : patch_state::prepared;
    return hook_status::success;
}

hook_status inline_hook::install(void* target, void* detour, void** original) try {
    if (original) *original = nullptr;
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto& rt = *runtime_;
    if (!rt.domain) return hook_status::unsupported;
    threading::patch_scope transaction(rt.domain);
    if (!transaction) return hook_status::busy;
    if (!healthy_locked()) return hook_status::partial;
    if (!target || !detour || target == detour) return hook_status::invalid_address;
    if (rt.entries.count(target)) return hook_status::already_hooked;
    if (!memory::is_executable(target) || !memory::is_executable(detour) ||
        !pin_image_code(target) || !pin_image_code(detour)) return hook_status::invalid_address;


    relocated_prologue relocated;
    const auto prepared=prepare_prologue(target,5,relocated,detour);
    if(prepared!=hook_status::success)return prepared;
    const auto patch_size=relocated.saved.size();
    if(hotpatch_hook::reserves_range(target,patch_size))return hook_status::already_hooked;
    const auto source_start=reinterpret_cast<std::uintptr_t>(target);
    const auto detour_address=reinterpret_cast<std::uintptr_t>(detour);
    if(detour_address>=source_start && detour_address-source_start<patch_size)
        return hook_status::invalid_address;
    for(const auto& kv:rt.entries) {
        const auto existing=reinterpret_cast<std::uintptr_t>(kv.first);
        if(source_start<existing+kv.second->saved.size() && existing<source_start+patch_size)
            return hook_status::already_hooked;
    }
    void* trampoline=relocated.entry;
    auto reclaim = std::make_shared<std::atomic<bool>>(true);
    auto* backing=new std::shared_ptr<void>(std::move(relocated.owner));
    std::shared_ptr<void> owner(trampoline,[reclaim,backing](void*) noexcept {
        if(reclaim->load(std::memory_order_relaxed))delete backing;
    });
    auto record = std::make_unique<inline_entry>();
    record->target = target;
    record->trampoline = trampoline;
    record->owner = owner;
    record->reclaim = reclaim;
    record->saved.resize(patch_size);
    if (!memory::safe_copy(record->saved.data(), target, patch_size) ||
        !memory::capture_pages(target, patch_size, record->pages)) return hook_status::invalid_address;
    record->observed.resize(patch_size);
    record->patch.resize(patch_size, 0x90);
    record->patch[0]=0xE9;
    const auto distance=reinterpret_cast<std::intptr_t>(relocated.redirect)-
                        reinterpret_cast<std::intptr_t>(target)-5;
    if(distance<INT32_MIN || distance>INT32_MAX)return hook_status::unsupported;
    const auto displacement=static_cast<std::int32_t>(distance);
    std::memcpy(record->patch.data()+1,&displacement,4);
    auto& e = *record;
    rt.entries.emplace(target, std::move(record)); 
    const auto result = apply(e, true);
    if (result == hook_status::busy) {
        rt.entries.erase(target);
        return result;
    }
    if (result != hook_status::success) {
        const auto rollback = apply(e, false);
        if (rollback == hook_status::success) {
            rt.entries.erase(target);
            transaction.healthy(healthy_locked());
            return hook_status::protect_failed;
        }
        e.state = patch_state::failed;
        transaction.healthy(false);
        return hook_status::partial;
    }
    if (original) {
        e.raw_published = true;
        reclaim->store(false, std::memory_order_relaxed);
        *original = trampoline; 
    }
    transaction.healthy(healthy_locked());
    return hook_status::success;
}
catch (const std::bad_alloc&) { return hook_status::alloc_failed; }

hook_status inline_hook::uninstall(void* target) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto& rt = *runtime_;
    const auto it = rt.entries.find(target);
    if (it == rt.entries.end()) return hook_status::not_hooked;
    threading::patch_scope transaction(rt.domain);
    if (!transaction) return hook_status::busy;
    auto& e = *it->second;
    const auto result = apply(e, false);
    if (result != hook_status::success) {
        if (result == hook_status::partial) e.state = patch_state::failed;
        transaction.healthy(healthy_locked());
        return result;
    }
    e.reclaim->store(false,std::memory_order_relaxed);
    ++rt.retired;
    rt.entries.erase(it); 
    transaction.healthy(healthy_locked());
    return hook_status::success;
}
hook_status inline_hook::uninstall_all() try {
    std::vector<void*> targets;
    {
        std::lock_guard<std::mutex> lock(runtime_->mutex);
        targets.reserve(runtime_->entries.size());
        for (const auto& p : runtime_->entries) targets.push_back(p.first);
    }
    auto result = hook_status::success;
    for (auto* target : targets) {
        const auto status = uninstall(target);
        if (status != hook_status::success && status != hook_status::not_hooked)
            result = hook_status::partial;
    }
    return result;
}
catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
} // namespace shadowhook::ring3
