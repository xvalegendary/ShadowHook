#include "shadowhook/ring3/breakpoint_dispatch.hpp"
#include "shadowhook/ring3/relocated_prologue.hpp"
#include "shadowhook/ring3/hotpatch_hook.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <cstring>
namespace shadowhook::ring3 {
namespace {
struct redirect {
    void* target{};
    void* original{};
    std::atomic<void*> route{};
    redirect* next{};
    std::shared_ptr<void> trampoline;
    std::shared_ptr<void> shadow;
};
std::atomic<redirect*> redirects{};
LONG NTAPI handle_breakpoint(PEXCEPTION_POINTERS ep) {
    if(!ep || ep->ExceptionRecord->ExceptionCode!=EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    const auto address=ep->ExceptionRecord->ExceptionAddress;
    for(auto* node=redirects.load(std::memory_order_acquire);node;node=node->next)
        if(node->target==address) {
            const auto route=node->route.load(std::memory_order_acquire);
            if(!route)return EXCEPTION_CONTINUE_SEARCH;
            ep->ContextRecord->Rip=reinterpret_cast<DWORD64>(route);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    return EXCEPTION_CONTINUE_SEARCH;
}
bool ensure_handler() {
    static const bool ready=[] {
        HMODULE module{};
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                              reinterpret_cast<LPCWSTR>(&handle_breakpoint),&module))return false;
        return AddVectoredExceptionHandler(1,&handle_breakpoint)!=nullptr;
    }();
    return ready;
}
bool pin_code(void* address) {
    MEMORY_BASIC_INFORMATION region{};
    if(VirtualQuery(address,&region,sizeof(region))!=sizeof(region))return false;
    if(region.Type!=MEM_IMAGE)return true;
    HMODULE module{};
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(address),&module)!=0;
}
}
struct breakpoint_dispatch::runtime {
    struct site {
        redirect* node{};
        std::uint8_t saved{};
        std::vector<memory::page_protection> pages;
        bool written{};
        bool failed{};
    };
    mutable std::mutex mutex;
    std::unordered_map<void*,site> sites;
    memory::patch_api api;
    bool shadow{};
};
breakpoint_dispatch::breakpoint_dispatch(bool shadow,memory::patch_api api):runtime_(std::make_unique<runtime>()) {
    runtime_->shadow=shadow;runtime_->api=api;
}
breakpoint_dispatch::~breakpoint_dispatch() {
    try { if(uninstall_all()==hook_status::success)return; } catch(...) {}
    (void)runtime_.release(); 
}
hook_status breakpoint_dispatch::install(void* target,void* detour,void** original) try {
    if(original)*original=nullptr;
    auto& rt=*runtime_;
    std::lock_guard<std::mutex> lock(rt.mutex);
    if(!target || !detour || target==detour || !memory::is_executable(detour))
        return hook_status::invalid_address;
    if(rt.sites.count(target) || hotpatch_hook::reserves_range(target,1))return hook_status::already_hooked;
    if(!ensure_handler())return hook_status::unsupported;
    relocated_prologue relocated;
    auto result=prepare_prologue(target,1,relocated);
    if(result!=hook_status::success)return result;
    if(relocated.saved[0]==0xCC)return hook_status::unsupported;
    if(!pin_code(target) || !pin_code(detour))return hook_status::invalid_address;
    auto node=std::make_unique<redirect>();
    node->target=target;node->original=relocated.entry;node->trampoline=std::move(relocated.owner);
    void* route=detour;
    if(rt.shadow) {
        SYSTEM_INFO info{};GetSystemInfo(&info);
        const auto value=reinterpret_cast<std::uintptr_t>(target);
        const auto page=value-value%info.dwPageSize;
        const auto offset=value-page;
        auto shadow=std::shared_ptr<void>(memory::allocate_rwx(info.dwPageSize*2),&memory::free_rwx);
        if(!shadow)return hook_status::alloc_failed;
        if(!memory::readable_range(reinterpret_cast<void*>(page),info.dwPageSize) ||
           !memory::safe_copy(shadow.get(),reinterpret_cast<void*>(page),info.dwPageSize))
            return hook_status::invalid_address;
        route=static_cast<std::uint8_t*>(shadow.get())+offset;
        asm_stubs::write_jmp_abs(route,detour);
        DWORD old{};
        if(!VirtualProtect(shadow.get(),info.dwPageSize*2,PAGE_EXECUTE_READ,&old) ||
           !FlushInstructionCache(GetCurrentProcess(),route,14))return hook_status::protect_failed;
        node->shadow=std::move(shadow);
    }
    runtime::site site;
    site.node=node.get();site.saved=relocated.saved[0];
    if(!memory::capture_pages(target,1,site.pages))return hook_status::invalid_address;
    rt.sites.emplace(target,std::move(site)); 
    auto& record=rt.sites.at(target);
    node->route.store(node->original,std::memory_order_relaxed);
    auto* published=node.release();
    auto* head=redirects.load(std::memory_order_acquire);
    do {published->next=head;} while(!redirects.compare_exchange_weak(head,published,
         std::memory_order_release,std::memory_order_acquire));
    if(!memory::make_writable(record.pages,rt.api)) {
        const bool restored=memory::restore_pages(record.pages,rt.api);
        if(restored){rt.sites.erase(target);return hook_status::protect_failed;}
        record.failed=true;return hook_status::partial;
    }
    const auto previous=InterlockedCompareExchange8(reinterpret_cast<volatile CHAR*>(target),
                                                    static_cast<CHAR>(0xCC),static_cast<CHAR>(record.saved));
    record.written=static_cast<std::uint8_t>(previous)==record.saved;
    const bool flushed=record.written && rt.api.flush(GetCurrentProcess(),target,1)!=0;
    const bool restored=memory::restore_pages(record.pages,rt.api);
    if(!record.written || !flushed || !restored) {record.failed=true;return hook_status::partial;}
    published->route.store(route,std::memory_order_release);
    if(original)*original=published->original;
    return hook_status::success;
} catch(const std::bad_alloc&) {return hook_status::alloc_failed;}
hook_status breakpoint_dispatch::uninstall(void* target) {
    auto& rt=*runtime_;
    std::lock_guard<std::mutex> lock(rt.mutex);
    auto it=rt.sites.find(target);
    if(it==rt.sites.end())return hook_status::not_hooked;
    auto& site=it->second;
    site.node->route.store(site.node->original,std::memory_order_release);
    if(!memory::make_writable(site.pages,rt.api)) {
        memory::restore_pages(site.pages,rt.api);site.failed=true;return hook_status::partial;
    }
    const auto previous=InterlockedCompareExchange8(reinterpret_cast<volatile CHAR*>(target),
                      static_cast<CHAR>(site.saved),static_cast<CHAR>(0xCC));
    const auto byte=static_cast<std::uint8_t>(previous);
    const bool unchanged=byte==site.saved;
    const bool copied=byte==0xCC || unchanged;
    if(copied)site.written=false;
    const bool flushed=copied && rt.api.flush(GetCurrentProcess(),target,1)!=0;
    const bool restored=memory::restore_pages(site.pages,rt.api);
    if(!copied || !flushed || !restored){site.failed=true;return hook_status::partial;}
    rt.sites.erase(it);
    return hook_status::success;
}
hook_status breakpoint_dispatch::uninstall_all() try {
    std::vector<void*> targets;
    {std::lock_guard<std::mutex> lock(runtime_->mutex);
     for(const auto& pair:runtime_->sites)targets.push_back(pair.first);}
    auto result=hook_status::success;
    for(auto* target:targets)if(uninstall(target)!=hook_status::success)result=hook_status::partial;
    return result;
} catch(const std::bad_alloc&) {return hook_status::alloc_failed;}
bool breakpoint_dispatch::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);return runtime_->sites.count(target)!=0;
}
std::size_t breakpoint_dispatch::active_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);return runtime_->sites.size();
}
}
