#include "shadowhook/ring3/hotpatch_hook.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace shadowhook::ring3 {
namespace {
constexpr std::uint16_t original_word = 0x9066; // 1 2-byte nop/nop
constexpr std::uint16_t redirect_word = 0xF9EB; // jmp entry-5 (from entry+2)
struct reservations {
    std::mutex mutex;
    std::vector<std::pair<std::uintptr_t,std::shared_ptr<std::atomic<bool>>>> sites;
};
std::atomic<reservations*> published_reservations{};
reservations& process_reservations() {
    static auto* value=new reservations; 
    published_reservations.store(value,std::memory_order_release);
    return *value;
}
std::shared_ptr<std::atomic<bool>> reserve(std::uintptr_t entry) {
    auto published=std::make_shared<std::atomic<bool>>(false);
    auto& all=process_reservations();
    std::lock_guard<std::mutex> lock(all.mutex);
    all.sites.emplace_back(entry,published);
    return published;
}
bool read_word(void* entry, std::uint16_t& value) {
    return memory::readable_range(entry,2) && memory::safe_copy(&value,entry,2);
}
bool pin_image(void* address) {
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(address,&region,sizeof(region)) != sizeof(region)) return false;
    if (region.Type != MEM_IMAGE) return true; 
    HMODULE module{};
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(address),&module) != 0;
}
bool executable_protection(DWORD value) {
    const auto p = value & 0xff;
    return p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}
void route_to(void** slot, void* destination) {
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(slot),destination);
}
}
hotpatch_hook::hotpatch_hook(memory::patch_api api) : runtime_(std::make_unique<runtime>()) {
    if (!api.protect || !api.flush) throw std::invalid_argument("patch_api requires both functions");
    runtime_->api = api;
}
hotpatch_hook::~hotpatch_hook() {
    try { if (uninstall_all() == hook_status::success) return; } catch (...) {}
    (void)runtime_.release();
    try { SH_LOG_ERROR("Hotpatch shutdown incomplete: runtime quarantined"); } catch (...) {}
}
bool hotpatch_hook::reserves_address(void* address) {return reserves_range(address,1);}
bool hotpatch_hook::reserves_range(void* address,std::size_t size) {
    const auto value=reinterpret_cast<std::uintptr_t>(address);
    if(!size || size>UINTPTR_MAX-value)return true;
    auto* all=published_reservations.load(std::memory_order_acquire);
    if(!all)return false;
    std::lock_guard<std::mutex> lock(all->mutex);
    for(const auto& pair:all->sites)
        if(pair.second->load(std::memory_order_acquire) &&
           value<pair.first+3 && pair.first-5<value+size)return true;
    return false;
}
hook_status hotpatch_hook::prepare(site& item) {
    auto* padding = static_cast<std::uint8_t*>(item.entry)-5;
    std::uint16_t word{};
    if (!read_word(item.entry,word) || word != original_word) return hook_status::already_hooked;
    if (!memory::make_writable(item.pages,runtime_->api)) {
        const bool restored = memory::restore_pages(item.pages,runtime_->api);
        if (!restored) item.state=hotpatch_state::failed;
        return restored ? hook_status::protect_failed : hook_status::partial;
    }
    bool copied{};
    if (item.preamble_written) {
        std::array<std::uint8_t,5> current{};
        copied = memory::safe_copy(current.data(),padding,5) && current == item.preamble;
    } else {
        item.reserved->store(true,std::memory_order_release);
        copied = memory::safe_copy(padding,item.preamble.data(),5);
        if (copied) item.preamble_written=true;
    }
    const bool flushed = copied && runtime_->api.flush(GetCurrentProcess(),padding,7) != 0;
    const bool restored = memory::restore_pages(item.pages,runtime_->api);
    if (!copied || !flushed || !restored) {
        item.state=hotpatch_state::failed;
        return hook_status::partial;
    }
    return hook_status::success;
}
hook_status hotpatch_hook::switch_entry(site& item, bool enabled) {
    const auto wanted = enabled ? redirect_word : original_word;
    const auto expected = enabled ? original_word : redirect_word;
    if (!memory::make_writable(item.pages,runtime_->api)) {
        const bool restored = memory::restore_pages(item.pages,runtime_->api);
        if (!restored) item.state=hotpatch_state::failed;
        return restored ? hook_status::protect_failed : hook_status::partial;
    }
    const auto seen = static_cast<std::uint16_t>(InterlockedCompareExchange16(
        reinterpret_cast<volatile SHORT*>(item.entry),
        static_cast<SHORT>(wanted),static_cast<SHORT>(expected)));
    const bool exchanged = seen == expected || (!enabled && seen == wanted);
    if (exchanged) {
        item.entry_enabled=enabled;
        if (enabled) item.ever_published=true;
    } else item.entry_enabled=seen==redirect_word;
    const bool flushed = runtime_->api.flush(GetCurrentProcess(),item.entry,2) != 0;
    const bool restored = memory::restore_pages(item.pages,runtime_->api);
    if (!exchanged || !flushed || !restored) {
        item.state=hotpatch_state::failed;
        return hook_status::partial;
    }
    item.state=enabled ? hotpatch_state::active : hotpatch_state::retired;
    return hook_status::success;
}
hook_status hotpatch_hook::retire(site& item) {
    route_to(item.route,static_cast<std::uint8_t*>(item.entry)+2);
    return switch_entry(item,false);
}
hook_status hotpatch_hook::install(void* target,void* detour,void** original) try {
    if (original) *original=nullptr;
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto start=reinterpret_cast<std::uintptr_t>(target);
    if (!target || !detour || target == detour || start < 5 || (start & 1) ||
        start > UINTPTR_MAX-2) return hook_status::invalid_address;
    const auto destination=reinterpret_cast<std::uintptr_t>(detour);
    if (destination >= start-5 && destination < start+2) return hook_status::invalid_address;
    if (!memory::is_executable(target) || !memory::is_executable(detour) ||
        !memory::readable_range(reinterpret_cast<void*>(start-5),7)) return hook_status::invalid_address;
    auto found=runtime_->sites.find(target);
    if (found != runtime_->sites.end() && found->second->state != hotpatch_state::retired)
        return hook_status::already_hooked;
    std::uint16_t word{};
    if (!read_word(target,word) || word != original_word) return hook_status::unsupported;
    if (found == runtime_->sites.end()) {
        if (reserves_address(target)) return hook_status::already_hooked;
        DWORD64 image{};
        const auto* function=RtlLookupFunctionEntry(start,&image,nullptr);
        if(function && image+function->BeginAddress!=start) return hook_status::unsupported;
        for(std::size_t i=0;i<5;++i) {
            DWORD64 padding_image{};
            if(RtlLookupFunctionEntry(start-5+i,&padding_image,nullptr)) return hook_status::unsupported;
        }
        std::array<std::uint8_t,5> padding{};
        if (!memory::safe_copy(padding.data(),reinterpret_cast<void*>(start-5),5) ||
            !std::all_of(padding.begin(),padding.end(),[](auto b){return b==0x90 || b==0xCC;}))
            return hook_status::unsupported;
        for (const auto& pair:runtime_->sites) {
            const auto other=reinterpret_cast<std::uintptr_t>(pair.first);
            if (start-5 < other+2 && other-5 < start+2) return hook_status::already_hooked;
        }
        auto item=std::make_unique<site>();
        item->entry=target;
        if (!memory::capture_pages(reinterpret_cast<void*>(start-5),7,item->pages) ||
            !std::all_of(item->pages.begin(),item->pages.end(),[](const auto& p){return executable_protection(p.original);}))
            return hook_status::unsupported;
        SYSTEM_INFO system{};GetSystemInfo(&system);
        const auto page=static_cast<std::size_t>(system.dwPageSize);
        if (page < 64 || page > SIZE_MAX/2) return hook_status::unsupported;
        auto owned=std::unique_ptr<void,decltype(&memory::free_rwx)>(
            memory::allocate_rwx_near(target,page*2),&memory::free_rwx);
        if (!owned) return hook_status::alloc_failed;
        auto* code=static_cast<std::uint8_t*>(owned.get());
        item->allocation=code;
        item->route=reinterpret_cast<void**>(code+page); 
        item->original=code+32;
        const std::int32_t displacement=static_cast<std::int32_t>(page-6);
        code[0]=0xFF;code[1]=0x25;
        std::memcpy(code+2,&displacement,4);
        route_to(item->route,reinterpret_cast<void*>(start+2));
        asm_stubs::write_jmp_abs(item->original,reinterpret_cast<void*>(start+2));
        DWORD old{};
        if (!VirtualProtect(code,page,PAGE_EXECUTE_READ,&old) ||
            !runtime_->api.flush(GetCurrentProcess(),code,46)) return hook_status::protect_failed;
        const auto relative=static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(code))-
                            static_cast<std::int64_t>(start);
        if (relative < INT32_MIN || relative > INT32_MAX) return hook_status::unsupported;
        item->preamble[0]=0xE9;
        const auto rel32=static_cast<std::int32_t>(relative);
        std::memcpy(item->preamble.data()+1,&rel32,4);
        item->reserved=reserve(start);
        found=runtime_->sites.emplace(target,std::move(item)).first;
        (void)owned.release();
    }
    auto& item=*found->second;
    if (!pin_image(target) || !pin_image(detour)) {
        if(!item.reserved->load(std::memory_order_acquire)) {
            memory::free_rwx(item.allocation);
            runtime_->sites.erase(found);
        }
        return hook_status::invalid_address;
    }
    const auto prepared=prepare(item);
    if (prepared != hook_status::success) {
        if(!item.reserved->load(std::memory_order_acquire) && prepared!=hook_status::partial) {
            memory::free_rwx(item.allocation);
            runtime_->sites.erase(found);
        }
        return prepared;
    }
    route_to(item.route,detour);
    const auto committed=switch_entry(item,true);
    if (committed != hook_status::success) {
        const auto rolled_back=retire(item);
        if (rolled_back == hook_status::success) return hook_status::protect_failed;
        return hook_status::partial;
    }
    if (original) *original=item.original;
    return hook_status::success;
} catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
hook_status hotpatch_hook::uninstall(void* target) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto found=runtime_->sites.find(target);
    if (found==runtime_->sites.end() || found->second->state==hotpatch_state::retired)
        return hook_status::not_hooked;
    return retire(*found->second);
}
hook_status hotpatch_hook::uninstall_all() try {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto result=hook_status::success;
    for (auto& pair:runtime_->sites)
        if (pair.second->state != hotpatch_state::retired && retire(*pair.second) != hook_status::success)
            result=hook_status::partial;
    return result;
} catch (...) { return hook_status::partial; }
bool hotpatch_hook::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto found=runtime_->sites.find(target);
    return found != runtime_->sites.end() && found->second->state != hotpatch_state::retired;
}
std::size_t hotpatch_hook::active_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    std::size_t count{};
    for (const auto& pair:runtime_->sites) if(pair.second->state != hotpatch_state::retired) ++count;
    return count;
}
bool hotpatch_hook::inspect(void* target,hotpatch_report& report) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto found=runtime_->sites.find(target);
    if(found==runtime_->sites.end()) return false;
    const auto& s=*found->second;
    report={s.state,s.entry_enabled,s.preamble_written,s.ever_published,s.allocation,s.original,s.pages};
    return true;
}
} // namespace shadowhook::ring3

