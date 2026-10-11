#include "shadowhook/ring3/vtable_hook.hpp"
#include "shadowhook/utils/logger.hpp"
#include <cstring>
#include <limits>
#include <stdexcept>
namespace shadowhook::ring3 {
namespace {
constexpr std::size_t maximum_methods=4096,maximum_prefix=16;
bool read_pointer(const void* source,void*& value) {
    return memory::readable_range(source,sizeof(void*)) &&
           memory::safe_copy(&value,source,sizeof(void*));
}
bool pin_image(const void* address) {
    MEMORY_BASIC_INFORMATION region{};
    if(VirtualQuery(address,&region,sizeof(region))!=sizeof(region) || region.State!=MEM_COMMIT)return false;
    if(region.Type!=MEM_IMAGE)return true;
    HMODULE module{};
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(address),&module)!=0;
}
bool exchange_pointer(void** slot,void* desired,void* expected,void*& previous) noexcept {
    __try {
        previous=InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(slot),desired,expected);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {return false;}
}
hook_status read_layout(void* instance,const vtable_options& options,void**& table) {
    if(!instance || reinterpret_cast<std::uintptr_t>(instance)%alignof(void*) ||
       !options.method_count || options.method_count>maximum_methods ||
       options.slot>=options.method_count || options.prefix_slots>maximum_prefix ||
       (options.mode!=vtable_mode::instance_local && options.mode!=vtable_mode::shared_slot))
        return hook_status::invalid_address;
    void* pointer{};
    if(!read_pointer(instance,pointer) || !pointer)return hook_status::invalid_address;
    const auto address=reinterpret_cast<std::uintptr_t>(pointer);
    const auto length=options.method_count*sizeof(void*);
    if(address%alignof(void*) || length>UINTPTR_MAX-address ||
       !memory::readable_range(pointer,length))return hook_status::invalid_address;
    if(options.mode==vtable_mode::instance_local) {
        const auto prefix=options.prefix_slots*sizeof(void*);
        if(prefix>address || !memory::readable_range(
            reinterpret_cast<void*>(address-prefix),length+prefix))return hook_status::invalid_address;
    }
    table=static_cast<void**>(pointer);
    return hook_status::success;
}
}
struct vtable_hook::record {
    void* instance{};
    vtable_options options;
    void** original_table{};
    void** replacement_table{};
    void** publication_slot{};
    void* old_value{};
    void* new_value{};
    void* original_method{};
    std::unique_ptr<void,decltype(&memory::free_rwx)> clone{nullptr,&memory::free_rwx};
    std::vector<memory::page_protection> pages;
    vtable_state state{vtable_state::prepared};
    bool published{},ever_published{};
    ~record() {
        if(ever_published)(void)clone.release();
    }
};
struct vtable_hook::runtime {
    mutable std::mutex mutex;
    std::shared_ptr<threading::execution_domain> domain;
    memory::patch_api api;
    std::unordered_map<void*,std::unique_ptr<record>> records;
};
vtable_hook::vtable_hook(std::shared_ptr<threading::execution_domain> domain,memory::patch_api api)
    :runtime_(std::make_unique<runtime>()) {
    if(!api.protect)throw std::invalid_argument("vtable patch_api requires protection callback");
    runtime_->domain=domain?std::move(domain):std::make_shared<threading::execution_domain>();
    runtime_->api=api;
    if(!runtime_->domain->bind(runtime_.get()))throw std::invalid_argument("vtable execution domain already bound");
}
vtable_hook::~vtable_hook() {
    try {
        if(uninstall_all()==hook_status::success) {
            runtime_->domain->unbind(runtime_.get());return;
        }
    }catch(...){}
    runtime_->domain->close();
    (void)runtime_.release(); 
}
std::shared_ptr<threading::execution_domain> vtable_hook::execution_domain() const {return runtime_->domain;}
threading::execution_scope vtable_hook::enter_execution() const {return runtime_->domain->enter();}
bool vtable_hook::healthy_locked() const {
    for(const auto& pair:runtime_->records)if(pair.second->state==vtable_state::failed)return false;
    return true;
}
hook_status vtable_hook::apply(record& item,bool installed) {
    const auto prior=item.state;
    item.state=installed?vtable_state::prepared:vtable_state::restoring;
    if(!memory::make_writable(item.pages,runtime_->api)) {
        const bool restored=memory::restore_pages(item.pages,runtime_->api);
        item.state=restored?prior:vtable_state::failed;
        return restored?hook_status::protect_failed:hook_status::partial;
    }
    auto* desired=installed?item.new_value:item.old_value;
    auto* expected=item.published?item.new_value:item.old_value;
    void* previous{};
    const bool accessed=exchange_pointer(item.publication_slot,desired,expected,previous);
    const bool exchanged=accessed && (previous==expected ||
                                      (!installed && previous==desired));
    if(exchanged) {
        item.published=installed;
        if(installed)item.ever_published=true;
    }
    const bool restored=memory::restore_pages(item.pages,runtime_->api);
    if(!exchanged || !restored) {
        item.state=vtable_state::failed;
        return hook_status::partial;
    }
    item.state=installed?vtable_state::installed:vtable_state::prepared;
    return hook_status::success;
}
hook_status vtable_hook::install(void* instance,void* detour,void** original) {
    SH_LOG_WARN("vtable legacy API: shared slot 0; use install_slot with explicit layout for instance-local hooks");
    return install_slot(instance,{0,1,vtable_mode::shared_slot,0},detour,original);
}
hook_status vtable_hook::install_locked(void* instance,const vtable_options& options,
                                       void* detour,void** original) {
    if(original)*original=nullptr;
    if(!detour || !memory::is_executable(detour))return hook_status::invalid_address;
    if(runtime_->records.count(instance))return hook_status::already_hooked;
    void** table{};
    auto result=read_layout(instance,options,table);
    if(result!=hook_status::success)return result;
    for(const auto& pair:runtime_->records) {
        const auto& other=*pair.second;
        if(other.original_table!=table)continue;
        if(other.options.mode!=options.mode ||
           (options.mode==vtable_mode::shared_slot && other.options.slot==options.slot))
            return hook_status::already_hooked;
    }
    const auto count=options.mode==vtable_mode::instance_local?options.method_count:std::size_t(1);
    for(std::size_t i=0;i<count;++i) {
        const auto index=options.mode==vtable_mode::instance_local?i:options.slot;
        void* method{};
        if(!read_pointer(table+index,method) || !memory::is_executable(method) || !pin_image(method))
            return hook_status::invalid_address;
    }
    if(options.mode==vtable_mode::instance_local && options.prefix_slots) {
        void* locator{};
        if(!read_pointer(table-1,locator) || !locator ||
           !memory::readable_range(locator,sizeof(std::uint32_t)) || !pin_image(locator))
            return hook_status::invalid_address;
    }
    auto item=std::make_unique<record>();
    item->instance=instance;item->options=options;item->original_table=table;
    if(!read_pointer(table+options.slot,item->original_method))return hook_status::invalid_address;
    if(item->original_method==detour)return hook_status::invalid_address;
    if(options.mode==vtable_mode::instance_local) {
        const auto prefix=options.prefix_slots*sizeof(void*);
        const auto bytes=(options.prefix_slots+options.method_count)*sizeof(void*);
        item->clone.reset(VirtualAlloc(nullptr,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if(!item->clone)return hook_status::alloc_failed;
        const auto begin=reinterpret_cast<std::uintptr_t>(table)-prefix;
        if(!memory::safe_copy(item->clone.get(),reinterpret_cast<void*>(begin),bytes))
            return hook_status::invalid_address;
        item->replacement_table=reinterpret_cast<void**>(
            static_cast<std::uint8_t*>(item->clone.get())+prefix);
        item->replacement_table[options.slot]=detour;
        DWORD old{};
        if(!VirtualProtect(item->clone.get(),bytes,PAGE_READONLY,&old))return hook_status::protect_failed;
        item->publication_slot=static_cast<void**>(instance);
        item->old_value=table;item->new_value=item->replacement_table;
    } else {
        item->publication_slot=table+options.slot;
        item->old_value=item->original_method;item->new_value=detour;
    }
    if(!memory::capture_pages(item->publication_slot,sizeof(void*),item->pages) ||
       !pin_image(table) || !pin_image(detour) || !pin_image(item->original_method))
        return hook_status::invalid_address;
    auto& record=*item;
    runtime_->records.emplace(instance,std::move(item)); // throwing allocations precede publication
    result=apply(record,true);
    if(result!=hook_status::success) {
        if(!record.published && record.state!=vtable_state::failed) {
            runtime_->records.erase(instance);return result;
        }
        const auto rolled_back=apply(record,false);
        if(rolled_back==hook_status::success) {
            runtime_->records.erase(instance);
            return hook_status::protect_failed;
        }
        record.state=vtable_state::failed;
        return hook_status::partial;
    }
    if(original)*original=record.original_method;
    return hook_status::success;
}
hook_status vtable_hook::install_slot(void* instance,const vtable_options& options,
                                     void* detour,void** original) try {
    if(original)*original=nullptr;
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    threading::patch_scope exclusive(runtime_->domain);
    if(!exclusive)return hook_status::busy;
    if(!healthy_locked()){exclusive.healthy(false);return hook_status::partial;}
    const auto result=install_locked(instance,options,detour,original);
    exclusive.healthy(healthy_locked());
    return result;
}catch(const std::bad_alloc&){return hook_status::alloc_failed;}
hook_status vtable_hook::install_method(void* instance,void* method,vtable_options options,
                                       void* detour,void** original) try {
    if(original)*original=nullptr;
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    threading::patch_scope exclusive(runtime_->domain);
    if(!exclusive)return hook_status::busy;
    if(!healthy_locked()){exclusive.healthy(false);return hook_status::partial;}
    if(!method || !memory::is_executable(method))return hook_status::invalid_address;
    options.slot=0;
    void** table{};
    auto result=read_layout(instance,options,table);
    if(result!=hook_status::success)return result;
    std::size_t found{},matches{};
    for(std::size_t i=0;i<options.method_count;++i) {
        void* value{};
        if(!read_pointer(table+i,value))return hook_status::invalid_address;
        if(value==method){found=i;++matches;}
    }
    if(!matches)return hook_status::not_hooked; 
    if(matches!=1)return hook_status::unsupported; 
    options.slot=found;
    result=install_locked(instance,options,detour,original);
    exclusive.healthy(healthy_locked());
    return result;
}catch(const std::bad_alloc&){return hook_status::alloc_failed;}
hook_status vtable_hook::uninstall(void* instance) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto it=runtime_->records.find(instance);
    if(it==runtime_->records.end())return hook_status::not_hooked;
    threading::patch_scope exclusive(runtime_->domain);
    if(!exclusive)return hook_status::busy;
    const auto result=apply(*it->second,false);
    if(result==hook_status::success)runtime_->records.erase(it);
    exclusive.healthy(healthy_locked());
    return result;
}
hook_status vtable_hook::uninstall_all() try {
    std::vector<void*> instances;
    {std::lock_guard<std::mutex> lock(runtime_->mutex);
     instances.reserve(runtime_->records.size());for(const auto& pair:runtime_->records)instances.push_back(pair.first);}
    auto result=hook_status::success;
    for(auto* instance:instances) {
        const auto status=uninstall(instance);
        if(status!=hook_status::success && status!=hook_status::not_hooked)result=hook_status::partial;
    }
    return result;
}catch(const std::bad_alloc&){return hook_status::alloc_failed;}
bool vtable_hook::is_hooked(void* instance) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);return runtime_->records.count(instance)!=0;
}
std::size_t vtable_hook::active_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);return runtime_->records.size();
}
bool vtable_hook::inspect(void* instance,vtable_report& report) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto it=runtime_->records.find(instance);if(it==runtime_->records.end())return false;
    const auto& item=*it->second;
    report.state=item.state;report.mode=item.options.mode;
    report.slot=item.options.slot;report.method_count=item.options.method_count;
    report.original_table=item.original_table;report.replacement_table=item.replacement_table;
    report.published=item.published;report.pages=item.pages;
    return true;
}
}
