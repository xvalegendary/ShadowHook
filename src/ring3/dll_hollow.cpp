#include "shadowhook/ring3/dll_hollow.hpp"
#include "shadowhook/utils/memory.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <stdexcept>
namespace shadowhook::ring3 {
namespace {
constexpr std::size_t max_image=64*1024*1024;
constexpr std::size_t page_size=4096;
bool fits(std::size_t offset,std::size_t length,std::size_t size) {
    return offset<=size && length<=size-offset;
}
template<class T> bool read(const std::vector<std::uint8_t>& bytes,std::size_t offset,T& value) {
    if(!fits(offset,sizeof(T),bytes.size()))return false;
    std::memcpy(&value,bytes.data()+offset,sizeof(T));return true;
}
template<class T> bool write(std::vector<std::uint8_t>& bytes,std::size_t offset,const T& value) {
    if(!fits(offset,sizeof(T),bytes.size()))return false;
    std::memcpy(bytes.data()+offset,&value,sizeof(T));return true;
}
const char* string_at(const std::vector<std::uint8_t>& bytes,std::size_t offset) {
    if(offset>=bytes.size())return nullptr;
    const auto limit=std::min<std::size_t>(4096,bytes.size()-offset);
    return std::memchr(bytes.data()+offset,0,limit) ? reinterpret_cast<const char*>(bytes.data()+offset):nullptr;
}
struct layout {
    IMAGE_NT_HEADERS64 nt{};
    std::size_t nt_offset{};
    std::vector<IMAGE_SECTION_HEADER> sections;
    std::vector<DWORD> protection;
    std::size_t size{};
};
DWORD rights(DWORD characteristics) {
    const bool exec=(characteristics&IMAGE_SCN_MEM_EXECUTE)!=0;
    const bool writable=(characteristics&IMAGE_SCN_MEM_WRITE)!=0;
    const bool readable=(characteristics&IMAGE_SCN_MEM_READ)!=0;
    if(exec)return writable ? PAGE_EXECUTE_READWRITE:readable ? PAGE_EXECUTE_READ:PAGE_EXECUTE;
    return writable ? PAGE_READWRITE:readable ? PAGE_READONLY:PAGE_NOACCESS;
}
hook_status parse(const std::vector<std::uint8_t>& file,layout& out) {
    IMAGE_DOS_HEADER dos{};
    if(!read(file,0,dos) || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<sizeof(dos))
        return hook_status::invalid_address;
    if(!read(file,static_cast<std::size_t>(dos.e_lfanew),out.nt))return hook_status::invalid_address;
    const auto& nt=out.nt;const auto& opt=nt.OptionalHeader;
    if(nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
       !(nt.FileHeader.Characteristics&IMAGE_FILE_DLL) ||
       nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
       opt.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)return hook_status::unsupported;
    if(opt.AddressOfEntryPoint || opt.NumberOfRvaAndSizes!=IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
       opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size ||
       opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size ||
       opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size ||
       opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size ||
       opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size)
        return hook_status::unsupported;
    if(opt.SectionAlignment!=page_size || opt.FileAlignment<512 || opt.FileAlignment>page_size ||
       (opt.FileAlignment&(opt.FileAlignment-1)) ||
       !opt.SizeOfImage || opt.SizeOfImage>max_image || opt.SizeOfImage%page_size ||
       !opt.SizeOfHeaders || opt.SizeOfHeaders>opt.SizeOfImage ||
       opt.SizeOfHeaders>file.size() || !nt.FileHeader.NumberOfSections ||
       nt.FileHeader.NumberOfSections>96)return hook_status::invalid_address;
    out.nt_offset=static_cast<std::size_t>(dos.e_lfanew);out.size=opt.SizeOfImage;
    const auto section_offset=out.nt_offset+sizeof(IMAGE_NT_HEADERS64);
    if(!fits(section_offset,nt.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER),opt.SizeOfHeaders))
        return hook_status::invalid_address;
    out.protection.assign(out.size/page_size,PAGE_NOACCESS);
    for(std::size_t i=0;i<(opt.SizeOfHeaders+page_size-1)/page_size;++i)out.protection[i]=PAGE_READONLY;
    std::size_t raw_end=opt.SizeOfHeaders;
    std::size_t last_end=(opt.SizeOfHeaders+page_size-1)&~(page_size-1);
    for(unsigned i=0;i<nt.FileHeader.NumberOfSections;++i) {
        IMAGE_SECTION_HEADER section{};
        if(!read(file,section_offset+i*sizeof(section),section))return hook_status::invalid_address;
        const auto length=std::max(section.Misc.VirtualSize,section.SizeOfRawData);
        if(!length || section.VirtualAddress%page_size || section.VirtualAddress<last_end ||
           !fits(section.VirtualAddress,length,out.size) ||
           !fits(section.PointerToRawData,section.SizeOfRawData,file.size()) ||
           (section.SizeOfRawData && (section.PointerToRawData<raw_end ||
                                    section.PointerToRawData%opt.FileAlignment)))
            return hook_status::invalid_address;
        if(section.SizeOfRawData%opt.FileAlignment)return hook_status::invalid_address;
        if(section.SizeOfRawData)raw_end=section.PointerToRawData+static_cast<std::size_t>(section.SizeOfRawData);
        if((section.Characteristics&IMAGE_SCN_MEM_EXECUTE) && (section.Characteristics&IMAGE_SCN_MEM_WRITE))
            return hook_status::unsupported; 
        last_end=(section.VirtualAddress+static_cast<std::size_t>(length)+page_size-1)&~(page_size-1);
        const auto protection=rights(section.Characteristics);
        for(std::size_t p=section.VirtualAddress/page_size;p<last_end/page_size;++p)
            out.protection[p]=protection;
        out.sections.push_back(section);
    }
    for(unsigned i=0;i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;++i) {
        const auto& dir=opt.DataDirectory[i];
        if((!dir.Size)!=(!dir.VirtualAddress))return hook_status::invalid_address;
        if(!dir.Size)continue;
        if(i==IMAGE_DIRECTORY_ENTRY_SECURITY) {
            if(!fits(dir.VirtualAddress,dir.Size,file.size()))return hook_status::invalid_address;
        } else {
            if(!fits(dir.VirtualAddress,dir.Size,out.size))return hook_status::invalid_address;
            for(std::size_t p=dir.VirtualAddress/page_size;
                p<=(dir.VirtualAddress+dir.Size-1)/page_size;++p)
                if(out.protection[p]==PAGE_NOACCESS)return hook_status::invalid_address;
        }
    }
    return hook_status::success;
}
hook_status read_file(const wchar_t* path,std::vector<std::uint8_t>& bytes) {
    if(!path || !*path)return hook_status::invalid_address;
    const auto file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return hook_status::invalid_address;
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(file,&size) || size.QuadPart<=0 || size.QuadPart>max_image) {
        CloseHandle(file);return hook_status::invalid_address;
    }
    try {bytes.resize(static_cast<std::size_t>(size.QuadPart));}
    catch(...){CloseHandle(file);throw;}
    DWORD actual{};
    const bool ok=ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&actual,nullptr)!=0 &&
                  actual==bytes.size();
    CloseHandle(file);return ok?hook_status::success:hook_status::invalid_address;
}
hook_status relocate(std::vector<std::uint8_t>& bytes,const layout& info,std::uint64_t from,std::uint64_t to) {
    const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(from!=to && !dir.Size)return hook_status::unsupported;
    std::size_t cursor=dir.VirtualAddress,end=cursor+dir.Size;
    while(cursor<end) {
        IMAGE_BASE_RELOCATION block{};
        if(!read(bytes,cursor,block) || block.SizeOfBlock<sizeof(block) || block.VirtualAddress%page_size ||
           (block.SizeOfBlock-sizeof(block))%sizeof(WORD) ||
           !fits(cursor,block.SizeOfBlock,end))return hook_status::invalid_address;
        for(std::size_t offset=sizeof(block);offset<block.SizeOfBlock;offset+=sizeof(WORD)) {
            WORD item{};read(bytes,cursor+offset,item);
            const auto type=item>>12;
            if(type==IMAGE_REL_BASED_ABSOLUTE)continue;
            if(type!=IMAGE_REL_BASED_DIR64)return hook_status::unsupported;
            const auto location=static_cast<std::size_t>(block.VirtualAddress)+(item&0xFFF);
            std::uint64_t value{};
            if(!fits(location,sizeof(value),info.size) || !read(bytes,location,value))return hook_status::invalid_address;
            value+=to-from;write(bytes,location,value);
        }
        cursor+=block.SizeOfBlock;
    }
    auto nt=info.nt;nt.OptionalHeader.ImageBase=to;
    write(bytes,info.nt_offset,nt);
    return hook_status::success;
}
bool pin_module(HMODULE module) {
    HMODULE pinned{};
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(module),&pinned)!=0;
}
hook_status imports(std::vector<std::uint8_t>& bytes,const layout& info) {
    const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!dir.Size)return hook_status::success;
    const auto end=static_cast<std::size_t>(dir.VirtualAddress)+dir.Size;
    for(std::size_t cursor=dir.VirtualAddress;fits(cursor,sizeof(IMAGE_IMPORT_DESCRIPTOR),end);
        cursor+=sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR entry{};read(bytes,cursor,entry);
        if(!entry.Name && !entry.FirstThunk && !entry.OriginalFirstThunk)return hook_status::success;
        const auto* name=string_at(bytes,entry.Name);
        if(!name || std::strchr(name,'/') || std::strchr(name,'\\') || std::strchr(name,':') ||
           !entry.FirstThunk || !entry.OriginalFirstThunk)return hook_status::invalid_address;
        const auto module=LoadLibraryExA(name,nullptr,LOAD_LIBRARY_SEARCH_DEFAULT_DIRS|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!module)return hook_status::invalid_address;
        const bool pinned=pin_module(module);FreeLibrary(module);
        if(!pinned)return hook_status::invalid_address;
        bool terminated=false;
        for(std::size_t i=0;i<info.size/sizeof(std::uint64_t);++i) {
            const auto input=static_cast<std::size_t>(entry.OriginalFirstThunk)+i*8;
            const auto output=static_cast<std::size_t>(entry.FirstThunk)+i*8;
            std::uint64_t thunk{};
            if(!fits(output,8,info.size) || !read(bytes,input,thunk))return hook_status::invalid_address;
            if(!thunk){terminated=true;break;}
            FARPROC procedure{};
            if(IMAGE_SNAP_BY_ORDINAL64(thunk))procedure=GetProcAddress(module,MAKEINTRESOURCEA(thunk&0xFFFF));
            else {
                if(thunk>UINT32_MAX)return hook_status::invalid_address;
                const auto* symbol=string_at(bytes,static_cast<std::size_t>(thunk)+sizeof(WORD));
                if(!symbol)return hook_status::invalid_address;
                procedure=GetProcAddress(module,symbol);
            }
            if(!procedure)return hook_status::invalid_address;
            HMODULE code_module{};
            if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                                  reinterpret_cast<LPCWSTR>(procedure),&code_module))return hook_status::invalid_address;
            const auto value=reinterpret_cast<std::uint64_t>(procedure);write(bytes,output,value);
        }
        if(!terminated)return hook_status::invalid_address;
    }
    return hook_status::invalid_address;
}
hook_status validate_functions(const std::vector<std::uint8_t>& bytes,const layout& info) {
    const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if(dir.Size%sizeof(RUNTIME_FUNCTION))return hook_status::invalid_address;
    DWORD previous{};
    for(std::size_t p=dir.VirtualAddress;p<static_cast<std::size_t>(dir.VirtualAddress)+dir.Size;p+=sizeof(RUNTIME_FUNCTION)) {
        RUNTIME_FUNCTION function{};
        if(!read(bytes,p,function) || function.BeginAddress<previous ||
           function.BeginAddress>=function.EndAddress || function.EndAddress>info.size ||
           !fits(function.UnwindData,4,info.size))return hook_status::invalid_address;
        previous=function.EndAddress;
        if(bytes[function.UnwindData]!=1)return hook_status::unsupported;
        if(info.protection[function.BeginAddress/page_size]!=PAGE_EXECUTE_READ ||
           info.protection[(function.EndAddress-1)/page_size]!=PAGE_EXECUTE_READ)
            return hook_status::invalid_address;
        const auto count=bytes[function.UnwindData+2];
        if(!fits(function.UnwindData,4+((count+1u)&~1u)*2u,info.size))return hook_status::invalid_address;
        const auto prolog=bytes[function.UnwindData+1];
        unsigned last=256;
        for(unsigned i=0;i<count;) {
            const auto code=bytes[function.UnwindData+4+i*2];
            const auto descriptor=bytes[function.UnwindData+5+i*2];
            const auto op=descriptor&15,argument=descriptor>>4;
            unsigned slots=1;
            switch(op) {
            case 0:case 2:case 3:break;
            case 1:if(argument>1)return hook_status::invalid_address;slots=argument==0?2:3;break;
            case 4:case 8:slots=2;break;
            case 5:case 9:slots=3;break;
            default:return hook_status::unsupported;
            }
            if(code>prolog || code>last || i+slots>count)return hook_status::invalid_address;
            last=code;i+=slots;
        }
    }
    return hook_status::success;
}
void* export_at(void* base,const layout& info,const char* name) {
    if(!name)return nullptr;
    const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(dir.Size<sizeof(IMAGE_EXPORT_DIRECTORY))return nullptr;
    auto* bytes=static_cast<const std::uint8_t*>(base);
    IMAGE_EXPORT_DIRECTORY exports{};
    if(!memory::safe_copy(&exports,bytes+dir.VirtualAddress,sizeof(exports)))return nullptr;
    if(exports.NumberOfNames>info.size/4 || exports.NumberOfFunctions>info.size/4 ||
       !fits(exports.AddressOfNames,exports.NumberOfNames*4ull,info.size) ||
       !fits(exports.AddressOfNameOrdinals,exports.NumberOfNames*2ull,info.size) ||
       !fits(exports.AddressOfFunctions,exports.NumberOfFunctions*4ull,info.size))return nullptr;
    for(DWORD i=0;i<exports.NumberOfNames;++i) {
        DWORD rva{};WORD ordinal{};
        if(!memory::safe_copy(&rva,bytes+exports.AddressOfNames+i*4,4) ||
           !memory::safe_copy(&ordinal,bytes+exports.AddressOfNameOrdinals+i*2,2) ||
           rva>=info.size || ordinal>=exports.NumberOfFunctions)return nullptr;
        char symbol[512]{};
        std::size_t n=0;
        for(;n<sizeof(symbol)-1 && rva+n<info.size;++n)
            if(!memory::safe_copy(&symbol[n],bytes+rva+n,1) || !symbol[n])break;
        if(n==sizeof(symbol)-1 || rva+n==info.size || symbol[n])return nullptr;
        if(std::strcmp(symbol,name)!=0)continue;
        DWORD function{};
        if(!memory::safe_copy(&function,bytes+exports.AddressOfFunctions+ordinal*4,4) ||
           function>=info.size || (function>=dir.VirtualAddress && function-dir.VirtualAddress<dir.Size))
            return nullptr; 
        const auto p=info.protection[function/page_size];
        return p==PAGE_EXECUTE || p==PAGE_EXECUTE_READ ? static_cast<std::uint8_t*>(base)+function:nullptr;
    }
    return nullptr;
}
}
struct owned_image_runtime {
    std::unique_ptr<void,decltype(&memory::free_rwx)> allocation{nullptr,&memory::free_rwx};
    std::shared_ptr<threading::execution_domain> domain=std::make_shared<threading::execution_domain>();
    layout info;
    memory::patch_api api;
    std::size_t capacity{};
    std::atomic<std::size_t> mapped_size{};
    bool table_registered{};
    bool failed{};
    ~owned_image_runtime() {
        if(table_registered) {
            const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if(!RtlDeleteFunctionTable(reinterpret_cast<RUNTIME_FUNCTION*>(
                 static_cast<std::uint8_t*>(allocation.get())+dir.VirtualAddress))) {
                (void)allocation.release(); 
            }
        }
    }
};
struct dll_hollow::image_backup {
    std::shared_ptr<owned_image_runtime> target;
    std::vector<std::uint8_t> bytes;
    layout info;
};
namespace {
bool protect_image(owned_image_runtime& rt,const layout& info) {
    bool success=true;DWORD old{};
    for(std::size_t p=0;p<rt.capacity/page_size;++p) {
        const auto protection=p<info.protection.size()?info.protection[p]:PAGE_NOACCESS;
        if(!rt.api.protect(static_cast<std::uint8_t*>(rt.allocation.get())+p*page_size,
                           page_size,protection,&old))success=false;
    }
    return success;
}
hook_status apply(owned_image_runtime& rt,const std::vector<std::uint8_t>& bytes,const layout& info) {
    DWORD old{};
    if(!rt.api.protect(rt.allocation.get(),rt.capacity,PAGE_READWRITE,&old)) {
        const bool restored=protect_image(rt,rt.info);
        rt.failed=!restored;
        return restored?hook_status::protect_failed:hook_status::partial;
    }
    if(rt.table_registered) {
        const auto& dir=rt.info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if(!RtlDeleteFunctionTable(reinterpret_cast<RUNTIME_FUNCTION*>(
               static_cast<std::uint8_t*>(rt.allocation.get())+dir.VirtualAddress))) {
            protect_image(rt,rt.info);return hook_status::partial;
        }
        rt.table_registered=false;
    }
    std::memset(rt.allocation.get(),0,rt.capacity);
    std::memcpy(rt.allocation.get(),bytes.data(),bytes.size());
    rt.info=info;
    const auto& dir=info.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    const bool protected_ok=protect_image(rt,info);
    const bool flushed=rt.api.flush(GetCurrentProcess(),rt.allocation.get(),info.size)!=0;
    if(dir.Size)rt.table_registered=RtlAddFunctionTable(reinterpret_cast<RUNTIME_FUNCTION*>(
        static_cast<std::uint8_t*>(rt.allocation.get())+dir.VirtualAddress),
        dir.Size/sizeof(RUNTIME_FUNCTION),reinterpret_cast<DWORD64>(rt.allocation.get()))!=0;
    const bool success=protected_ok && flushed && (!dir.Size || rt.table_registered);
    rt.failed=!success;
    if(success)rt.mapped_size.store(info.size,std::memory_order_release);
    return success?hook_status::success:hook_status::partial;
}
hook_status make_image(const wchar_t* path,std::size_t capacity,std::shared_ptr<owned_image_runtime>& out,memory::patch_api api={}) {
    std::vector<std::uint8_t> file;
    auto status=read_file(path,file);if(status!=hook_status::success)return status;
    layout info;
    status=parse(file,info);if(status!=hook_status::success)return status;
    if(capacity==0)capacity=info.size;
    if(capacity<info.size || capacity>max_image || capacity%page_size)return hook_status::invalid_address;
    auto rt=std::make_shared<owned_image_runtime>();
    rt->api=api;
    rt->capacity=capacity;rt->allocation.reset(VirtualAlloc(nullptr,capacity,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!rt->allocation)return hook_status::alloc_failed;
    std::vector<std::uint8_t> stage(info.size);
    std::memcpy(stage.data(),file.data(),info.nt.OptionalHeader.SizeOfHeaders);
    for(const auto& section:info.sections)
        std::memcpy(stage.data()+section.VirtualAddress,file.data()+section.PointerToRawData,section.SizeOfRawData);
    status=relocate(stage,info,info.nt.OptionalHeader.ImageBase,reinterpret_cast<std::uint64_t>(rt->allocation.get()));
    if(status!=hook_status::success)return status;
    status=validate_functions(stage,info);if(status!=hook_status::success)return status;
    status=imports(stage,info);if(status!=hook_status::success)return status;
    rt->info=info;
    status=apply(*rt,stage,info);
    if(status!=hook_status::success)return status;
    out=std::move(rt);return hook_status::success;
}
bool snapshot(owned_image_runtime& rt,std::vector<std::uint8_t>& bytes) {
    bytes.assign(rt.info.size,0);
    for(std::size_t p=0;p<rt.info.protection.size();++p)
        if(rt.info.protection[p]!=PAGE_NOACCESS &&
           !memory::safe_copy(bytes.data()+p*page_size,
                             static_cast<std::uint8_t*>(rt.allocation.get())+p*page_size,page_size))return false;
    return true;
}
}
image_export owned_dll_image::pin_export(const char* name) const {
    image_export result;
    auto owner=runtime_;if(!owner)return result;
    auto scope=owner->domain->enter();if(!scope)return result;
    auto address=export_at(owner->allocation.get(),owner->info,name);
    if(!address)return result;
    result.owner_=std::move(owner);result.scope_=std::move(scope);result.address_=address;
    return result;
}
void* owned_dll_image::base() const noexcept {return runtime_?runtime_->allocation.get():nullptr;}
std::size_t owned_dll_image::image_size() const noexcept {return runtime_?runtime_->mapped_size.load(std::memory_order_acquire):0;}
dll_hollow::dll_hollow(memory::patch_api api):api_(api) {
    if(!api.protect || !api.flush)throw std::invalid_argument("patch_api requires both functions");
}
dll_hollow::~dll_hollow() {
    try {if(uninstall_all()==hook_status::success)return;}catch(...){}
    (void)images_.release();
}
hook_status dll_hollow::load_image(const wchar_t* path,owned_dll_image& out,std::size_t capacity) try {
    if(out.runtime_)return hook_status::already_hooked;
    std::shared_ptr<owned_image_runtime> owner;
    auto status=make_image(path,capacity,owner,api_);
    if(status==hook_status::success)out.runtime_=std::move(owner);
    return status;
}catch(const std::bad_alloc&){return hook_status::alloc_failed;}
hook_status dll_hollow::replace_image(owned_dll_image& target,const wchar_t* replacement,
                                      owned_dll_image* original_snapshot) try {
    if(!target.runtime_ || (original_snapshot && (original_snapshot==&target || original_snapshot->runtime_)))
        return hook_status::invalid_address;
    std::lock_guard<std::mutex> lock(mutex_);
    auto rt=target.runtime_;auto base=rt->allocation.get();
    if(images_->count(base))return hook_status::already_hooked;
    std::shared_ptr<owned_image_runtime> candidate;
    auto status=make_image(replacement,0,candidate);
    if(status!=hook_status::success)return status;
    if(candidate->info.size>rt->capacity)return hook_status::unsupported;
    threading::patch_scope exclusive(rt->domain);
    if(!exclusive)return hook_status::busy;
    auto backup=std::make_shared<image_backup>();backup->target=rt;backup->info=rt->info;
    if(!snapshot(*rt,backup->bytes))return hook_status::invalid_address;
    std::shared_ptr<owned_image_runtime> original;
    if(original_snapshot) {
        original=std::make_shared<owned_image_runtime>();original->capacity=rt->info.size;
        original->allocation.reset(VirtualAlloc(nullptr,original->capacity,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if(!original->allocation)return hook_status::alloc_failed;
        auto bytes=backup->bytes;
        status=relocate(bytes,backup->info,reinterpret_cast<std::uint64_t>(base),
                        reinterpret_cast<std::uint64_t>(original->allocation.get()));
        if(status!=hook_status::success)return status;
        original->info=backup->info;
        status=apply(*original,bytes,backup->info);if(status!=hook_status::success)return status;
    }
    std::vector<std::uint8_t> stage;
    if(!snapshot(*candidate,stage))return hook_status::invalid_address;
    status=relocate(stage,candidate->info,reinterpret_cast<std::uint64_t>(candidate->allocation.get()),
                    reinterpret_cast<std::uint64_t>(base));
    if(status!=hook_status::success)return status;
    images_->emplace(base,backup); 
    status=apply(*rt,stage,candidate->info);
    if(status!=hook_status::success) {
        const auto rolled_back=apply(*rt,backup->bytes,backup->info);
        exclusive.healthy(rolled_back==hook_status::success);
        if(rolled_back==hook_status::success) {images_->erase(base);return hook_status::protect_failed;}
        return hook_status::partial;
    }
    exclusive.healthy(true);
    if(original_snapshot)original_snapshot->runtime_=std::move(original);
    return hook_status::success;
}catch(const std::bad_alloc&){return hook_status::alloc_failed;}
hook_status dll_hollow::restore_locked(void* base) {
    auto it=images_->find(base);if(it==images_->end())return hook_status::not_hooked;
    auto rt=it->second->target;
    threading::patch_scope exclusive(rt->domain);
    if(!exclusive)return hook_status::busy;
    const auto status=apply(*rt,it->second->bytes,it->second->info);
    exclusive.healthy(status==hook_status::success);
    if(status==hook_status::success)images_->erase(it);
    return status;
}
hook_status dll_hollow::restore_image(owned_dll_image& target) {return uninstall(target.base());}
hook_status dll_hollow::install(void*,void*,void** original) {
    if(original)*original=nullptr;return hook_status::unsupported;
}
hook_status dll_hollow::uninstall(void* target) {
    std::lock_guard<std::mutex> lock(mutex_);return restore_locked(target);
}
hook_status dll_hollow::uninstall_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto result=hook_status::success;
    for(auto it=images_->begin();it!=images_->end();) {
        auto* base=it->first;++it;
        if(restore_locked(base)!=hook_status::success)result=hook_status::partial;
    }
    return result;
}
bool dll_hollow::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(mutex_);return images_->count(target)!=0;
}
std::size_t dll_hollow::active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);return images_->size();
}
}
