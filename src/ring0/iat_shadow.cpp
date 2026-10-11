#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "shadowhook/ring0/iat_shadow.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <cstring>
#include <string>

namespace shadowhook::ring0 {
namespace {
struct image_view {
    std::uintptr_t base{};
    std::size_t size{};
    IMAGE_DATA_DIRECTORY imports{};
    bool bounds(std::size_t offset, std::size_t count) const {
        return offset <= size && count <= size - offset && count <= UINTPTR_MAX - (base + offset);
    }
    template<class T> bool read(std::size_t offset, T& value) const {
        return bounds(offset, sizeof(T)) &&
            memory::readable_range(reinterpret_cast<void*>(base + offset), sizeof(T)) &&
            memory::safe_copy(&value, reinterpret_cast<void*>(base + offset), sizeof(T));
    }
    bool text(std::size_t offset, std::string& value) const {
        value.clear();
        for (std::size_t i = 0; i < 4096; ++i) {
            char c{};
            if (offset > size || i > size - offset || !read(offset + i, c)) return false;
            if (!c) return true;
            value.push_back(c);
        }
        return false;
    }
};
bool inspect_image(void* module, image_view& image) {
    const auto base = reinterpret_cast<std::uintptr_t>(module);
    MEMORY_BASIC_INFORMATION m{};
    if (!base || VirtualQuery(module, &m, sizeof(m)) != sizeof(m) || m.AllocationBase != module) return false;
    std::size_t allocation{};
    auto cursor = base;
    do {
        const auto region = reinterpret_cast<std::uintptr_t>(m.BaseAddress);
        if (region != cursor || !m.RegionSize || m.RegionSize > UINTPTR_MAX - cursor) return false;
        allocation += m.RegionSize;
        cursor += m.RegionSize;
        if (VirtualQuery(reinterpret_cast<void*>(cursor), &m, sizeof(m)) != sizeof(m)) break;
    } while (m.AllocationBase == module);
    image = {base, allocation, {}};
    IMAGE_DOS_HEADER dos{};
    if (!image.read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) return false;
    const auto nt_offset = static_cast<std::size_t>(dos.e_lfanew);
    struct nt_prefix { DWORD signature; IMAGE_FILE_HEADER file; };
    static_assert(sizeof(nt_prefix) == 24);
    nt_prefix prefix{};
    if (!image.read(nt_offset, prefix) || prefix.signature != IMAGE_NT_SIGNATURE ||
        prefix.file.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        prefix.file.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !image.bounds(nt_offset, sizeof(prefix) + prefix.file.SizeOfOptionalHeader)) return false;
    IMAGE_OPTIONAL_HEADER64 optional{};
    if (!image.read(nt_offset + sizeof(prefix), optional) ||
        optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        optional.SizeOfImage > allocation || optional.SizeOfImage < sizeof(IMAGE_DOS_HEADER) ||
        optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
        optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return false;
    image.size = optional.SizeOfImage;
    if (!image.bounds(nt_offset, sizeof(prefix) + prefix.file.SizeOfOptionalHeader)) return false;
    image.imports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    return image.imports.VirtualAddress && image.imports.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR) &&
        image.bounds(image.imports.VirtualAddress, image.imports.Size) &&
        memory::readable_range(reinterpret_cast<void*>(base + image.imports.VirtualAddress), image.imports.Size);
}
std::vector<void**> lookup(void* module, void* target, const char* dll_name = nullptr,
                           const char* function = nullptr) {
    image_view image{};
    if (!inspect_image(module, image)) return {};
    std::vector<void**> slots;
    const auto count = image.imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    bool descriptors_terminated{};
    for (std::size_t n = 0; n < count; ++n) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        if (!image.read(image.imports.VirtualAddress + n * sizeof(d), d)) return {};
        if (!d.Name && !d.FirstThunk && !d.OriginalFirstThunk) { descriptors_terminated = true; break; }
        if (!d.Name || !d.FirstThunk) return {};
        std::string dll;
        if (!image.text(d.Name, dll)) return {};
        const bool selected_dll = !dll_name || _stricmp(dll.c_str(), dll_name) == 0;
        if (d.FirstThunk % alignof(void*) || !image.bounds(d.FirstThunk, sizeof(IMAGE_THUNK_DATA64))) return {};
        const auto max = (image.size - d.FirstThunk) / sizeof(IMAGE_THUNK_DATA64);
        bool terminated{};
        for (std::size_t i = 0; i < max; ++i) {
            IMAGE_THUNK_DATA64 ft{};
            const auto ft_offset = d.FirstThunk + i * sizeof(ft);
            if (!image.read(ft_offset, ft)) return {};
            if (!ft.u1.Function) { terminated = true; break; }
            bool matched = target && ft.u1.Function == reinterpret_cast<std::uintptr_t>(target);
            if (function && selected_dll) {
                if (!d.OriginalFirstThunk || !image.bounds(d.OriginalFirstThunk, sizeof(ft)) ||
                    i > (image.size - d.OriginalFirstThunk) / sizeof(ft)) return {};
                IMAGE_THUNK_DATA64 oft{};
                if (!image.read(d.OriginalFirstThunk + i * sizeof(oft), oft)) return {};
                if (!IMAGE_SNAP_BY_ORDINAL64(oft.u1.Ordinal) && oft.u1.AddressOfData) {
                    if (!image.bounds(oft.u1.AddressOfData, sizeof(WORD) + 1)) return {};
                    std::string name;
                    if (!image.text(oft.u1.AddressOfData + sizeof(WORD), name)) return {};
                    matched = name == function;
                }
            }
            if (matched && selected_dll) {
                auto slot = reinterpret_cast<void**>(image.base + ft_offset);
                if (std::find(slots.begin(), slots.end(), slot) == slots.end()) slots.push_back(slot);
            }
        }
        if (!terminated) return {};
    }
    return descriptors_terminated ? slots : std::vector<void**>{};
}
} // namespace

std::vector<void**> iat_shadow::find_iat_slots(void* module, void* target) {
    return target ? lookup(module, target) : std::vector<void**>{};
}
void** iat_shadow::find_iat_entry_addr(void* module, const char* dll, const char* function) {
    if (!module || !dll || !function) return nullptr;
    const auto slots = lookup(module, nullptr, dll, function);
    return slots.empty() ? nullptr : slots.front();
}
void* iat_shadow::resolve_import(const char* module, const char* function) {
    if (!module || !function) return nullptr;
    const auto handle = GetModuleHandleA(module);
    return handle ? reinterpret_cast<void*>(GetProcAddress(handle, function)) : nullptr;
}
iat_shadow::~iat_shadow() {
    try { if (uninstall_all() == hook_status::success) return; } catch (...) {}
    (void)records_.release();
    try { SH_LOG_ERROR("[iat_shadow] failed shutdown: recovery records quarantined"); } catch (...) {}
}
hook_status iat_shadow::install(void* target, void* detour, void** original) {
    return install_module(GetModuleHandleW(nullptr), target, detour, original, true);
}
hook_status iat_shadow::install_module(void* module, void* target, void* detour,
                                      void** original, bool all) {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        auto slots = find_iat_slots(module, target);
        if (!all && slots.size() > 1) slots.resize(1);
        return install_selected(target, detour, original, slots);
    } catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
}
hook_status iat_shadow::install_slot(void* module, void** slot, void* target,
                                    void* detour, void** original) {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        const auto slots = find_iat_slots(module, target);
        if (std::find(slots.begin(), slots.end(), slot) == slots.end()) return hook_status::invalid_address;
        return install_selected(target, detour, original, {slot});
    } catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
}
hook_status iat_shadow::install_selected(void* target, void* detour, void** original,
                                        const std::vector<void**>& slots) {
    if (original) *original = nullptr;
    if (!target || !detour || target == detour || slots.empty()) return hook_status::invalid_address;
    if (records_->count(target)) return hook_status::already_hooked;
    std::vector<iat_entry> prepared;
    prepared.reserve(slots.size());
    for (auto slot : slots) {
        iat_entry e{};
        e.slot = slot; e.original = target; e.detour = detour;
        if (!memory::capture_pages(slot, sizeof(void*), e.pages)) return hook_status::invalid_address;
        prepared.push_back(std::move(e));
    }
    auto inserted = records_->emplace(target, std::move(prepared));
    auto& entries = inserted.first->second;
    if (original) *original = target; 
    bool committed = true;
    for (auto& e : entries) {
        if (!memory::make_writable(e.pages, {})) { committed = false; break; }
        const auto seen = InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(e.slot), detour, target);
        e.active = seen == target;
        const bool rights = memory::restore_pages(e.pages, {});
        if (!e.active || !rights) { committed = false; break; }
    }
    if (committed) return hook_status::success;
    bool rolled_back = true;
    for (auto& e : entries) if (restore(e) != hook_status::success) rolled_back = false;
    if (!rolled_back) return hook_status::partial;
    records_->erase(inserted.first);
    return hook_status::protect_failed;
}
hook_status iat_shadow::restore(iat_entry& e) {
    if (!memory::make_writable(e.pages, {})) {
        memory::restore_pages(e.pages, {});
        return hook_status::partial;
    }
    bool restored = true;
    if (e.active) {
        const auto seen = InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(e.slot),
                                                           e.original, e.detour);
        restored = seen == e.detour || seen == e.original;
        if (restored) e.active = false; 
    }
    const bool rights = memory::restore_pages(e.pages, {});
    return restored && rights ? hook_status::success : hook_status::partial;
}
hook_status iat_shadow::uninstall(void* target) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = records_->find(target);
    if (it == records_->end()) return hook_status::not_hooked;
    bool ok = true;
    for (auto& e : it->second) if (restore(e) != hook_status::success) ok = false;
    if (!ok) return hook_status::partial;
    records_->erase(it);
    return hook_status::success;
}
hook_status iat_shadow::uninstall_all() try {
    std::vector<void*> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& e : *records_) targets.push_back(e.first);
    }
    auto status = hook_status::success;
    for (auto target : targets) {
        const auto result = uninstall(target);
        if (result != hook_status::success && result != hook_status::not_hooked) status = hook_status::partial;
    }
    return status;
}
catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
bool iat_shadow::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_->count(target) != 0;
}
std::size_t iat_shadow::active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_->size();
}
} // namespace shadowhook::ring0
