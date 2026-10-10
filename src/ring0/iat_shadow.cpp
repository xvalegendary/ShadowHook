#define NOMINMAX
#include "shadowhook/ring0/iat_shadow.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace shadowhook::ring0 {
    namespace {
        struct image_view {
            std::uint8_t* base{};
            std::size_t image_size{};
            IMAGE_DATA_DIRECTORY imports{};
            std::uint8_t* rva(std::size_t offset, std::size_t count) const {
                if (!base || offset > image_size || count > image_size - offset) return nullptr;
                return base + offset;
            }
        };

        bool inspect_image(std::uint8_t* base, image_view& img) {
            if (!base) return false;
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 0x100000)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
                return false;
            img.base = base;
            img.image_size = nt->OptionalHeader.SizeOfImage;
            if (img.image_size < sizeof(IMAGE_DOS_HEADER) ||
                static_cast<std::size_t>(dos->e_lfanew) > img.image_size ||
                sizeof(*nt) > img.image_size - static_cast<std::size_t>(dos->e_lfanew)) return false;
            img.imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            return img.imports.Size != 0 && img.rva(img.imports.VirtualAddress, img.imports.Size);
        }

        bool get_main_image(image_view& img) {
            return inspect_image(reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr)), img);
        }

        void** find_resolved_iat_slot(void* target) {
            image_view img{};
            if (!get_main_image(img)) return nullptr;
            const auto* descriptors = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                img.rva(img.imports.VirtualAddress, img.imports.Size));
            const auto count = img.imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
            for (std::size_t n = 0; n < count; ++n) {
                const auto& d = descriptors[n];
                if (!d.Name && !d.FirstThunk) break;
                if (d.FirstThunk == 0) continue;
                const std::size_t offset = d.FirstThunk;
                if (!img.rva(offset, sizeof(IMAGE_THUNK_DATA64))) continue;
                const auto max_thunks = (img.image_size - offset) / sizeof(IMAGE_THUNK_DATA64);
                for (std::size_t i = 0; i < max_thunks; ++i) {
                    auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                        img.rva(offset + i * sizeof(IMAGE_THUNK_DATA64), sizeof(IMAGE_THUNK_DATA64)));
                    if (thunk->u1.Function == 0) break;
                    if (reinterpret_cast<void*>(static_cast<std::uintptr_t>(thunk->u1.Function)) == target)
                        return reinterpret_cast<void**>(&thunk->u1.Function);
                }
            }
            return nullptr;
        }
    } // namespace

    void** iat_shadow::find_iat_entry_addr(void* module_base, const char* import_module, const char* func_name) {
        if (!module_base || !import_module || !func_name) return nullptr;
        image_view img{};
        if (!inspect_image(static_cast<std::uint8_t*>(module_base), img)) return nullptr;
        const auto* descriptors = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            img.rva(img.imports.VirtualAddress, img.imports.Size));
        const auto count = img.imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (std::size_t i = 0; i < count; ++i) {
            const auto& desc = descriptors[i];
            if (!desc.Name && !desc.FirstThunk) break;
            const auto* dll = img.rva(desc.Name, 1);
            if (!dll || !std::memchr(dll, 0, img.image_size - desc.Name) ||
                _stricmp(reinterpret_cast<const char*>(dll), import_module) != 0) continue;
            if (!desc.OriginalFirstThunk || !desc.FirstThunk) continue;
            if (!img.rva(desc.OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA64)) ||
                !img.rva(desc.FirstThunk, sizeof(IMAGE_THUNK_DATA64))) continue;
            const auto count_oft = (img.image_size - desc.OriginalFirstThunk) / sizeof(IMAGE_THUNK_DATA64);
            const auto count_ft = (img.image_size - desc.FirstThunk) / sizeof(IMAGE_THUNK_DATA64);
            for (std::size_t j = 0; j < std::min(count_oft, count_ft); ++j) {
                const auto* oft = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
                    img.rva(desc.OriginalFirstThunk + j * sizeof(IMAGE_THUNK_DATA64), sizeof(IMAGE_THUNK_DATA64)));
                auto* ft = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                    img.rva(desc.FirstThunk + j * sizeof(IMAGE_THUNK_DATA64), sizeof(IMAGE_THUNK_DATA64)));
                if (!oft->u1.AddressOfData) break;
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) continue;
                const auto rva = static_cast<std::size_t>(oft->u1.AddressOfData);
                const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(img.rva(rva, 3));
                if (!ibn) continue;
                const auto remaining = img.image_size - rva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                if (!std::memchr(ibn->Name, 0, remaining)) continue;
                if (std::strcmp(ibn->Name, func_name) == 0)
                    return reinterpret_cast<void**>(&ft->u1.Function);
            }
        }
        return nullptr;
    }

    void* iat_shadow::resolve_import(const char* module, const char* func_name) {
        if (!module || !func_name) return nullptr;
        const auto h = GetModuleHandleA(module); 
        return h ? reinterpret_cast<void*>(GetProcAddress(h, func_name)) : nullptr;
    }

    hook_status iat_shadow::install(void* target, void* detour, void** original) {
        if (original) *original = nullptr;
        if (!target || !detour || target == detour) return hook_status::invalid_address;
        if (iat_hooks_.count(target)) return hook_status::already_hooked;
        auto* slot = find_resolved_iat_slot(target);
        if (!slot) return hook_status::invalid_address;

        auto previous_value = *slot;
        iat_entry entry{};
        entry.target = target;
        entry.detour = detour;
        entry.iat_slot = slot;
        entry.real_function = previous_value;
        entry.original = previous_value;
        entry.patch_size = sizeof(void*);
        std::memcpy(entry.saved_bytes, &previous_value, sizeof(previous_value));
        entry.active = true;

        
        iat_hooks_.emplace(target, entry);
        try {
            hooks_.push_back({ target, detour, previous_value, sizeof(void*), {}, true });
        }
        catch (...) {
            iat_hooks_.erase(target);
            return hook_status::alloc_failed;
        }
        DWORD old{};
        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) {
            iat_hooks_.erase(target);
            hooks_.pop_back();
            return hook_status::protect_failed;
        }

       
        void* seen = InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(slot),
            detour, previous_value);
        DWORD ignored{};
        const bool prot_ok = VirtualProtect(slot, sizeof(void*), old, &ignored) != 0;
        if (seen != previous_value) {
            iat_hooks_.erase(target);
            hooks_.pop_back();
            return prot_ok ? hook_status::already_hooked : hook_status::partial;
        }
        if (original) *original = previous_value;
        if (!prot_ok) return hook_status::partial; 
        return hook_status::success;
    }

    hook_status iat_shadow::uninstall(void* target) {
        const auto it = iat_hooks_.find(target);
        if (it == iat_hooks_.end()) return hook_status::not_hooked;
        auto& item = it->second;
        DWORD old{};
        if (!VirtualProtect(item.iat_slot, sizeof(void*), PAGE_READWRITE, &old))
            return hook_status::protect_failed;
        void* seen = InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(item.iat_slot), item.real_function, item.detour);
        DWORD ignored{};
        const bool prot_ok = VirtualProtect(item.iat_slot, sizeof(void*), old, &ignored) != 0;
        if (seen != item.detour || !prot_ok) return hook_status::partial;
        iat_hooks_.erase(it);
        auto pos = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& x) { return x.target == target; });
        if (pos != hooks_.end()) hooks_.erase(pos);
        return hook_status::success;
    }

    hook_status iat_shadow::uninstall_all() {
        hook_status overall = hook_status::success;
        std::vector<void*> targets;
        targets.reserve(iat_hooks_.size());
        for (const auto& p : iat_hooks_) targets.push_back(p.first);
        for (auto* target : targets)
            if (uninstall(target) != hook_status::success) overall = hook_status::partial;
        return overall;
    }

    bool iat_shadow::is_hooked(void* target) const {
        return iat_hooks_.count(target) != 0;
    }
} // namespace shadowhook::ring0
