#include "shadowhook/ring0/iat_shadow.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook::ring0 {

    void** iat_shadow::find_iat_entry_addr(void* module_base, const char* import_module,
        const char* func_name) {
        if (!module_base || !import_module || !func_name) return nullptr;

        auto* dos = (IMAGE_DOS_HEADER*)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) return nullptr;

        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)module_base + dir.VirtualAddress);

        for (; imp->Name; imp++) {
            const char* dll_name = (const char*)((uint8_t*)module_base + imp->Name);
            if (_stricmp(dll_name, import_module) != 0) continue;

            auto* oft = (IMAGE_THUNK_DATA64*)((uint8_t*)module_base + imp->OriginalFirstThunk);
            auto* ft = (IMAGE_THUNK_DATA64*)((uint8_t*)module_base + imp->FirstThunk);

            for (; oft->u1.AddressOfData; oft++, ft++) {
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) continue;

                auto* ibn = (IMAGE_IMPORT_BY_NAME*)
                    ((uint8_t*)module_base + oft->u1.AddressOfData);
                if (strcmp(ibn->Name, func_name) == 0) {
                    return (void**)&ft->u1.Function;
                }
            }
        }

        return nullptr;
    }

    void* iat_shadow::resolve_import(const char* module, const char* func_name) {
        HMODULE h = GetModuleHandleA(module);
        if (!h) h = LoadLibraryA(module);
        if (!h) return nullptr;
        return GetProcAddress(h, func_name);
    }

    hook_status iat_shadow::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (iat_hooks_.count(target)) {
            SH_LOG_WARN("[iat_shadow] %p already hooked", target);
            return hook_status::already_hooked;
        }

        HMODULE hLocal = GetModuleHandleA(nullptr);
        if (!hLocal) return hook_status::invalid_address;

        auto* dos = (IMAGE_DOS_HEADER*)hLocal;
        auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)hLocal + dos->e_lfanew);
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) return hook_status::invalid_address;

        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)hLocal + dir.VirtualAddress);
        void** iat_slot = nullptr;

        for (; imp->Name; imp++) {
            auto* ft = (IMAGE_THUNK_DATA64*)((uint8_t*)hLocal + imp->FirstThunk);
            for (; ft->u1.AddressOfData; ft++) {
                if ((void*)ft->u1.Function == target) {
                    iat_slot = (void**)&ft->u1.Function;
                    break;
                }
            }
            if (iat_slot) break;
        }

        if (!iat_slot) {
            SH_LOG_ERROR("[iat_shadow] target %p not found in IAT", target);
            return hook_status::invalid_address;
        }

        DWORD old;
        if (!VirtualProtect(iat_slot, sizeof(void*), PAGE_READWRITE, &old)) {
            SH_LOG_ERROR("[iat_shadow] protect failed for %p", iat_slot);
            return hook_status::protect_failed;
        }

        iat_entry ie = {};
        ie.target = target;
        ie.detour = detour;
        ie.iat_slot = iat_slot;
        ie.real_function = *iat_slot;
        ie.original = ie.real_function;
        ie.patch_size = sizeof(void*);
        memcpy(ie.saved_bytes, &ie.real_function, sizeof(void*));
        ie.active = true;

        *iat_slot = detour;

        DWORD tmp;
        VirtualProtect(iat_slot, sizeof(void*), old, &tmp);

        if (original) *original = ie.real_function;

        iat_hooks_[target] = ie;
        hooks_.push_back({ target, detour, ie.real_function, sizeof(void*), {}, true });

        SH_LOG_INFO("[iat_shadow] %p: %p -> %p (slot=%p)", target, ie.real_function, detour, iat_slot);

        return hook_status::success;
    }

    hook_status iat_shadow::uninstall(void* target) {
        auto it = iat_hooks_.find(target);
        if (it == iat_hooks_.end()) return hook_status::not_hooked;

        auto& ie = it->second;

        DWORD old;
        if (!VirtualProtect(ie.iat_slot, sizeof(void*), PAGE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        *ie.iat_slot = ie.real_function;

        DWORD tmp;
        VirtualProtect(ie.iat_slot, sizeof(void*), old, &tmp);

        SH_LOG_INFO("[iat_shadow] restored %p", ie.iat_slot);

        iat_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        return hook_status::success;
    }

    hook_status iat_shadow::uninstall_all() {
        auto copy = iat_hooks_;
        for (auto& kv : copy) {
            uninstall(kv.first);
        }
        return hook_status::success;
    }

    bool iat_shadow::is_hooked(void* target) const {
        return iat_hooks_.count(target) > 0;
    }

} // namespace shadowhook::ring0