#include "shadowhook/ring3/dll_hollow.hpp"
#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/memory.hpp"

namespace shadowhook::ring3 {

    hook_status dll_hollow::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        if (hollow_hooks_.count(target)) {
            return hook_status::already_hooked;
        }

        HMODULE hLocal = GetModuleHandleA(nullptr);
        if (!hLocal) return hook_status::invalid_address;

        auto* dos = (IMAGE_DOS_HEADER*)hLocal;
        auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)hLocal + dos->e_lfanew);
        auto* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir->Size) return hook_status::invalid_address;

        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)hLocal + dir->VirtualAddress);
        void** iat_slot = nullptr;

        for (; imp->Name; imp++) {
            auto* oft = (IMAGE_THUNK_DATA64*)((uint8_t*)hLocal + imp->OriginalFirstThunk);
            auto* ft = (IMAGE_THUNK_DATA64*)((uint8_t*)hLocal + imp->FirstThunk);

            for (; oft->u1.AddressOfData; oft++, ft++) {
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) continue;
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)hLocal + oft->u1.AddressOfData);
                if ((void*)ft->u1.Function == target) {
                    iat_slot = (void**)&ft->u1.Function;
                    break;
                }
            }
            if (iat_slot) break;
        }

        if (!iat_slot) {
            SH_LOG_ERROR("[dll_hollow] target %p not found in IAT", target);
            return hook_status::invalid_address;
        }

        DWORD old;
        if (!memory::protect(iat_slot, sizeof(void*), PAGE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        hollow_entry he = {};
        he.target = target;
        he.detour = detour;
        he.iat_slot = iat_slot;
        he.real_function = *iat_slot;
        he.original = he.real_function;
        he.patch_size = sizeof(void*);
        memcpy(he.saved_bytes, iat_slot, sizeof(void*));
        he.active = true;

        *iat_slot = detour;

        DWORD tmp;
        memory::protect(iat_slot, sizeof(void*), old, &tmp);

        if (original) *original = he.real_function;

        hollow_hooks_[target] = he;
        hooks_.push_back({ target, detour, he.real_function, sizeof(void*), {}, true });

        SH_LOG_INFO("[dll_hollow] hooked %p -> %p (via IAT %p)", target, detour, iat_slot);
        return hook_status::success;
    }

    hook_status dll_hollow::uninstall(void* target) {
        auto it = hollow_hooks_.find(target);
        if (it == hollow_hooks_.end()) return hook_status::not_hooked;

        auto& he = it->second;

        DWORD old;
        if (!memory::protect(he.iat_slot, sizeof(void*), PAGE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        *he.iat_slot = he.real_function;

        DWORD tmp;
        memory::protect(he.iat_slot, sizeof(void*), old, &tmp);

        hollow_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        SH_LOG_INFO("[dll_hollow] restored %p", target);
        return hook_status::success;
    }

    hook_status dll_hollow::uninstall_all() {
        auto copy = hollow_hooks_;
        for (auto& kv : copy) {
            uninstall(kv.first);
        }
        return hook_status::success;
    }

    bool dll_hollow::is_hooked(void* target) const {
        return hollow_hooks_.count(target) > 0;
    }

} // namespace shadowhook::ring3