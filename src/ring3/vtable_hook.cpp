#include "shadowhook/ring3/vtable_hook.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>

namespace shadowhook::ring3 {

    hook_status vtable_hook::install(void* target, void* detour, void** original) {
        if (!target || !detour) return hook_status::invalid_address;

        void** instance_ptr = (void**)target;
        void** vtable = *(void***)target; /// fck cpp
        if (!vtable) {
            SH_LOG_ERROR("vtable: null vtable for instance %p", target);
            return hook_status::invalid_address;
        }

        void* first_method = vtable[0];
        uint32_t idx = find_vtable_index(vtable, first_method);
        if (idx == UINT32_MAX) {
            SH_LOG_ERROR("vtable: cannot find method index for instance %p", target);
            return hook_status::invalid_address;
        }

        if (vtable_hooks_.count(target)) {
            SH_LOG_WARN("vtable: instance %p already hooked at index %u", target, idx);
            return hook_status::already_hooked;
        }

        DWORD old;
        if (!VirtualProtect(&vtable[idx], sizeof(void*), PAGE_READWRITE, &old)) {
            SH_LOG_ERROR("vtable: protect failed for index %u", idx);
            return hook_status::protect_failed;
        }

        vtable_entry ve = {};
        ve.target = target;
        ve.detour = detour;
        ve.vtable_ptr = vtable;
        ve.method_index = idx;
        ve.original_method = vtable[idx];
        ve.patch_size = sizeof(void*);
        memcpy(ve.saved_bytes, &vtable[idx], sizeof(void*));
        ve.active = true;

        vtable[idx] = detour;

        DWORD tmp;
        VirtualProtect(&vtable[idx], sizeof(void*), old, &tmp);

        if (original) *original = ve.original_method;

        vtable_hooks_[target] = ve;
        hooks_.push_back({ target, detour, ve.original_method, sizeof(void*), {}, true });

        SH_LOG_INFO("[vtable] hooked instance %p [idx=%u] %p -> %p",
            target, idx, ve.original_method, detour);

        return hook_status::success;
    }

    hook_status vtable_hook::uninstall(void* target) {
        auto it = vtable_hooks_.find(target);
        if (it == vtable_hooks_.end()) return hook_status::not_hooked;

        auto& ve = it->second;
        DWORD old;
        if (!VirtualProtect(&ve.vtable_ptr[ve.method_index], sizeof(void*),
            PAGE_READWRITE, &old)) {
            return hook_status::protect_failed;
        }

        ve.vtable_ptr[ve.method_index] = ve.original_method;

        DWORD tmp;
        VirtualProtect(&ve.vtable_ptr[ve.method_index], sizeof(void*), old, &tmp);

        SH_LOG_INFO("[vtable] restored instance %p [idx=%u]", target, ve.method_index);

        vtable_hooks_.erase(it);

        auto h_it = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& e) { return e.target == target; });
        if (h_it != hooks_.end()) hooks_.erase(h_it);

        return hook_status::success;
    }

    hook_status vtable_hook::uninstall_all() {
        hook_status status = hook_status::success;
        auto copy = vtable_hooks_;
        for (auto& [target, ve] : copy) {
            if (uninstall(target) != hook_status::success) {
                status = hook_status::partial;
            }
        }
        return status;
    }

    bool vtable_hook::is_hooked(void* target) const {
        return vtable_hooks_.count(target) > 0;
    }

    uint32_t vtable_hook::find_vtable_index(void** vtable, void* target_method, size_t max_scan) {
        for (size_t i = 0; i < max_scan; i++) {
            if (vtable[i] == target_method) {
                return static_cast<uint32_t>(i);
            }
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(vtable + i, &mbi, sizeof(mbi))) break;
            if (mbi.State != MEM_COMMIT) break;
        }
        return UINT32_MAX;
    }

} // namespace shadowhook::ring3