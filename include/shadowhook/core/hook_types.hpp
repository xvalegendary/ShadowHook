#pragma once
#include <cstdint>
#include <cstddef>
#include <windows.h>

namespace shadowhook {

    enum class hook_status : uint8_t {
        success = 0x00,
        already_hooked = 0x01,
        not_hooked = 0x02,
        invalid_address = 0x03,
        alloc_failed = 0x04,
        protect_failed = 0x05,
        unsupported = 0x06,
        partial = 0x07
    };

    enum class hook_type : uint8_t {
        ept = 0x01,
        page_shadow = 0x02,
        iat_shadow = 0x03,
        ssdt_shadow = 0x04,
        vtable = 0x05,
        exception_veh = 0x06,
        dll_hollow = 0x07,
        inline_hook = 0x08
    };

    enum class hook_scope_type : uint8_t {
        global_scope = 0x00,
        process_scope = 0x01,
        thread_scope = 0x02
    };

    struct hook_descriptor {
        void* target;
        void* detour;
        void** original;
        hook_type           type;
        hook_scope_type     scope;
        uint32_t            pid;
        uint32_t            tid;
        size_t              patch_size;
        uint8_t             original_bytes[16];
    };



    using hook_callback_t = void(*)(hook_descriptor*);

    inline const char* status_str(hook_status s) {
        switch (s) {
        case hook_status::success:         return "success";
        case hook_status::already_hooked:  return "already_hooked";
        case hook_status::not_hooked:      return "not_hooked";
        case hook_status::invalid_address: return "invalid_address";
        case hook_status::alloc_failed:    return "alloc_failed";
        case hook_status::protect_failed:  return "protect_failed";
        case hook_status::unsupported:     return "unsupported";
        case hook_status::partial:         return "partial";
        default:                           return "unknown";
        }
    }

    inline const char* type_str(hook_type t) {
        switch (t) {
        case hook_type::ept:           return "ept";
        case hook_type::page_shadow:   return "page_shadow";
        case hook_type::iat_shadow:    return "iat_shadow";
        case hook_type::ssdt_shadow:   return "ssdt_shadow";
        case hook_type::vtable:        return "vtable";
        case hook_type::exception_veh: return "exception_veh";
        case hook_type::dll_hollow:    return "dll_hollow";
        case hook_type::inline_hook:   return "inline_hook";
        default:                       return "unknown";
        }
    }

} // namespace shadowhook