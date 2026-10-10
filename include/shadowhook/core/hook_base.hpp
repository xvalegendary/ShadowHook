#pragma once
#include "hook_types.hpp"
#include "hook_context.hpp"
#include <memory>
#include <vector>
#include <atomic>

namespace shadowhook {

    class hook_base {
    public:
        hook_base() = default;
        virtual ~hook_base() = default;

        hook_base(const hook_base&) = delete;
        hook_base& operator=(const hook_base&) = delete;
        hook_base(hook_base&&) = delete;
        hook_base& operator=(hook_base&&) = delete;

        virtual hook_status install(void* target, void* detour, void** original) = 0;
        virtual hook_status uninstall(void* target) = 0;
        virtual hook_status uninstall_all() = 0;
        virtual bool        is_hooked(void* target) const = 0;
        virtual hook_type   type() const = 0;
        virtual const char* name() const = 0;

        size_t active_count() const { return hooks_.size(); }

    protected:
        struct entry {
            void* target;
            void* detour;
            void* original;
            size_t        patch_size;
            bool          active;
        };

        std::vector<entry> hooks_;

        entry* find_entry(void* target);
        const entry* find_entry(void* target) const;

        bool save_bytes(void* dst, const void* src, size_t size);
        bool restore_bytes(void* dst, const entry* e);

        virtual bool protect(void* addr, size_t size, DWORD* old);
    };

} // namespace shadowhook