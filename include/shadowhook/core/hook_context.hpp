#pragma once
#include <cstdint>
#include <windows.h>

namespace shadowhook {

    class hook_context {
    public:
        void save(CONTEXT* ctx);
        void restore(CONTEXT* ctx);

        void set_rip(CONTEXT* ctx, uintptr_t addr);
        void add_rip(CONTEXT* ctx, int32_t offset);

        void set_single_step(CONTEXT* ctx, bool enable);
        bool is_single_step(CONTEXT* ctx);

    private:
        uintptr_t saved_rip = 0;
        uintptr_t saved_rsp = 0;
        uintptr_t saved_rax = 0;
        uintptr_t saved_rcx = 0;
        uintptr_t saved_rdx = 0;
        uintptr_t saved_r8 = 0;
        uintptr_t saved_r9 = 0;
    };

} // namespace shadowhook