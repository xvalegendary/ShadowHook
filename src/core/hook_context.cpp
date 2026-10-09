#include "shadowhook/core/hook_context.hpp"
#include "shadowhook/utils/logger.hpp"

namespace shadowhook {

    void hook_context::save(CONTEXT* ctx) {
        if (!ctx) return;
        saved_rip = ctx->Rip;
        saved_rsp = ctx->Rsp;
        saved_rax = ctx->Rax;
        saved_rcx = ctx->Rcx;
        saved_rdx = ctx->Rdx;
        saved_r8 = ctx->R8;
        saved_r9 = ctx->R9;
    }

    void hook_context::restore(CONTEXT* ctx) {
        if (!ctx) return;
        ctx->Rip = saved_rip;
        ctx->Rsp = saved_rsp;
        ctx->Rax = saved_rax;
        ctx->Rcx = saved_rcx;
        ctx->Rdx = saved_rdx;
        ctx->R8 = saved_r8;
        ctx->R9 = saved_r9;
    }

    void hook_context::set_rip(CONTEXT* ctx, uintptr_t addr) {
        if (ctx) ctx->Rip = addr;
    }

    void hook_context::add_rip(CONTEXT* ctx, int32_t offset) {
        if (ctx) ctx->Rip += offset;
    }

    void hook_context::set_single_step(CONTEXT* ctx, bool enable) {
        if (!ctx) return;
        if (enable) {
            ctx->EFlags |= (1 << 8);
        }
        else {
            ctx->EFlags &= ~(1 << 8);
        }
    }

    bool hook_context::is_single_step(CONTEXT* ctx) {
        if (!ctx) return false;
        return (ctx->EFlags & (1 << 8)) != 0;
    }

} // namespace shadowhook