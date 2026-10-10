#include "shadowhook/ring3/inline_hook.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/memory.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace shadowhook::ring3 {
    namespace {
        struct instruction {
            std::size_t old_offset{};
            std::size_t new_offset{};
            std::size_t emitted_size{};
            asm_stubs::insn_info info{};
            std::uintptr_t destination{};
        };

        std::size_t output_size(const asm_stubs::insn_info& info) {
            switch (info.branch) {
            case asm_stubs::branch_kind::jump: return 14;
            case asm_stubs::branch_kind::call: return 16;
            case asm_stubs::branch_kind::conditional: return 16;
            default: return info.length;
            }
        }
    } // namespace

    inline_hook::~inline_hook() {
        const auto status = uninstall_all();
        if (status != hook_status::success)
            SH_LOG_ERROR("[inline_hook] destruction with remaining live patches: %s", status_str(status));
    }

    hook_status inline_hook::install(void* target, void* detour, void** original) {
        if (original) *original = nullptr;
        if (!target || !detour || target == detour) return hook_status::invalid_address;
        if (inline_hooks_.count(target)) return hook_status::already_hooked;
        if (!memory::is_executable(target)) return hook_status::invalid_address;

        const auto* source = static_cast<const std::uint8_t*>(target);
        const auto source_start = reinterpret_cast<std::uintptr_t>(target);
        std::vector<instruction> steps;
        std::size_t patch_size = 0, output_length = 0;


        while (patch_size < sizeof(asm_stubs::jmp_abs)) {
            MEMORY_BASIC_INFORMATION mbi{};
            const auto* addr = source + patch_size;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                return hook_status::invalid_address;
            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto current = reinterpret_cast<std::uintptr_t>(addr);
            if (current < base || current - base >= mbi.RegionSize) return hook_status::invalid_address;
            const auto accessible = std::min<std::size_t>(15, mbi.RegionSize - (current - base));
            const auto info = asm_stubs::decode(addr, accessible);
            if (info.length == 0 || info.length > accessible || info.length > 15)
                return hook_status::unsupported;

            instruction item{};
            item.old_offset = patch_size;
            item.new_offset = output_length;
            item.emitted_size = output_size(info);
            item.info = info;
            if (info.is_relative) {
                std::int64_t relative = 0;
                if (info.rel_size == 1) {
                    std::int8_t value{};
                    std::memcpy(&value, addr + info.rel_offset, 1);
                    relative = value;
                }
                else if (info.rel_size == 4) {
                    std::int32_t value{};
                    std::memcpy(&value, addr + info.rel_offset, 4);
                    relative = value;
                }
                else return hook_status::unsupported;
                const auto base_after = static_cast<std::int64_t>(current + info.length);
                item.destination = static_cast<std::uintptr_t>(base_after + relative);
            }
            steps.push_back(item);
            patch_size += info.length;
            output_length += item.emitted_size;
            if (patch_size > 256 || output_length > 2048) return hook_status::unsupported;
        }

        for (const auto& step : steps) {
            if (!step.info.is_relative) continue;
            if (step.destination >= source_start && step.destination - source_start < patch_size) {
                const auto offset = step.destination - source_start;
                if (std::none_of(steps.begin(), steps.end(),
                    [offset](const auto& x) { return x.old_offset == offset; }))
                    return hook_status::unsupported;
            }
        }

        void* trampoline = memory::allocate_rwx_near(target, output_length + 14);
        if (!trampoline) return hook_status::alloc_failed;
        auto owned = std::unique_ptr<void, decltype(&memory::free_rwx)>(trampoline, &memory::free_rwx);
        auto* destination = static_cast<std::uint8_t*>(trampoline);
        const auto relocated_start = reinterpret_cast<std::uintptr_t>(trampoline);

        for (const auto& step : steps) {
            const auto* from = source + step.old_offset;
            auto* to = destination + step.new_offset;
            const auto& info = step.info;
            if (info.is_relative) {
                auto branch_target = step.destination;
                if (branch_target >= source_start && branch_target - source_start < patch_size) {
                    const auto offset = branch_target - source_start;
                    const auto it = std::find_if(steps.begin(), steps.end(),
                        [offset](const auto& x) { return x.old_offset == offset; });
                    branch_target = relocated_start + it->new_offset;
                }
                if (info.branch == asm_stubs::branch_kind::jump) {
                    asm_stubs::write_jmp_abs(to, reinterpret_cast<void*>(branch_target));
                }
                else if (info.branch == asm_stubs::branch_kind::call) {
                    asm_stubs::write_call_abs_safe(to, reinterpret_cast<void*>(branch_target));
                }
                else if (info.branch == asm_stubs::branch_kind::conditional) {
                    to[0] = static_cast<std::uint8_t>(0x70 | (info.condition ^ 1));
                    to[1] = 14;
                    asm_stubs::write_jmp_abs(to + 2, reinterpret_cast<void*>(branch_target));
                }
                else return hook_status::unsupported;
            }
            else {
                std::memcpy(to, from, info.length);
                if (info.is_rip_relative) {
                    std::int32_t old_disp{};
                    std::memcpy(&old_disp, from + info.rip_disp_offset, 4);
                    const auto absolute = static_cast<std::int64_t>(source_start + step.old_offset + info.length) + old_disp;
                    if (absolute >= static_cast<std::int64_t>(source_start) &&
                        absolute < static_cast<std::int64_t>(source_start + patch_size))
                        return hook_status::unsupported;
                    const auto next_new = static_cast<std::int64_t>(relocated_start + step.new_offset + info.length);
                    const auto new_disp = absolute - next_new;
                    if (new_disp < INT32_MIN || new_disp > INT32_MAX) return hook_status::unsupported;
                    const auto rel32 = static_cast<std::int32_t>(new_disp);
                    std::memcpy(to + info.rip_disp_offset, &rel32, 4);
                }
            }
        }
        asm_stubs::write_jmp_abs(destination + output_length, source + patch_size);
        DWORD trampoline_previous{};
        if (!memory::protect(trampoline, output_length + 14, PAGE_EXECUTE_READ, &trampoline_previous))
            return hook_status::protect_failed;
        if (!FlushInstructionCache(GetCurrentProcess(), trampoline, output_length + 14))
            return hook_status::protect_failed;


        try {
            auto record = std::make_unique<inline_entry>();
            record->target = target;
            record->detour = detour;
            record->original = trampoline;
            record->trampoline = trampoline;
            record->patch_size = patch_size;
            record->saved_bytes_dyn.assign(source, source + patch_size);
            inline_hooks_.emplace(target, std::move(record));
            hooks_.push_back({ target, detour, trampoline, patch_size, {}, true });
        }
        catch (...) {
            inline_hooks_.erase(target);
            return hook_status::alloc_failed;
        }

        DWORD previous{};
        if (!memory::protect(target, patch_size, PAGE_EXECUTE_READWRITE, &previous)) {
            inline_hooks_.erase(target);
            hooks_.pop_back();
            return hook_status::protect_failed;
        }

        asm_stubs::write_jmp_abs(target, detour);
        if (patch_size > 14) asm_stubs::write_nop(static_cast<std::uint8_t*>(target) + 14, patch_size - 14);
        const bool flush_ok = FlushInstructionCache(GetCurrentProcess(), target, patch_size) != 0;
        DWORD discarded{};
        const bool protection_ok = memory::protect(target, patch_size, previous, &discarded);
        if (!flush_ok || !protection_ok) {

            DWORD writable{};
            if (memory::protect(target, patch_size, PAGE_EXECUTE_READWRITE, &writable)) {
                const auto& bytes = inline_hooks_.at(target)->saved_bytes_dyn;
                std::memcpy(target, bytes.data(), bytes.size());
                const bool restored_cache = FlushInstructionCache(GetCurrentProcess(), target, patch_size) != 0;
                DWORD ignored{};
                const bool restored_prot = memory::protect(target, patch_size, previous, &ignored);
                if (restored_cache && restored_prot) {
                    inline_hooks_.erase(target);
                    hooks_.pop_back();
                    return hook_status::protect_failed;
                }
            }
            if (original) *original = trampoline;
            (void)owned.release();
            return hook_status::partial;
        }

        if (original) *original = trampoline;
        (void)owned.release();
        SH_LOG_INFO("[inline_hook] installed: target=%p detour=%p trampoline=%p stolen=%zu",
            target, detour, trampoline, patch_size);
        return hook_status::success;
    }

    hook_status inline_hook::uninstall(void* target) {
        const auto it = inline_hooks_.find(target);
        if (it == inline_hooks_.end()) return hook_status::not_hooked;
        auto& record = *it->second;
        DWORD previous{};
        if (!memory::protect(target, record.patch_size, PAGE_EXECUTE_READWRITE, &previous))
            return hook_status::protect_failed;
        std::memcpy(target, record.saved_bytes_dyn.data(), record.saved_bytes_dyn.size());
        const bool flush_ok = FlushInstructionCache(GetCurrentProcess(), target, record.patch_size) != 0;
        DWORD ignored{};
        const bool restored = memory::protect(target, record.patch_size, previous, &ignored);
        if (!flush_ok || !restored) return hook_status::partial;


        memory::free_rwx(record.trampoline);
        inline_hooks_.erase(it);
        const auto h = std::find_if(hooks_.begin(), hooks_.end(),
            [target](const entry& x) { return x.target == target; });
        if (h != hooks_.end()) hooks_.erase(h);
        return hook_status::success;
    }

    hook_status inline_hook::uninstall_all() {
        hook_status result = hook_status::success;
        std::vector<void*> targets;
        targets.reserve(inline_hooks_.size());
        for (const auto& p : inline_hooks_) targets.push_back(p.first);
        for (auto* target : targets)
            if (uninstall(target) != hook_status::success) result = hook_status::partial;
        return result;
    }

    bool inline_hook::is_hooked(void* target) const {
        return inline_hooks_.find(target) != inline_hooks_.end();
    }
} // namespace shadowhook::ring3
