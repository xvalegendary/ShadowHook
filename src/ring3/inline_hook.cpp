#include "shadowhook/ring3/inline_hook.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include "shadowhook/utils/logger.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace shadowhook::ring3 {
namespace {
struct instruction {
    std::size_t old_offset{}, new_offset{}, emitted_size{};
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
bool volatile_register(unsigned reg) {
    return reg == 0 || reg == 1 || reg == 2 || (reg >= 8 && reg <= 11);
}

bool leaf_instruction(const std::uint8_t* bytes, const asm_stubs::insn_info& info) {
    if (info.branch == asm_stubs::branch_kind::call) return false;
    if (info.branch != asm_stubs::branch_kind::none) return true;
    std::size_t pos{};
    while (pos < info.length && bytes[pos] == 0x66) ++pos;
    unsigned rex{};
    if (pos < info.length && (bytes[pos] & 0xf0) == 0x40) rex = bytes[pos++];
    if (pos >= info.length) return false;
    const auto op = bytes[pos++];
    if (op == 0x90 || op == 0xC3 || op == 0xCC) return true;
    if (op >= 0xB8 && op <= 0xBF) return volatile_register((op - 0xB8) + ((rex & 1) ? 8 : 0));
    if (op == 0x0F) return pos < info.length && bytes[pos] == 0x1F;
    if (pos >= info.length) return false;
    const auto m = bytes[pos];
    const auto reg = ((m >> 3) & 7) + ((rex & 4) ? 8 : 0);
    const auto rm = (m & 7) + ((rex & 1) ? 8 : 0);
    const bool register_operand = (m >> 6) == 3;
    if (op == 0x8B || op == 0x8D || op == 0x63) return volatile_register(reg);
    if (op == 0x89) return register_operand && volatile_register(rm);
    if (op == 0x85 || op == 0x84 || op == 0x39 || op == 0x3B) return true;
    if (op == 0x31 || op == 0x33 || op == 0x01 || op == 0x03 || op == 0x29 || op == 0x2B)
        return (op & 2) ? volatile_register(reg) : register_operand && volatile_register(rm);
    if (op == 0x81 || op == 0x83)
        return ((m >> 3) & 7) == 7 || (register_operand && volatile_register(rm));
    if (op == 0xC7) return register_operand && volatile_register(rm);
    if (op == 0xFF) return ((m >> 3) & 7) == 4; 
    return false;
}
} // namespace

inline_hook::inline_hook(std::shared_ptr<threading::execution_domain> d, memory::patch_api api)
    : runtime_(std::make_unique<runtime>()) {
    runtime_->domain = std::move(d);
    runtime_->api = api;
    if (!api.protect || !api.flush) throw std::invalid_argument("patch_api requires both functions");
    if (runtime_->domain && !runtime_->domain->bind(runtime_.get()))
        throw std::invalid_argument("execution_domain already owned or faulted");
}
inline_hook::~inline_hook() {
    try {
        if (shutdown() == hook_status::success) {
            if (runtime_->domain) runtime_->domain->unbind(runtime_.get());
            return;
        }
    } catch (...) {}
    auto* retained = runtime_.release();
    try {
        if (retained->domain) retained->domain->close();
        SH_LOG_ERROR("[inline_hook] failed shutdown: entire runtime quarantined");
    } catch (...) {} 
}
hook_status inline_hook::configure_execution(std::shared_ptr<threading::execution_domain> d) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    if (!runtime_->entries.empty() || (runtime_->domain && runtime_->domain != d)) return hook_status::busy;
    if (d && !d->bind(runtime_.get())) return hook_status::busy;
    runtime_->domain = std::move(d);
    return hook_status::success;
}
bool inline_hook::healthy_locked() const {
    for (const auto& kv : runtime_->entries)
        if (kv.second->state == patch_state::failed) return false;
    return true;
}
original_lease inline_hook::pin_original(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto it = runtime_->entries.find(target);
    if (it == runtime_->entries.end() || it->second->state != patch_state::patched) return {};
    return original_lease(it->second->owner, it->second->trampoline);
}
bool inline_hook::inspect(void* target, patch_report& report) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    const auto it = runtime_->entries.find(target);
    if (it == runtime_->entries.end()) return false;
    const auto& e = *it->second;
    report = {e.state, e.patch_installed, e.bytes_known, e.cache_flushed, e.pages};
    return true;
}
std::size_t inline_hook::active_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->entries.size();
}
std::size_t inline_hook::retired_count() const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->retired;
}
bool inline_hook::is_hooked(void* target) const {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    return runtime_->entries.count(target) != 0;
}
hook_status inline_hook::apply(inline_entry& e, bool patched) {
    const auto prior = e.state;
    e.state = patched ? patch_state::prepared : patch_state::restoring;
    if (!memory::make_writable(e.pages, runtime_->api)) {
        const bool restored = memory::restore_pages(e.pages, runtime_->api);
        e.state = restored ? prior : patch_state::failed;
        return restored ? hook_status::protect_failed : hook_status::partial;
    }
    const auto& bytes = patched ? e.patch : e.saved;
    e.bytes_known = false;
    const bool copied = memory::safe_copy(e.target, bytes.data(), bytes.size());
    if (copied) { e.patch_installed = patched; e.bytes_known = true; }
    e.cache_flushed = copied && runtime_->api.flush(GetCurrentProcess(), e.target, bytes.size()) != 0;
    const bool restored = memory::restore_pages(e.pages, runtime_->api);
    if (!copied || !e.cache_flushed || !restored) {
        e.state = patch_state::failed;
        return hook_status::partial;
    }
    e.state = patched ? patch_state::patched : patch_state::prepared;
    return hook_status::success;
}

hook_status inline_hook::install(void* target, void* detour, void** original) try {
    if (original) *original = nullptr;
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto& rt = *runtime_;
    if (!rt.domain) return hook_status::unsupported;
    threading::patch_scope transaction(rt.domain);
    if (!transaction) return hook_status::busy;
    if (!healthy_locked()) return hook_status::partial;
    if (!target || !detour || target == detour) return hook_status::invalid_address;
    if (rt.entries.count(target)) return hook_status::already_hooked;
    if (!memory::is_executable(target)) return hook_status::invalid_address;

    DWORD64 image_base{};
    if (RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(target), &image_base, nullptr))
        return hook_status::unsupported; 
    const auto* source = static_cast<const std::uint8_t*>(target);
    const auto source_start = reinterpret_cast<std::uintptr_t>(target);
    std::vector<instruction> steps;
    std::size_t patch_size = 0, output_length = 0;
    while (patch_size < sizeof(asm_stubs::jmp_abs)) {
        const auto current = source_start + patch_size;
        const auto* addr = source + patch_size;
        std::size_t accessible{};
        while (accessible < 15 && memory::readable_range(addr + accessible, 1)) ++accessible;
        std::array<std::uint8_t, 15> scratch{};
        if (!accessible || !memory::safe_copy(scratch.data(), addr, accessible))
            return hook_status::invalid_address;
        const auto info = asm_stubs::decode(scratch.data(), accessible);
        if (!info.length || !leaf_instruction(scratch.data(), info))
            return hook_status::unsupported;
        DWORD64 instruction_base{};
        if (RtlLookupFunctionEntry(current, &instruction_base, nullptr))
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
            } else if (info.rel_size == 4) {
                std::int32_t value{};
                std::memcpy(&value, addr + info.rel_offset, 4);
                relative = value;
            } else return hook_status::unsupported;
            const auto base_after = static_cast<std::int64_t>(current + info.length);
            item.destination = static_cast<std::uintptr_t>(base_after + relative);
        }
        steps.push_back(item);
        patch_size += info.length;
        output_length += item.emitted_size;
        if (patch_size > 256 || output_length > 2048) return hook_status::unsupported;
    }
    const auto detour_address = reinterpret_cast<std::uintptr_t>(detour);
    if (detour_address >= source_start && detour_address - source_start < patch_size)
        return hook_status::invalid_address;
    for (const auto& kv : rt.entries) {
        const auto existing = reinterpret_cast<std::uintptr_t>(kv.first);
        if (source_start < existing + kv.second->saved.size() && existing < source_start + patch_size)
            return hook_status::already_hooked;
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
            } else if (info.branch == asm_stubs::branch_kind::call) {
                asm_stubs::write_call_abs_safe(to, reinterpret_cast<void*>(branch_target));
            } else if (info.branch == asm_stubs::branch_kind::conditional) {
                to[0] = static_cast<std::uint8_t>(0x70 | (info.condition ^ 1));
                to[1] = 14;
                asm_stubs::write_jmp_abs(to + 2, reinterpret_cast<void*>(branch_target));
            } else return hook_status::unsupported;
        } else {
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

    auto reclaim = std::make_shared<std::atomic<bool>>(true);
    auto* transferred = owned.release();
    std::shared_ptr<void> owner(transferred, [reclaim](void* p) noexcept {
        if (reclaim->load(std::memory_order_relaxed)) memory::free_rwx(p);
    });
    auto record = std::make_unique<inline_entry>();
    record->target = target;
    record->trampoline = trampoline;
    record->owner = owner;
    record->reclaim = reclaim;
    record->saved.resize(patch_size);
    if (!memory::safe_copy(record->saved.data(), target, patch_size) ||
        !memory::capture_pages(target, patch_size, record->pages)) return hook_status::invalid_address;
    record->patch.resize(patch_size, 0x90);
    asm_stubs::write_jmp_abs(record->patch.data(), detour);
    auto& e = *record;
    rt.entries.emplace(target, std::move(record)); 
    const auto result = apply(e, true);
    if (result != hook_status::success) {
        const auto rollback = apply(e, false);
        if (rollback == hook_status::success) {
            rt.entries.erase(target);
            transaction.healthy(healthy_locked());
            return hook_status::protect_failed;
        }
        e.state = patch_state::failed;
        transaction.healthy(false);
        return hook_status::partial;
    }
    if (original) {
        e.raw_published = true;
        reclaim->store(false, std::memory_order_relaxed);
        *original = trampoline; 
    }
    transaction.healthy(healthy_locked());
    return hook_status::success;
}
catch (const std::bad_alloc&) { return hook_status::alloc_failed; }

hook_status inline_hook::uninstall(void* target) {
    std::lock_guard<std::mutex> lock(runtime_->mutex);
    auto& rt = *runtime_;
    const auto it = rt.entries.find(target);
    if (it == rt.entries.end()) return hook_status::not_hooked;
    threading::patch_scope transaction(rt.domain);
    if (!transaction) return hook_status::busy;
    auto& e = *it->second;
    const auto result = apply(e, false);
    if (result != hook_status::success) {
        if (result == hook_status::partial) e.state = patch_state::failed;
        transaction.healthy(healthy_locked());
        return result;
    }
    if (e.raw_published) ++rt.retired;
    rt.entries.erase(it); 
    transaction.healthy(healthy_locked());
    return hook_status::success;
}
hook_status inline_hook::uninstall_all() try {
    std::vector<void*> targets;
    {
        std::lock_guard<std::mutex> lock(runtime_->mutex);
        targets.reserve(runtime_->entries.size());
        for (const auto& p : runtime_->entries) targets.push_back(p.first);
    }
    auto result = hook_status::success;
    for (auto* target : targets) {
        const auto status = uninstall(target);
        if (status != hook_status::success && status != hook_status::not_hooked)
            result = hook_status::partial;
    }
    return result;
}
catch (const std::bad_alloc&) { return hook_status::alloc_failed; }
} // namespace shadowhook::ring3
