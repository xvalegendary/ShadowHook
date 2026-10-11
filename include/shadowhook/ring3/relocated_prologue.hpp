#pragma once
#include "shadowhook/utils/memory.hpp"
#include <memory>
#include "shadowhook/core/hook_types.hpp"
#include <cstdint>
namespace shadowhook::ring3 {
struct relocated_prologue {
    std::shared_ptr<void> owner;
    void* entry{};
    void* redirect{};
    std::vector<std::uint8_t> saved;
};

hook_status prepare_prologue(void* target, std::size_t minimum, relocated_prologue& out, void* detour=nullptr);
}
