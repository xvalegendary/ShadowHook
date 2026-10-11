#pragma once
#include <cstddef>
#include <vector>
#include <windows.h>
namespace shadowhook::memory {
struct patch_api {
    decltype(&VirtualProtect) protect{&VirtualProtect};
    decltype(&FlushInstructionCache) flush{&FlushInstructionCache};
};
struct page_protection {
    void* address{};
    std::size_t size{};
    DWORD original{};
    DWORD current{};
    DWORD error{};
};
bool safe_copy(void* dst, const void* src, std::size_t size);
bool readable_range(const void* addr, std::size_t size);
bool capture_pages(void* addr, std::size_t size, std::vector<page_protection>& pages);
bool make_writable(std::vector<page_protection>& pages, const patch_api& api);
bool restore_pages(std::vector<page_protection>& pages, const patch_api& api);
bool protect(void* addr, std::size_t size, DWORD new_prot, DWORD* old_prot);
bool is_executable(void* addr);
void* allocate_rwx(std::size_t size);
void* allocate_rwx_near(void* target, std::size_t size);
void free_rwx(void* addr);
} // namespace shadowhook::memory
