#pragma once
#include <cstdint>
#include <windows.h>

namespace shadowhook::memory {

	bool safe_copy(void* dst, const void* src, size_t size);
	bool protect(void* addr, size_t size, DWORD new_prot, DWORD* old_prot);
	bool is_executable(void* addr);
	void* allocate_rwx(size_t size);
	void* allocate_rwx_near(void* target, size_t size);
	void free_rwx(void* addr);

} // namespace shadowhook::memory	