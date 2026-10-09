#pragma once

#include "shadowhook/core/hook_types.hpp"
#include "shadowhook/core/hook_manager.hpp"
#include "shadowhook/core/hook_base.hpp"

#include "shadowhook/ring0/page_shadow.hpp"
#include "shadowhook/ring0/iat_shadow.hpp"
#include "shadowhook/ring3/vtable_hook.hpp"
#include "shadowhook/ring3/exception_hook.hpp"
#include "shadowhook/ring3/inline_hook.hpp"

#include "shadowhook/ring3/dll_hollow.hpp"
#include "shadowhook/ring0/ept_hook.hpp"
#include "shadowhook/ring0/ssdt_shadow.hpp"
#include "shadowhook/core/hook_context.hpp"
#include "shadowhook/utils/memory.hpp"	

#include "shadowhook/utils/logger.hpp"
#include "shadowhook/utils/pattern_scan.hpp"
#include "shadowhook/utils/asm_stubs.hpp"

#ifdef __cplusplus
extern "C" {
#endif

	void sh_init(void);
	void sh_shutdown(void);

	int  sh_hook(shadowhook::hook_type type, void* target, void* detour, void** original);
	int  sh_unhook(void* target);
	int  sh_unhook_all(void);
	int  sh_is_hooked(void* target);
	void sh_dump_status(void);

	void sh_set_log_level(int level);

#ifdef __cplusplus
}
#endif