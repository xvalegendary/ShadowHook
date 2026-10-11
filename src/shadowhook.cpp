#include "shadowhook/shadowhook.h"
#include "shadowhook/utils/logger.hpp"
#include <mutex>
#ifndef SHADOWHOOK_EXPERIMENTAL
#define SHADOWHOOK_EXPERIMENTAL 1
#endif
namespace shadowhook {

    static constexpr char haha[] = R"ART(




            /                        ##                                  /                             /
           #/                        ##                                 #/                            #/
           ##                        ##                                 ##                            ##
           ##                        ##          ##                     ##                            ##
           ##                        ##          ##                     ##                            ##
   /###    ##  /##      /###     ### ##    /###   ##    ###    ####     ##  /##      /###     /###    ##  /##
  / #### / ## / ###    / ###  / ######### / ###  / ##    ###     ###  / ## / ###    / ###  / / ###  / ## / ###
 ##  ###/  ##/   ###  /   ###/ ##   #### /   ###/  ##     ###     ###/  ##/   ###  /   ###/ /   ###/  ##/   /
####       ##     ## ##    ##  ##    ## ##    ##   ##      ##      ##   ##     ## ##    ## ##    ##   ##   /
  ###      ##     ## ##    ##  ##    ## ##    ##   ##      ##      ##   ##     ## ##    ## ##    ##   ##  /
    ###    ##     ## ##    ##  ##    ## ##    ##   ##      ##      ##   ##     ## ##    ## ##    ##   ## ##
      ###  ##     ## ##    ##  ##    ## ##    ##   ##      ##      ##   ##     ## ##    ## ##    ##   ######
 /###  ##  ##     ## ##    /#  ##    /# ##    ##   ##      /#      /    ##     ## ##    ## ##    ##   ##  ###
/ #### /   ##     ##  ####/ ##  ####/    ######     ######/ ######/     ##     ##  ######   ######    ##   ### /
   ###/     ##    ##   ###   ##  ###      ####       #####   #####       ##    ##   ####     ####      ##   ##/
                  /                                                            /
                 /                                                            /
                /                                                            /
               /                                                            /
)ART";



    namespace {
        std::mutex lifecycle_mutex;
        bool initialized = false;
    }
    static void PrintBanner() {
        printf("%s", haha);
    }
    void initialize() {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);
        if (initialized) return;
        PrintBanner();
        auto& mgr = hook_manager::instance();
        mgr.register_backend(std::make_unique<ring3::inline_hook>(
            std::make_shared<threading::execution_domain>()));
        mgr.register_backend(std::make_unique<ring0::iat_shadow>());
#if SHADOWHOOK_EXPERIMENTAL
        mgr.register_backend(std::make_unique<ring3::vtable_hook>());
        mgr.register_backend(std::make_unique<ring3::exception_hook>());
        mgr.register_backend(std::make_unique<ring0::page_shadow>());
        mgr.register_backend(std::make_unique<ring3::dll_hollow>());
        mgr.register_backend(std::make_unique<ring0::ept_hook>());
        mgr.register_backend(std::make_unique<ring0::ssdt_shadow>());
#endif
        initialized = true;

#if SHADOWHOOK_EXPERIMENTAL
        SH_LOG_INFO("shadowhook initialized (experimental backends enabled)");
#else
        SH_LOG_INFO("shadowhook initialized (experimental backends disabled)");
#endif
    }
    hook_status shutdown_checked() {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);
        const auto status = hook_manager::instance().uninstall_all();
        if (status != hook_status::success) {
            SH_LOG_ERROR("shutdown: failed to remove every hook; library remains initialized");
            return status;
        }
        initialized = false;
        return hook_status::success;
    }
    void shutdown() { (void)shutdown_checked(); }
} // namespace shadowhook

extern "C" {
    void sh_init(void) { shadowhook::initialize(); }
    void sh_shutdown(void) { shadowhook::shutdown(); }
    int sh_shutdown_checked(void) { return static_cast<int>(shadowhook::shutdown_checked()); }
    int sh_hook(shadowhook::hook_type type, void* target, void* detour, void** original) {
        return static_cast<int>(shadowhook::hook_manager::instance().install(type, target, detour, original));
    }
    int sh_unhook(void* target) { return static_cast<int>(shadowhook::hook_manager::instance().uninstall(target)); }
    int sh_unhook_all(void) { return static_cast<int>(shadowhook::hook_manager::instance().uninstall_all()); }
    int sh_is_hooked(void* target) { return shadowhook::hook_manager::instance().is_hooked(target) ? 1 : 0; }
    void sh_dump_status(void) { shadowhook::hook_manager::instance().dump_status(); }
    void sh_set_log_level(int level) {
        if (level >= 0 && level <= 4) shadowhook::log::set_level(static_cast<shadowhook::log::level>(level));
    }
}
