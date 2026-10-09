
#include "shadowhook/shadowhook.h"
#include "shadowhook/utils/logger.hpp"


namespace shadowhook {

    static bool g_initialized = false;

    static constexpr char haha[] = R"ART(




            /                      ##                                    /                             /
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

    static void PrintBanner() {
        printf(haha);
    }

    void initialize() {
        system("cls");
        if (g_initialized)
            return;

        PrintBanner();
        

        SH_LOG_INFO("initializing backends...");

        auto& mgr = hook_manager::instance();

        mgr.register_backend(std::make_unique<ring0::iat_shadow>());
        mgr.register_backend(std::make_unique<ring0::page_shadow>());
        mgr.register_backend(std::make_unique<ring3::vtable_hook>());
        mgr.register_backend(std::make_unique<ring3::exception_hook>());
        mgr.register_backend(std::make_unique<ring3::inline_hook>());
        mgr.register_backend(std::make_unique<ring3::dll_hollow>());
        mgr.register_backend(std::make_unique<ring0::ept_hook>());
        mgr.register_backend(std::make_unique<ring0::ssdt_shadow>());


        g_initialized = true;

        SH_LOG_INFO("[+] ShadowHook ready — %zu backends registered", 7ull);
    }

    void shutdown() {
        if (!g_initialized)
            return;

        SH_LOG_INFO("[~] shutting down ShadowHook...");

        hook_manager::instance().uninstall_all();

        g_initialized = false;

        SH_LOG_INFO("[-] ShadowHook stopped");
    }

} // namespace shadowhook

extern "C" {

    void sh_init(void) {
        shadowhook::initialize();
    }

    void sh_shutdown(void) {
        shadowhook::shutdown();
    }

    int sh_hook(
        shadowhook::hook_type type,
        void* target,
        void* detour,
        void** original
    ) {
        return (int)shadowhook::hook_manager::instance()
            .install(type, target, detour, original);
    }

    int sh_unhook(void* target) {
        return (int)shadowhook::hook_manager::instance().uninstall(target);
    }

    int sh_unhook_all(void) {
        return (int)shadowhook::hook_manager::instance().uninstall_all();
    }

    int sh_is_hooked(void* target) {
        return shadowhook::hook_manager::instance().is_hooked(target) ? 1 : 0;
    }

    void sh_dump_status(void) {
        shadowhook::hook_manager::instance().dump_status();
    }

    void sh_set_log_level(int level) {
        shadowhook::log::set_level(
            (shadowhook::log::level)level
        );
    }

} // extern "C"
