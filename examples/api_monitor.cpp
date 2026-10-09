#include "shadowhook/shadowhook.h"
#include <windows.h>
#include <cstdio>

typedef int (WINAPI* pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

static pMessageBoxA orig_MessageBoxA = nullptr;

int WINAPI hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    SH_LOG_INFO("[monitor] MessageBoxA intercepted: '%s'", lpText);
    return orig_MessageBoxA(hWnd, "Intercepted by ShadowHook!", "ShadowHook", uType);
}

int main() {
    sh_init();
    sh_set_log_level(4);

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    void* pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");

    SH_LOG_INFO("[~] installing inline hook on MessageBoxA...");
    sh_hook(shadowhook::hook_type::inline_hook, pMessageBoxA,
        (void*)hook_MessageBoxA, (void**)&orig_MessageBoxA);

    SH_LOG_INFO("[~] calling MessageBoxA...");
    MessageBoxA(nullptr, "Original Text", "Test", MB_OK);

    SH_LOG_INFO("[~] unhooking...");
    sh_unhook(pMessageBoxA);

    sh_dump_status();
    sh_shutdown();

    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}