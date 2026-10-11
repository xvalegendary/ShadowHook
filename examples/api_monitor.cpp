#include "shadowhook/shadowhook.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <thread>
#include <chrono>

namespace {
using message_box = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
message_box original{};
std::atomic<unsigned> detour_calls{};

int WINAPI monitor(HWND window, LPCSTR text, LPCSTR caption, UINT type) {
    ++detour_calls;
    SH_LOG_INFO("MessageBoxA intercepted: '%s'", text ? text : "(null)");
    if (!original) {
        SH_LOG_ERROR("MessageBoxA: original pointer is null");
        return 0;
    }
    return original(window, "Intercepted by ShadowHook!", caption, type);
}


struct dialog_probe {
    std::wstring caption;
    const wchar_t* expected{};
    ULONGLONG deadline{};
    bool text_verified{};
    bool close_posted{};
};
constexpr wchar_t saved_dialog_proc[] = L"ShadowHook.SelfTest.OriginalDialogProc";
constexpr UINT close_test_dialog = WM_APP + 0x17E;

INT_PTR CALLBACK test_dialog_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    const auto previous = reinterpret_cast<WNDPROC>(GetPropW(window, saved_dialog_proc));
    if (message == close_test_dialog) {
        return EndDialog(window, IDOK) ? TRUE : FALSE;
    }
    const auto result = previous ? CallWindowProcW(previous, window, message, wparam, lparam) : FALSE;
    if (message == WM_NCDESTROY) RemovePropW(window, saved_dialog_proc);
    return result;
}

BOOL CALLBACK inspect_child(HWND window, LPARAM parameter) {
    auto& probe = *reinterpret_cast<dialog_probe*>(parameter);
    wchar_t text[512]{};
    const auto length = GetWindowTextW(window, text, static_cast<int>(std::size(text)));
    if (length > 0 &&
        std::wcscmp(text, probe.expected) == 0) {
        probe.text_verified = true;
    }
    return TRUE;
}
BOOL CALLBACK inspect_dialog(HWND window, LPARAM parameter) {
    auto& probe = *reinterpret_cast<dialog_probe*>(parameter);
    DWORD process{};
    GetWindowThreadProcessId(window, &process);
    if (process != GetCurrentProcessId()) return TRUE;
    wchar_t caption[256]{};
    const auto length = GetWindowTextW(window, caption, static_cast<int>(std::size(caption)));
    if (length <= 0 || probe.caption != caption) return TRUE;
    EnumChildWindows(window, inspect_child, parameter);
    if (!probe.close_posted && (probe.text_verified || GetTickCount64() >= probe.deadline)) {
        const auto previous = GetWindowLongPtrW(window, DWLP_DLGPROC);
        if (!previous || !SetPropW(window, saved_dialog_proc, reinterpret_cast<HANDLE>(previous))) return TRUE;
        SetLastError(0);
        const auto replaced = SetWindowLongPtrW(window, DWLP_DLGPROC, reinterpret_cast<LONG_PTR>(&test_dialog_proc));
        if (!replaced && GetLastError() != 0) {
            RemovePropW(window, saved_dialog_proc);
            return TRUE;
        }
        probe.close_posted = PostMessageW(window, close_test_dialog, 0, 0) != 0;
        if (!probe.close_posted) {
            SetWindowLongPtrW(window, DWLP_DLGPROC, previous);
            RemovePropW(window, saved_dialog_proc);
        }
    }
    return TRUE;
}
bool test_dialog(const char* stage, bool intercepted) {
    const auto caption = std::string("ShadowHook IAT test ") + std::to_string(GetCurrentProcessId()) + " " + stage;
    dialog_probe probe{std::wstring(caption.begin(), caption.end()),
                       intercepted ? L"Intercepted by ShadowHook!" : L"Original Text",
                       GetTickCount64() + 10000, false, false};
    std::atomic<bool> finished{};
    std::thread observer([&] {
        while (!finished.load()) {
            EnumWindows(inspect_dialog, reinterpret_cast<LPARAM>(&probe));
            const auto now = GetTickCount64();
            if ((now >= probe.deadline && !probe.close_posted) || now >= probe.deadline + 2000) {
                SH_LOG_ERROR("Self-test: dialog watchdog expired");
                ExitProcess(8);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    const auto result = MessageBoxA(nullptr, "Original Text", caption.c_str(), MB_OK);
    finished.store(true);
    observer.join(); 
    const bool passed = probe.text_verified && probe.close_posted && result == IDOK;
    shadowhook::log::raw(passed ? shadowhook::log::level::info : shadowhook::log::level::error,
                        passed ? "+" : "-",
                        "Self-test %s | text='%s', verified=%s, result=%d, detour calls=%u",
                        stage, intercepted ? "Intercepted by ShadowHook!" : "Original Text",
                        probe.text_verified ? "yes" : "no", result, detour_calls.load());
    return passed;
}

void* slot_value(void** slot) {
    void* value{};
    return shadowhook::memory::safe_copy(&value, slot, sizeof(value)) ? value : nullptr;
}
} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const bool self_test = argc == 2 && std::strcmp(argv[1], "--self-test") == 0;
    if (argc > 1 && !self_test) {
        SH_LOG_WARN("Usage: api_monitor [--self-test]");
        return 1;
    }
    char executable[32768]{};
    const auto length = GetModuleFileNameA(nullptr, executable, static_cast<DWORD>(std::size(executable)));
    if (!length || length >= std::size(executable)) {
        SH_LOG_ERROR("Failed to read executable path");
        return 1;
    }
    SH_LOG_INFO("api_monitor/v2 | MessageBoxA IAT monitor");
    SH_LOG_DEBUG("Executable: %s", executable);
    sh_init();
    const auto module = LoadLibraryW(L"user32.dll");
    if (!module) {
        SH_LOG_ERROR("LoadLibrary(user32) failed | WinAPI error=%lu", GetLastError());
        return 1;
    }
    const auto target = reinterpret_cast<void*>(GetProcAddress(module, "MessageBoxA"));
    const auto slots = shadowhook::ring0::iat_shadow::find_iat_slots(GetModuleHandleW(nullptr), target);
    if (!target || slots.empty()) {
        SH_LOG_ERROR("MessageBoxA import not found in this EXE");
        FreeLibrary(module);
        return 2;
    }
    SH_LOG_DEBUG("IAT | module=main.exe, matches=%zu, slot=%p, before=%p, target=%p",
                slots.size(), static_cast<void*>(slots.front()), slot_value(slots.front()), target);
    if (self_test && (!test_dialog("before-hook", false) || detour_calls.load() != 0)) {
        FreeLibrary(module);
        return 3;
    }

    SH_LOG_STEP("installing MessageBoxA hook...");
    void* raw{};
    const auto status = static_cast<shadowhook::hook_status>(
        sh_hook(shadowhook::hook_type::iat_shadow, target, reinterpret_cast<void*>(&monitor), &raw));
    original = reinterpret_cast<message_box>(raw);
    SH_LOG_DEBUG("install | status=%s, active=%d, original=%p, slot=%p, detour=%p",
                 shadowhook::status_str(status), sh_is_hooked(target), raw,
                 slot_value(slots.front()), reinterpret_cast<void*>(&monitor));
    if (status != shadowhook::hook_status::success || !original || !sh_is_hooked(target)) {
        SH_LOG_ERROR("hook installation failed | status=%s", shadowhook::status_str(status));
        const auto cleanup = sh_shutdown_checked();
        if (cleanup == 0) FreeLibrary(module);
        return 4;
    }
    SH_LOG_INFO("hk installed | backend=IAT, active=1");
    SH_LOG_STEP("calling MessageBoxA...");
    bool observed = slot_value(slots.front()) == reinterpret_cast<void*>(&monitor);
    if (self_test) observed = test_dialog("during-hook", true) && detour_calls.load() == 1 && observed;
    else {
        const auto result = MessageBoxA(nullptr, "Original Text", "ShadowHook IAT monitor", MB_OK);
        observed = result != 0 && detour_calls.load() == 1 && observed;
    }

    SH_LOG_STEP("removing MessageBoxA hk");
    const auto removed = static_cast<shadowhook::hook_status>(sh_unhook(target));
    const bool restored = removed == shadowhook::hook_status::success &&
                          !sh_is_hooked(target) && slot_value(slots.front()) == target;
    if (restored) SH_LOG_INFO("hk removed | active=0, IAT slot restored");
    else SH_LOG_ERROR("hk removal failed | status=%s, active=%d",
                      shadowhook::status_str(removed), sh_is_hooked(target));
    if (self_test && restored)
        observed = test_dialog("after-unhook", false) && detour_calls.load() == 1 && observed;
    const auto shutdown = sh_shutdown_checked();
    if (shutdown == 0) FreeLibrary(module);
    const bool passed = observed && restored && shutdown == 0;
    shadowhook::log::raw(passed ? shadowhook::log::level::info : shadowhook::log::level::error,
                        passed ? "+" : "-", "%s | detour calls=%u, shutdown=%s",
                        passed ? "unhooked" : "failed", detour_calls.load(),
                        shadowhook::status_str(static_cast<shadowhook::hook_status>(shutdown)));
    return passed ? 0 : 5;
}
