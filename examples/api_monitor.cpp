#include "shadowhook/shadowhook.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <thread>
#include <chrono>
#include <memory>

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

int inline_demo_detour() { return 8; }

int run_inline_demo() {
    sh_init();
    auto& manager = shadowhook::hook_manager::instance();
    auto domain = manager.inline_execution_domain();
    if (!domain) {
        SH_LOG_ERROR("Default inline execution domain is missing");
        return 6;
    }
    using function = int(*)();
    const std::uint8_t code[] = {0xB8,7,0,0,0,
        0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3};
    auto owner = std::unique_ptr<void, decltype(&shadowhook::memory::free_rwx)>(
        shadowhook::memory::allocate_rwx(4096), &shadowhook::memory::free_rwx);
    if (!owner) return 6;
    auto* target = owner.get();
    std::memcpy(target, code, sizeof(code));
    DWORD old{};
    if (!VirtualProtect(target, 4096, PAGE_EXECUTE_READ, &old) ||
        !FlushInstructionCache(GetCurrentProcess(), target, sizeof(code))) return 6;
    const auto fn = reinterpret_cast<function>(target);

    const bool passed = [&] {
        {
            auto executing = shadowhook::enter_inline_execution();
            if (!executing || fn() != 7) return false;
        }
        const auto installed = static_cast<shadowhook::hook_status>(sh_hook(
            shadowhook::hook_type::inline_hook, target,
            reinterpret_cast<void*>(&inline_demo_detour), nullptr));
        SH_LOG_INFO("Default inline install | status=%s", shadowhook::status_str(installed));
        if (installed != shadowhook::hook_status::success) return false;
        auto lease = manager.pin_inline_original(target);
        if (!lease) return false;
        {
            auto executing = shadowhook::enter_inline_execution();
            if (!executing) return false;
            const auto hooked = fn();
            const auto original_value = lease.as<function>()();
            const auto busy = static_cast<shadowhook::hook_status>(sh_unhook(target));
            SH_LOG_INFO("Guarded call | target=%d, original=%d, active=%zu, unhook=%s",
                        hooked, original_value, domain->active_calls(), shadowhook::status_str(busy));
            if (hooked != 8 || original_value != 7 || busy != shadowhook::hook_status::busy) return false;
        }
        const auto removed = static_cast<shadowhook::hook_status>(sh_unhook(target));
        if (removed != shadowhook::hook_status::success || sh_is_hooked(target)) return false;
        {
            auto executing = shadowhook::enter_inline_execution();
            if (!executing) return false;
            const auto restored = fn();
            const auto retained = lease.as<function>()();
            SH_LOG_INFO("After unhook | target=%d, retained original=%d", restored, retained);
            if (restored != 7 || retained != 7 || std::memcmp(target, code, sizeof(code)) != 0) return false;
        }
        return true;
    }();

    const auto shutdown = static_cast<shadowhook::hook_status>(sh_shutdown_checked());
    if (shutdown != shadowhook::hook_status::success || sh_is_hooked(target)) {
        (void)owner.release();
        SH_LOG_ERROR("Inline demo shutdown failed; target allocation retained");
        return 6;
    }
    SH_LOG_INFO("Default inline demo | %s, shutdown=%s", passed ? "PASS" : "FAIL", shadowhook::status_str(shutdown));
    return passed ? 0 : 6;
}
using hotpatch = shadowhook::ring3::hotpatch_hook;
using hotpatch_state = shadowhook::ring3::hotpatch_state;
using native_function = int(*)();
using native_owner = std::unique_ptr<void,decltype(&shadowhook::memory::free_rwx)>;
std::atomic<std::uintptr_t> fault_site{};
std::atomic<bool> fault_restore{},fault_cache{};

BOOL WINAPI native_protect(LPVOID address,SIZE_T size,DWORD protection,PDWORD previous) {
    if(fault_restore.load() && protection==PAGE_EXECUTE_READ) {
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;
    }
    return VirtualProtect(address,size,protection,previous);
}
BOOL WINAPI native_flush(HANDLE process,LPCVOID address,SIZE_T size) {
    const auto point=reinterpret_cast<std::uintptr_t>(address);
    const auto target=fault_site.load();
    if(fault_cache.load() && target && point>=target-5 && point<=target+2) {
        SetLastError(ERROR_ACCESS_DENIED);return FALSE;
    }
    return FlushInstructionCache(process,address,size);
}
native_owner prepared_native_page(std::size_t pages,void*& target,bool cross_page=false) {
    SYSTEM_INFO info{};GetSystemInfo(&info);
    native_owner owner(shadowhook::memory::allocate_rwx(info.dwPageSize*pages),&shadowhook::memory::free_rwx);
    if(!owner) return owner;
    auto* bytes=static_cast<std::uint8_t*>(owner.get());
    auto* entry=bytes+(cross_page ? info.dwPageSize+2 : 16);
    std::memset(entry-5,0xCC,5);
    const std::uint8_t body[]={0x66,0x90,0xB8,7,0,0,0,0xC3};
    std::memcpy(entry,body,sizeof(body));
    DWORD previous{};
    if(!VirtualProtect(bytes,info.dwPageSize*pages,PAGE_EXECUTE_READ,&previous) ||
       !FlushInstructionCache(GetCurrentProcess(),bytes,info.dwPageSize*pages)) return native_owner(nullptr,&shadowhook::memory::free_rwx);
    if(cross_page && !VirtualProtect(bytes+info.dwPageSize,info.dwPageSize,PAGE_EXECUTE_READWRITE,&previous))
        return native_owner(nullptr,&shadowhook::memory::free_rwx);
    target=entry;return owner;
}
DWORD native_rights(void* address) {
    MEMORY_BASIC_INFORMATION value{};
    return VirtualQuery(address,&value,sizeof(value))==sizeof(value) ? value.Protect : 0;
}
int run_hotpatch_demo() {
    sh_init();
    auto& manager=shadowhook::hook_manager::instance();
    void* target{};
    auto owner=prepared_native_page(1,target);
    if(!owner) return 7;
    const auto fn=reinterpret_cast<native_function>(target);
    const auto detour=reinterpret_cast<void*>(&inline_demo_detour);
    bool passed=fn()==7;
    const auto status=static_cast<shadowhook::hook_status>(sh_hook(
        shadowhook::hook_type::hotpatch,target,detour,nullptr));
    passed=passed && status==shadowhook::hook_status::success && fn()==8;
    auto backend=std::dynamic_pointer_cast<hotpatch>(manager.get_backend(shadowhook::hook_type::hotpatch));
    shadowhook::ring3::hotpatch_report report;
    passed=passed && backend && backend->inspect(target,report);
    auto original=passed ? reinterpret_cast<native_function>(report.original) : nullptr;
    passed=passed && original && original()==7;
    auto* relay=report.relay;
    std::array<std::uint8_t,6> body{};
    shadowhook::memory::safe_copy(body.data(),static_cast<std::uint8_t*>(target)+2,6);
    passed=passed && sh_unhook(target)==0 && fn()==7 && original()==7;
    passed=passed && reinterpret_cast<native_function>(static_cast<std::uint8_t*>(target)-5)()==7;
    const auto conflict=static_cast<shadowhook::hook_status>(sh_hook(
        shadowhook::hook_type::inline_hook,target,detour,nullptr));
    passed=passed && conflict==shadowhook::hook_status::already_hooked;
    passed=passed && backend->install(target,detour,nullptr)==shadowhook::hook_status::success;
    shadowhook::ring3::hotpatch_report next;
    passed=passed && backend->inspect(target,next) && next.relay==relay;
    passed=passed && backend->uninstall(target)==shadowhook::hook_status::success;

    std::atomic<bool> stop{},bad_value{};
    std::atomic<unsigned> calls{};
    std::vector<std::thread> workers;
    for(int i=0;i<4;++i) workers.emplace_back([&] {
        while(!stop.load()) {
            const auto value=fn();
            if(value!=7 && value!=8) bad_value=true;
            ++calls;
        }
    });
    std::thread new_threads([&] {
        for(int i=0;i<100 && !stop.load();++i) {
            std::thread fresh([&] {
                for(int n=0;n<1000;++n) {
                    const auto value=fn();
                    if(value!=7 && value!=8) bad_value=true;
                    ++calls;
                }
            });
            fresh.join();
        }
    });
    for(int i=0;i<1000 && passed;++i) {
        passed=backend->install(target,detour,nullptr)==shadowhook::hook_status::success &&
               backend->uninstall(target)==shadowhook::hook_status::success;
    }
    stop=true;
    for(auto& worker:workers) worker.join();
    new_threads.join();
    passed=passed && !bad_value.load() && calls.load()>0 &&
           manager.inline_execution_domain()->active_calls()==0 &&
           std::memcmp(static_cast<std::uint8_t*>(target)+2,body.data(),6)==0 &&
           native_rights(target)==PAGE_EXECUTE_READ;
    SH_LOG_INFO("Native hotpatch | unguarded calls=%u, cycles=1000, original=7, relay reused=%s",
                calls.load(),next.relay==relay ? "yes":"no");
    if(hotpatch::reserves_address(target)) (void)owner.release(); 

    void* unsupported{};
    auto rejected=prepared_native_page(1,unsupported);
    if(!rejected) return 7;
    DWORD old{};
    VirtualProtect(unsupported,8,PAGE_EXECUTE_READWRITE,&old);
    auto* bytes=static_cast<std::uint8_t*>(unsupported);
    bytes[0]=0x90;bytes[1]=0x90; 
    VirtualProtect(unsupported,8,old,&old);
    std::array<std::uint8_t,8> unchanged{};
    shadowhook::memory::safe_copy(unchanged.data(),unsupported,8);
    passed=passed && backend->install(unsupported,detour,nullptr)==shadowhook::hook_status::unsupported &&
           std::memcmp(unsupported,unchanged.data(),8)==0;
    passed=passed && backend->install(bytes+1,detour,nullptr)==shadowhook::hook_status::invalid_address;
    SH_LOG_INFO("Native layout rejection | two NOPs and unaligned entry unchanged");

   
    void* split{};
    auto split_owner=prepared_native_page(2,split,true);
    if(!split_owner) return 7;
    hotpatch faults({&native_protect,&native_flush});
    passed=passed && faults.install(split,detour,nullptr)==shadowhook::hook_status::success;
    passed=passed && native_rights(static_cast<std::uint8_t*>(split)-5)==PAGE_EXECUTE_READ &&
                    native_rights(split)==PAGE_EXECUTE_READWRITE;
    fault_site=reinterpret_cast<std::uintptr_t>(split);
    fault_cache=true;
    passed=passed && faults.uninstall(split)==shadowhook::hook_status::partial;
    fault_cache=false;
    shadowhook::ring3::hotpatch_report failed;
    passed=passed && faults.inspect(split,failed) && failed.state==hotpatch_state::failed &&
                    !failed.entry_enabled && reinterpret_cast<native_function>(split)()==7;
    passed=passed && faults.recover(split)==shadowhook::hook_status::success;
    fault_restore=true;
    passed=passed && faults.install(split,detour,nullptr)==shadowhook::hook_status::partial;
    fault_restore=false;
    passed=passed && faults.recover(split)==shadowhook::hook_status::success &&
                    native_rights(static_cast<std::uint8_t*>(split)-5)==PAGE_EXECUTE_READ;
    passed=passed && faults.install(split,detour,nullptr)==shadowhook::hook_status::success;
    InterlockedExchange16(reinterpret_cast<volatile SHORT*>(split),static_cast<SHORT>(0x9090));
    passed=passed && faults.uninstall(split)==shadowhook::hook_status::partial;
    std::uint16_t foreign{};
    shadowhook::memory::safe_copy(&foreign,split,2);
    passed=passed && foreign==0x9090; 
    InterlockedExchange16(reinterpret_cast<volatile SHORT*>(split),static_cast<SHORT>(0x9066));
    passed=passed && faults.recover(split)==shadowhook::hook_status::success;
    SH_LOG_INFO("Native recovery | cross-page rights, cache/protection faults and foreign entry preserved");
    if(hotpatch::reserves_address(split)) (void)split_owner.release();


    void* transient{};
    auto transient_owner=prepared_native_page(1,transient);
    if(!transient_owner) return 7;
    auto local=std::make_unique<hotpatch>();
    void* raw_original{};
    passed=passed && local->install(transient,detour,&raw_original)==shadowhook::hook_status::success;
    const auto transient_fn=reinterpret_cast<native_function>(transient);
    std::atomic<bool> finish{},bad{};
    std::atomic<unsigned> activity{};
    std::thread active([&]{
        while(!finish.load()) {
            const auto value=transient_fn();
            if(value!=7 && value!=8) bad=true;
            ++activity;
        }
    });
    while(activity.load()<100) std::this_thread::yield();
    local.reset();
    finish=true;active.join();
    passed=passed && !bad.load() && transient_fn()==7 &&
                    reinterpret_cast<native_function>(raw_original)()==7 &&
                    reinterpret_cast<native_function>(static_cast<std::uint8_t*>(transient)-5)()==7;
    if(hotpatch::reserves_address(transient)) (void)transient_owner.release();
 
    native_owner cooperative(shadowhook::memory::allocate_rwx(4096),&shadowhook::memory::free_rwx);
    if(!cooperative) return 7;
    const std::uint8_t old_code[]={0xB8,7,0,0,0,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3};
    std::memcpy(cooperative.get(),old_code,sizeof(old_code));
    DWORD previous{};
    passed=passed && VirtualProtect(cooperative.get(),4096,PAGE_EXECUTE_READ,&previous) &&
                    FlushInstructionCache(GetCurrentProcess(),cooperative.get(),sizeof(old_code));
    passed=passed && sh_hook(shadowhook::hook_type::inline_hook,cooperative.get(),detour,nullptr)==0;
    {
        auto executing=shadowhook::enter_inline_execution();
        passed=passed && executing && reinterpret_cast<native_function>(cooperative.get())()==8;
    }
    passed=passed && sh_unhook(cooperative.get())==0;
    const auto cleanup=sh_shutdown_checked();
    if(cleanup!=0) { (void)cooperative.release();passed=false; }
    shadowhook::log::raw(passed ? shadowhook::log::level::info:shadowhook::log::level::error,
                        passed ? "+":"-","Native hotpatch demo | %s",passed ? "PASS":"FAIL");
    return passed ? 0:7;
}


} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2 && std::strcmp(argv[1], "--inline-demo") == 0) return run_inline_demo();
    if (argc == 2 && std::strcmp(argv[1], "--hotpatch-demo") == 0) return run_hotpatch_demo();
    const bool self_test = argc == 2 && std::strcmp(argv[1], "--self-test") == 0;
    if (argc > 1 && !self_test) {
        SH_LOG_WARN("Usage: api_monitor [--self-test | --inline-demo | --hotpatch-demo]");
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
