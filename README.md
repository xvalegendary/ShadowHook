<div align="center">

<img src="assets/logo.png" width="650" alt="shadowhook" />

<img src="assets/readme/hero.svg" width="940" alt="shadowhook — windows x64 hooking toolkit" />

<br />

**a custom c++17 hooking toolkit for windows x64**

inline detours · iat redirection · vtable hooks · veh breakpoints · native hotpatching · pe image replacement

<br />

[getting started](#getting-started) · [features](#features) · [usage](#usage) · [api reference](#api-reference) · [documentation](#documentation)

</div>

---

## overview

**shadowhook** is a modular windows x64 hooking library written in modern c++. it provides a consistent interface for intercepting functions, redirecting execution, and managing hook lifecycles — while keeping the low-level implementation in your own codebase.

use it to build debuggers, instrumentation tools, profiling utilities, reverse-engineering workflows, and custom windows internals experiments.

- **multiple hooking strategies** — choose the right backend for your target.
- **custom x64 relocation** — decode and relocate supported instructions into executable trampolines.
- **managed lifecycle** — install, inspect, restore, and query hooks through a central manager.
- **memory-aware patching** — track page protections, flush the instruction cache, and report operation status.
- **built-in logging** — lightweight console output with configurable verbosity.
- **easy integration** — c++17, cmake, msvc, and a static library target.

## features

| backend | what it does | best suited for |
| :-- | :-- | :-- |
| **inline hook** | redirects the function entry through a nearby relay; relocates original instructions to a trampoline | controlled native function interception |
| **iat hook** | swaps imported function pointers in a module's import address table | winapi monitoring inside your application |
| **vtable hook** | replaces a selected virtual method, using a private cloned table or an explicit shared slot | c++ objects and virtual interfaces |
| **veh hook** | uses an `int3` breakpoint and vectored exception dispatch to redirect execution | exception-driven instrumentation |
| **page shadow** | redirects an `int3` breakpoint into an executable shadow dispatch island | alternate breakpoint-based routing |
| **hotpatch** | atomically switches the entry of an explicitly prepared hotpatchable function | native hotpatch sites and live callers |
| **dll image replacement** | loads an owned pe image, replaces it within its reserved address space, and supports restoring a snapshot | controlled image replacement experiments |

`page_shadow` is a user-mode breakpoint/shadow-island backend, not an ept or pte remapper. `dll_hollow` exposes its own image API rather than the generic function-hook call. kernel-only ept/ssdt stubs are separate from the user-mode feature set.

## architecture

<img src="assets/readme/architecture.svg" width="100%" alt="shadowhook architecture" />

```text
application
    |
    v
shadowhook public api
    |
    v
hook_manager  ───────────────  hook_status / logging
    |
    +── inline_hook        +── hotpatch_hook
    +── iat_shadow         +── vtable_hook
    +── exception_veh      +── page_shadow
    +── dll_hollow (owned image api)
    |
    v
memory · x64 decoder · relocation · execution domains
```

Each backend owns its hook records and implements the shared hook interface. The manager handles registration, dispatch, conflict detection, and cleanup.

## getting started

### requirements

- **windows x64**
- **visual studio 2022** with the msvc c++ toolchain, windows sdk, and x64 masm support
- **cmake 3.16+**
- **c++17**

### build

```powershell
git clone https://github.com/xvalegendary/ShadowHook.git
cd ShadowHook

cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

This produces the static `shadowhook` library and the `api_monitor` example.

### run the examples

```powershell
# iat hook: intercept messageboxa in the example executable
.\build\Release\api_monitor.exe

# iat hook: automated messageboxa checks
.\build\Release\api_monitor.exe --self-test

# inline hook: controlled function + original trampoline
.\build\Release\api_monitor.exe --inline-demo

# hotpatch: prepared site, relay, and concurrent calls
.\build\Release\api_monitor.exe --hotpatch-demo
```

### add shadowhook to a cmake project

```cmake
set(SHADOWHOOK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(external/ShadowHook)
target_link_libraries(my_app PRIVATE shadowhook)
```

Include the public entry point with:

```cpp
#include "shadowhook/shadowhook.h"
```

## usage

<img src="assets/readme/lifecycle.svg" width="100%" alt="initialize, install, invoke, unhook, shutdown" />

### 01 / iat hook — intercept `MessageBoxA`

A complete example using the main executable's import address table. Link the application with `user32.lib` (or `user32` in cmake).

```cpp
#include "shadowhook/shadowhook.h"
#include <windows.h>

using message_box_fn = int (WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
static message_box_fn original_message_box = nullptr;

int WINAPI message_box_detour(HWND window, LPCSTR text,
                              LPCSTR caption, UINT flags) {
    SH_LOG_INFO("messageboxa intercepted: %s", text ? text : "(null)");
    return original_message_box(window, "intercepted by shadowhook", caption, flags);
}

int main() {
    sh_init();

    auto* module = GetModuleHandleW(L"user32.dll");
    void* target = module
        ? reinterpret_cast<void*>(GetProcAddress(module, "MessageBoxA"))
        : nullptr;

    void* original = nullptr;
    auto status = static_cast<shadowhook::hook_status>(
        sh_hook(shadowhook::hook_type::iat_shadow,
                target,
                reinterpret_cast<void*>(&message_box_detour),
                &original));

    if (status != shadowhook::hook_status::success || !original) {
        SH_LOG_ERROR("iat hook failed: %s", shadowhook::status_str(status));
        sh_shutdown_checked();
        return 1;
    }

    original_message_box = reinterpret_cast<message_box_fn>(original);
    MessageBoxA(nullptr, "hello, world", "shadowhook", MB_OK);

    const auto removed = static_cast<shadowhook::hook_status>(sh_unhook(target));
    const auto shutdown = static_cast<shadowhook::hook_status>(sh_shutdown_checked());
    return removed == shadowhook::hook_status::success &&
           shutdown == shadowhook::hook_status::success ? 0 : 1;
}
```

The default `iat_shadow` call searches matching imports in the **main executable**. To target another owned module or a specific slot, use `iat_shadow::install_module()` or `iat_shadow::install_slot()`.

### 02 / inline hook — original trampoline

The inline backend installs a relative entry jump to a nearby relay and relocates the displaced instructions. Use `original_lease` to keep the trampoline alive while calling the original function.

```cpp
// target and detour are function addresses with matching signatures.
// the host must coordinate all target/original calls through this domain.

sh_init();

using function_fn = int(*)();
auto& manager = shadowhook::hook_manager::instance();

auto status = static_cast<shadowhook::hook_status>(
    sh_hook(shadowhook::hook_type::inline_hook, target, detour, nullptr));

if (status == shadowhook::hook_status::success) {
    auto original = manager.pin_inline_original(target);

    {
        auto execution = shadowhook::enter_inline_execution();
        if (execution) {
            auto hooked = reinterpret_cast<function_fn>(target)();
            if (original) {
                auto before_hook = original.as<function_fn>()();
                (void)before_hook;
            }
            (void)hooked;
        }
    } // execution has ended before unhook

    sh_unhook(target);
}

sh_shutdown_checked();
```

For inline hooks, the execution domain covers the **entire** call, including calls that bypass the detour. See [`docs/hardening.md`](docs/hardening.md) and [`docs/runtime-backends.md`](docs/runtime-backends.md) for the execution and relocation contracts. The runnable reference is `api_monitor --inline-demo`.

### 03 / vtable hook — one object, one method

Select the exact vtable slot and method count. The default `instance_local` mode clones the table and replaces the chosen object's vfptr without modifying the shared source table.

```cpp
sh_init();

shadowhook::ring3::vtable_options options{};
options.slot = 1;           // selected virtual method
options.method_count = 3;   // actual abi method count
options.prefix_slots = 1;   // msvc rtti; use 0 for com/no-rtti tables
options.mode = shadowhook::ring3::vtable_mode::instance_local;

void* original = nullptr;
auto status = shadowhook::hook_vtable_slot(instance, options, detour, &original);

if (status == shadowhook::hook_status::success) {
    {
        auto execution = shadowhook::enter_vtable_execution();
        if (execution) {
            // invoke the selected virtual method through the object here
        }
    }
    sh_unhook(instance);
}

sh_shutdown_checked();
```

Use `shadowhook::hook_vtable_method()` when you know the unique raw method address instead of the slot. Use `vtable_mode::shared_slot` when the intention is to change the class-wide table. See [`docs/vtable-hooks.md`](docs/vtable-hooks.md) for ABI layout and ownership.

### 04 / veh, page shadow, and hotpatch

These backends use the same lifecycle API:

```cpp
sh_init();

// choose one strategy for the target
const auto kind = shadowhook::hook_type::exception_veh;
// alternatives: page_shadow, hotpatch

void* original = nullptr;
auto status = static_cast<shadowhook::hook_status>(
    sh_hook(kind, target, detour, &original));

if (status == shadowhook::hook_status::success) {
    // call the target and/or its original using the matching function signature
    sh_unhook(target);
}

sh_shutdown_checked();
```

- **veh** places an `int3` at the target and dispatches through a vectored exception handler.
- **page shadow** uses breakpoint dispatch to enter an executable shadow island.
- **hotpatch** expects an explicitly prepared x64 entry (`66 90` plus five reserved bytes before it); see [`docs/hotpatch.md`](docs/hotpatch.md).

### 05 / owned dll image replacement

`dll_hollow` is a dedicated owned-image workflow, not a regular function detour. Load a supported private pe image, replace it with another compatible image, optionally call a snapshot of the original, then restore it.

```cpp
using shadowhook::hook_status;
using shadowhook::ring3::dll_hollow;
using shadowhook::ring3::owned_dll_image;

dll_hollow loader;
owned_dll_image live, previous;

if (loader.load_image(L"original.dll", live, 1024 * 1024) == hook_status::success) {
    if (loader.replace_image(live, L"replacement.dll", &previous) == hook_status::success) {
        {
            auto export_fn = live.pin_export("Value");
            if (export_fn) {
                int result = export_fn.as<int(*)(int)>()(42);
                (void)result;
            }
        } // release export lease before restoration

        loader.restore_image(live);
    }
}
```

This workflow targets **privately owned, compatible native x64 images**. See [`docs/runtime-backends.md`](docs/runtime-backends.md) for the image format and lifetime rules.

## api reference

| api | description |
| :-- | :-- |
| `sh_init()` | initialize shadowhook and register the user-mode backends |
| `sh_hook(type, target, detour, original)` | install a function hook through the selected backend |
| `sh_unhook(target)` | restore a hooked target |
| `sh_unhook_all()` | remove all registered active hooks |
| `sh_is_hooked(target)` | check whether a target is currently tracked |
| `sh_dump_status()` | print active backend counts |
| `sh_set_log_level(level)` | configure console log verbosity (`0`–`4`) |
| `sh_shutdown_checked()` | perform cleanup and return a status |
| `sh_shutdown()` | compatibility cleanup call without a return value |
| `hook_manager::instance().pin_inline_original(target)` | obtain a managed original trampoline lease |
| `shadowhook::enter_inline_execution()` | enter the cooperative inline execution domain |
| `shadowhook::hook_vtable_slot(...)` | install a vtable hook with an explicit layout and slot |
| `shadowhook::hook_vtable_method(...)` | select a vtable method by its raw address |
| `shadowhook::enter_vtable_execution()` | enter the cooperative vtable execution domain |

### status codes

Every `sh_hook()` and `sh_unhook()` call returns a `hook_status` code (as an integer). Convert it with `shadowhook::status_str()` when logging.

```cpp
const auto status = static_cast<shadowhook::hook_status>(sh_unhook(target));
SH_LOG_INFO("unhook status: %s", shadowhook::status_str(status));
```

| status | meaning |
| :-- | :-- |
| `success` | operation completed |
| `already_hooked` / `not_hooked` | target is already registered / is not registered |
| `invalid_address` | target, detour, or memory layout is not valid for the operation |
| `alloc_failed` | required allocation could not be completed |
| `protect_failed` | memory protection operation failed |
| `unsupported` | target or backend does not match the selected implementation |
| `busy` | execution or mutation is currently in progress |
| `partial` | incomplete transaction; recovery may be required |

### logging

```text
[+] hook_manager initialized
[+] registering backend: inline_hook
[+] registering backend: iat_shadow
[~] installing messageboxa hook...
[+] hk installed | backend=iat_shadow
[~] removing messageboxa hook...
[+] hk removed
```

The logger exposes `SH_LOG_INFO`, `SH_LOG_STEP`, `SH_LOG_WARN`, `SH_LOG_ERROR`, `SH_LOG_DEBUG`, and `SH_LOG_VERBOSE`.

## project layout

```text
shadowhook/
├── include/shadowhook/
│   ├── shadowhook.h       public api
│   ├── core/              manager, status types, hook contracts
│   ├── ring3/             inline, vtable, veh, hotpatch, image replacement
│   ├── ring0/             iat, page shadow, and kernel stub declarations
│   └── utils/             memory, decoder, logging, scanning
├── src/                   backend implementations and internals
├── examples/
│   └── api_monitor.cpp    iat, inline, and hotpatch demos
├── docs/                  runtime contracts and detailed guides
└── assets/                shadowhook artwork
```

## documentation

| guide | topic |
| :-- | :-- |
| [`docs/runtime-backends.md`](docs/runtime-backends.md) | inline, veh, page shadow, hotpatch, and owned-image behavior |
| [`docs/vtable-hooks.md`](docs/vtable-hooks.md) | instance-local hooks, shared slots, rtti, and object lifetime |
| [`docs/hotpatch.md`](docs/hotpatch.md) | prepared sites, native patch protocol, and relay ownership |
| [`docs/hardening.md`](docs/hardening.md) | execution domains, trampoline lifetime, rollback, and recovery |
| [`examples/api_monitor.cpp`](examples/api_monitor.cpp) | runnable winapi and native function examples |

## license

shadowhook is released under the [mit license](LICENSE).

<div align="center">

<img src="assets/readme/footer.svg" width="940" alt="shadowhook — research, instrument, understand" />

</div>
