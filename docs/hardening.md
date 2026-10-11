# Hardening: lifetime, cooperative transactions and bounded decoding

## Compatibility changes

- sh_init() registers the inline backend with a live, shared **execution domain**.
  Ordinary sh_hook(inline_hook, ...) can install eligible leaf targets immediately.
  Every target/original call must still enter shadowhook::enter_inline_execution();
  unregistered callers and arbitrary process threads are not protected by that domain.
  Directly constructed inline_hook objects can still use configure_execution(domain)
  when explicitly created without a domain.
- get_backend() returns shared_ptr<hook_base>, not a borrowed raw pointer.
- sh_shutdown_checked() returns the actual shutdown status. The old void API remains a shim.
- The API monitor uses atomic IAT exchange instead of patching an uncooperative OS API.
- The process-wide manager intentionally survives static destruction. Explicit shutdown
  still removes hooks; process termination releases its storage.
- Global /GS- and /Gs9999999 were removed. Stack probes and security-cookie defaults
  stay enabled. The old suspended-thread array was especially sensitive to stack depth.

## Why a manager mutex was insufficient

A registry mutex protects data structures, not instruction execution. A sampled RIP
does not tell us about a pending return into stolen instructions. Suspending a peer
holding a heap/loader lock can also deadlock the patcher.

An execution_scope increments admission's active-call count BEFORE entering target
code and decrements AFTER the entire target/detour/original call returns or unwinds.
The patcher atomically closes admission only when that count is zero. Thus there are
neither instruction fetches nor pending returns in the patch footprint at commit.
A non-quiescent operation returns busy without altering bytes. Arrivals during a
transaction wait outside target code; failure closes admission until recovery.

This guarantee is conditional on a real host integration:
1. Every call path, callback and new thread enters the SAME domain before executing
   the target or an original trampoline. Guarding only inside the detour is too late.
2. The domain belongs to one backend runtime; binding a second runtime is rejected.
3. The patch footprint has no independent interior entry points, and belongs to the
   selected function/stub. No other writer patches or reprotects these pages.
4. The target and detour modules/allocations remain alive through all calls, leases
   and legacy originals. A lease owns trampoline storage, NOT the target module.
5. Avoid patching under loader lock or from DllMain. Never destroy an active backend
   or unload a detour module before checked shutdown and application quiescence.

This is cooperative patching, not general-purpose transparent hot patching of arbitrary
third-party threads. A simple mutex around install/uninstall would not establish any
of the execution guarantees above.

## Migration example

~~~cpp
sh_init();
auto& manager = shadowhook::hook_manager::instance();
auto domain = manager.inline_execution_domain(); // SAME domain bound to the backend
if (!domain) return;

// Omit raw original output; obtain leases instead.
auto status = static_cast<shadowhook::hook_status>(
    sh_hook(shadowhook::hook_type::inline_hook, target, detour, nullptr));
if (status != shadowhook::hook_status::success)
    return;

{
    auto executing = shadowhook::enter_inline_execution(); // BEFORE target entry; hold through full return
    if (!executing) return;           // recovery required, no execution admitted
    reinterpret_cast<function_pointer>(target)();
}

// Inside a detour already covered by its caller's execution_scope:
auto original = manager.pin_inline_original(target);
if (original) original.as<function_pointer>()(); // keep the lease through return

// Or for an independently retained original:
auto retained_original = manager.pin_inline_original(target);
auto removed = static_cast<shadowhook::hook_status>(sh_unhook(target));
if (removed == shadowhook::hook_status::success && retained_original) {
    auto executing = shadowhook::enter_inline_execution();
    if (executing) retained_original.as<function_pointer>()();
}
retained_original = {}; // final lease release reclaims executable storage
~~~

A raw original pointer has no observable last use. Its trampoline is therefore
retained for process lifetime, including after backend destruction. This intentionally
costs executable memory per legacy installation. Never cache a pointer from a lease
past that lease's lifetime; use the lease API for deterministic reclamation.

Keep a shared backend handle throughout operations. It pins the backend object;
an execution scope pins the domain, and an original lease pins the trampoline.

## Transaction and recovery model

prepared -> patched -> restoring -> prepared (registration removed)
Any unresolved byte/cache/protection failure -> failed (registration retained).

Preparation completes allocations, decoding, relocation and per-page protection
capture before modifying target bytes. Each page has its own original/current/error
record. Trampoline pages transition RW -> RX; source pages become writable only for
the transaction and return to their individually captured rights.

Installation failures attempt restoration of original bytes, instruction cache and
all original page rights. A fully completed rollback returns protect_failed and
removes the registration. An incomplete rollback returns partial, retains the whole
record, and closes the domain. Unhook uses the same restoration path.

inspect(target, report) exposes patch state, whether bytes are known, whether the
detour bytes remain installed, cache completion and original/current rights of each
page. A failed copy marks byte identity unknown instead of guessing its result.
recover(target) retries restoration from the retained ORIGINAL rights. A successful
retry reopens admission after the failed registration has been removed.

Call shutdown() or sh_shutdown_checked(), inspect failures, recover and retry BEFORE
destroying wrappers. On destructor failure the complete runtime, owners, records and
closed domain are quarantined for process lifetime. This last-resort retention is
not a successful shutdown and supplies no post-destruction recovery handle.

## Unwind and relocation boundary

This implementation intentionally rejects targets covered by RUNTIME_FUNCTION and
rejects stolen instructions that change RSP/nonvolatile registers, perform calls,
or have unsupported semantics. It accepts only the auditable leaf subset in
leaf_instruction(). Those trampoline instructions preserve a leaf frame, so no
invented unwind table is installed.

Known length does NOT imply safe relocation. The decoder includes a first VEX
milestone (map 0F vector moves and VZEROUPPER/VZEROALL), but the inline relocator
still rejects vector prologues. EVEX, additional VEX maps, LOOP and unknown groups
remain fail-closed. A future non-leaf implementation needs regenerated unwind
codes, handler/chain validation and exception tests before enabling such prologues.
Full CET/CFG configuration coverage and kernel runtime integration are separate
validation tasks; these tests establish behavior on the current Windows x64 host.

Relocation tests cover local JMP/Jcc destinations, external JMP, RIP operands,
invalid interior destinations and cross-page instruction boundaries. Expanded
CALL bytes are tested as an emitter; stolen CALLs are rejected by unwind policy.

## Memory, IAT, assembly and logging

PE parsing first obtains the allocation extent, copies bounded DOS/NT/file/optional
headers, validates SizeOfOptionalHeader and SizeOfImage, then reads bounded RVA
objects and strings. No unchecked typed pointer dereference occurs in the parser.

IAT install_module() selects an image and all matching resolved slots (or the first
when explicitly requested); install_slot() validates a specific slot against that
image's import table. Each aligned slot uses compare/exchange. A competing writer
is left intact and restoration records remain retryable. Keep module and detour
lifetimes valid: atomic pointer exchange does not drain in-flight detour calls.

The scanner joins adjacent readable committed regions, skips guard/noaccess/reserved
regions, and preserves matches across readable protection boundaries. SEH handles
a mapping fault during comparison. Results are best-effort observations, not a
consistent snapshot of concurrently changing mappings.

asm_stubs.asm contains user-mode instructions only. CPUID retains the 64-bit output
pointer in R8 and preserves RBX with MASM unwind annotations. CPUID_EX accepts a
subleaf. Privileged CR/MSR/CLI/STI/DR routines are in asm_kernel.asm, which is assembled
only by an explicit option and never linked into the ring3 library. Interrupt
disable returns flags in RAX; restoration controls IF without writing below RSP.

Logger level is atomic with relaxed ordering (no unrelated data is published).
Console discovery, state and output share one mutex. Invalid/redirected console
handles and failed console API calls disable colors instead of using uninitialized
attributes.

## Build and manual examples

CMake builds the library and optional examples only. CTest, enable_testing(),
add_test(), and all test/probe executable targets have been removed. Files in
tests/ are retained as historical research sources but are not compiled.
tools/verify.ps1 performs a clean Debug/Release build, without building or running tests.

The existing example supports manual validation:
- api_monitor --inline-demo: normal sh_init/sh_hook API with the default domain;
  target returns 7 -> 8 -> 7, original lease returns 7, guarded unhook reports busy.
- api_monitor --self-test: actual MessageBoxA IAT routing with automated dialog checks.

Domain presence fixes initialization compatibility; it does not relax the decoder,
unwind, module-lifetime or caller-enrollment contracts. Eligible leaf functions and
host-integrated guards remain required. Register a custom inline_hook(custom_domain)
before sh_init() if you need a host-owned domain; registered backends are not replaced.
The registry/domain getter releases manager/backend locks before waiting for
execution admission so detours can obtain original leases without lock inversion.

## Reference contracts

- [VirtualProtect: old protection describes the first page](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [SuspendThread: debugger use and deadlock caveat](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
- [Windows x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)
- [x64 unwind information](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [RtlLookupFunctionEntry](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry)
- [Intel architecture manuals and instruction reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)


## Prepared native hotpatch sites

For unguarded callers, hook_type::hotpatch supplies a separate native slot-switching path. It accepts only the prepared 66 90 entry/padding contract and has no unsafe fallback. Cooperative inline semantics are unchanged. See [native mode, lifetime and recovery](hotpatch.md).
## Runtime backend update
See [runtime-backends.md](runtime-backends.md) for the current relocation/unwind,
breakpoint lifetime and full owned-image replacement contracts. Old statements
that all unwind-covered prologues are rejected or that dll_hollow aliases IAT
are superseded by that document. Native hotpatch remains prepared-site only.
