# Runtime backend contracts

## Inline (Windows x64)

The inline writer now uses a 5-byte rel32 entry jump to a nearby immutable relay.
Original displaced instructions are decoded/relocated into an RX trampoline.
V1 flags=0 unwind codes are filtered and their instruction-end offsets remapped;
RtlAddFunctionTable registers the trampoline. Unsupported VEX/EVEX/opcodes,
handler/CHAININFO/newer unwind formats, mid-function entry and short terminal
functions fail closed. GS/FS loads and common scalar SSE encodings are supported.

**Mutation remains cooperative**: every caller must enter the backend execution
domain for the entire target/detour/original call. This includes indirect callers.
A thread snapshot is not a thread-creation barrier; the interrupted experimental
process_pause implementation was removed rather than presented as all-process safety.
This change does not certify arbitrary unguarded live Windows API patching.
Control/runtime APIs used by the implementation (e.g. VirtualProtect and
GetCurrentThreadId/SRW locks) are rejected rather than recursively hooking the
transaction machinery. Do not call control APIs from DllMain.

Raw originals, trampoline metadata and pinned loaded images are process-lifetime.
Private target/detour code and user data must remain valid while references exist.
Leases retain ownership; unhook does not reclaim executable storage speculatively.
Unknown foreign bytes are preserved and reported partial, with recovery retained.
SEC_IMAGE RW requests canonicalized to WRITECOPY are accepted as writable, while
literal observed protections are retained for per-page recovery.

## exception_veh / page_shadow

INT3 stays installed throughout activation. A process-lifetime, lock-free linked
registry routes ExceptionAddress directly to detour or to an independent original
trampoline. No TF/single-step, temporary byte restoration or global backend pointer.
Unhook routes to original BEFORE restoring the byte; delayed breakpoints still
have valid records. Foreign bytes and failed cache/protection restoration keep
recovery records. The handler returns CONTINUE_SEARCH for unrelated exceptions.

page_shadow creates an RX copy of a readable source page, with an independent
absolute-jump dispatch island at the target offset (allocation allows crossing).
Only the island is executed; copied arbitrary page instructions are NOT assumed
relocatable. This is user-mode breakpoint-to-shadow dispatch, not PTE/EPT remapping.
Breakpoint handlers and executable routes are retained until process exit.
Current retention is per publication; repeated installs consume memory and are not
advertised as a bounded-memory production solution. Callback code/data lifetime
still belongs to the caller. An already-started detour may finish after unhook.

## Native hotpatch

The prepared-site contract in hotpatch.md remains mandatory: one aligned 66 90
entry instruction, five independently reserved padding bytes, immutable function
body and no independent entry into the padding. No unsafe fallback for MessageBoxA.
Tested both private code under unguarded workers and a prepared MEM_IMAGE site.

## Full DLL image replacement

dll_hollow no longer aliases IAT. The old function-shaped sh_hook request returns
unsupported. Use dll_hollow::load_image / replace_image / restore_image.
This replaces HEADERS AND ALL SECTIONS in the SAME owned reservation, resolves
normal imports, applies DIR64 relocations, restores section-specific W^X rights,
flushes instruction cache and registers .pdata. A separately relocated old image
snapshot supplies original exports. Restore puts back the captured image bytes.

This is an exclusively owned private PE image, NOT a loader-listed HMODULE:
- Native AMD64 /NOENTRY DLL; no DllMain/CRT startup or static TLS.
- Delay/bound imports, CLR, load config/CFG metadata, language handlers/chained
  unwind and non-DIR64 relocations fail closed.
- Imported modules/code are pinned to keep snapshots valid.
- pin_export returns a move-only lease holding owner AND execution admission.
  Keep the lease alive throughout the call; do not save its raw pointer afterwards.
- Replacement/restore returns busy while any export lease is held.
- Module state must be statically relocatable: no background threads, escaped
  pointers, runtime-created self-pointers or external resources needing detach.
- The capacity is fixed at load time; a larger replacement is rejected unchanged.
- Code+data/headers are replaced, not the Windows loader's module bookkeeping.
  An arbitrary LoadLibrary/system DLL is NOT accepted as owned input.
- No general claim of substituting any arbitrary DLL or preserving its ABI/state.
- Failure keeps recovery ownership and closes export admission until restore.

Example (for eligible images):
~~~cpp
shadowhook::ring3::dll_hollow backend;
shadowhook::ring3::owned_dll_image module, original;
auto status=backend.load_image(L"original.dll",module,1024*1024);
// Check status before every following operation.
status=backend.replace_image(module,L"replacement.dll",&original);
{
    auto current=module.pin_export("Value");
    auto previous=original.pin_export("Value");
    // Call only if both leases are valid; use the exact exported ABI.
    current.as<int(*)(int)>()(1);
    previous.as<int(*)(int)>()(1);
}
status=backend.restore_image(module);
~~~

CMake still contains NO test targets. Regression probes are independent manual
artifacts in hardening-evidence/runtime-backend-fix, not part of the default build.

Primary contracts:
- https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
