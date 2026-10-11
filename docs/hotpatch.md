# Native hotpatch mode (Windows x64, prepared sites only)

## What this changes

The cooperative inline backend remains unchanged. Its 14-byte trampoline patch
still requires every target/original caller to participate in the execution domain.
This backend is **not** automatically selected for arbitrary live Windows API calls.

For unguarded callers, select hook_type::hotpatch explicitly. It uses an existing
hotpatch entry slot rather than overwriting a multi-instruction prologue.
Unsupported sites return unsupported/invalid_address without an instruction patch.
There is no automatic fallback to the cooperative 14-byte writer.

## Required site contract

The owner must establish ALL of the following; byte-pattern matching alone is
not proof that an arbitrary export was prepared for hotpatching:

- Windows x64 executable/readable storage.
- Entry begins with exactly one 2-byte instruction, 66 90 (NOP), at an even address.
  Two separate 90 instructions are rejected: a thread could be between them.
- Five reserved executable bytes immediately precede the entry. Those bytes have
  no independent callers/return addresses; only 90/CC padding is accepted.
- No independent control-flow entry into the middle of the entry slot.
- Runtime unwind coverage must identify the real entry, and not cover the padding.
- The original function body stays immutable and has valid original unwind metadata.
- No other patching engine writes the slot/body. Manager requests overlapping a
  published site's padding/entry/body-entry are rejected, even after unhook.
- The target/detour ABI matches. Privately allocated target and detour code remains
  valid for process lifetime once published; this pointer API does not own it.
- Loaded target/detour images are pinned until process exit. Hot DLL unload/reload is
  deliberately not supported by this process-lifetime mode.
- Invoke control APIs outside DllMain/loader lock.

The supported 66 90 layout is deliberately narrower than all possible outputs of
MSVC /hotpatch and /FUNCTIONPADMIN. Those switches alone do not imply acceptance.
CFG/CET configurations beyond the tested host need independent validation.

## Commit protocol

1. Allocate a nearby relay with immutable code on an RX page and an aligned route
   pointer on a separate RW page. Original is an immutable tail jump to entry+2.
2. While entry is still its original single NOP, prepare E9 rel32 in the reserved
   padding. Preserve/restore protection for EACH touched source page and flush cache.
3. Publish the detour address through InterlockedExchangePointer.
4. Switch entry from 66 90 to EB F9 through aligned InterlockedCompareExchange16.
   Flush source instruction cache and restore original page protections.

No executable multi-byte prologue is memcpy-patched during activation. The initial
five-byte padding write happens only before that padding is reachable. Reinstallation
does not rewrite it. The function body is never relocated or rewritten.

## Unhook, late jumps and ownership

Unhook FIRST routes the relay to untouched entry+2, then atomically restores the
entry NOP. A thread that already decoded the old short jump can still reach padding
or the relay, so **both remain valid and executable for process lifetime**.

The reserved padding is intentionally NOT restored on normal unhook: restoring it
while an old jump is pending would introduce a new race. The original trampoline is
also retained, including after successful backend destruction. Reinstallation within
the same backend reuses the relay; memory grows per distinct site, not per cycle.

Calls overlapping install/uninstall may observe the old or new destination. Unhook
does not drain detours that already started. Module pinning prevents code-unload UAF,
but it does not own arbitrary detour userdata; keep that data valid until host-level
quiescence. The code retains immutable storage instead of assuming RIP sampling proves
reclamation safe.

Process-lifetime ownership reservations survive backend destruction. A different
backend is rejected rather than overwriting a late jump's destination. is_hooked()
reports active/recovery records, not these retired ownership reservations.

## Failure and recovery

prepared / active / retired / failed states are exposed through inspect().
Page records retain original/current/error protection values.
Failed protection/cache restoration retains the site for recover(target).
Activation failures route back to the original body and attempt entry restoration.
A foreign entry value is left intact; the owner resolves that conflict before retry.
Failed destructor shutdown preserves the full recovery runtime.

## API

~~~cpp
sh_init();
void* original{};
auto status = static_cast<shadowhook::hook_status>(
    sh_hook(shadowhook::hook_type::hotpatch, prepared_entry, matching_detour, &original));
if (status == shadowhook::hook_status::success) {
    // These calls require no execution_scope; prepared-site contract applies.
    reinterpret_cast<function_pointer>(prepared_entry)();
    reinterpret_cast<function_pointer>(original)();
    sh_unhook(prepared_entry);
}
~~~

CMake still builds no unit-test targets. Manual example:
api_monitor --hotpatch-demo

That example covers unguarded workers, threads created during switching, 1000
install/uninstall cycles, immutable body/relay reuse, delayed preamble calls, raw
original after backend destruction, cross-page rights, injected cache/protection
failures, foreign entry conflicts, unsupported/unaligned layouts, and an unrelated
cooperative hook in the same process. --inline-demo and --self-test remain available.

## Primary references

- [Microsoft hotpatch entry/padding explanation](https://devblogs.microsoft.com/oldnewthing/20110921-00/?p=9583/)
- [MSVC hotpatch requirements](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image?view=msvc-170)
- [FUNCTIONPADMIN defaults](https://learn.microsoft.com/en-us/cpp/build/reference/functionpadmin-create-hotpatchable-image?view=msvc-170)
- [Aligned 16-bit compare/exchange](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockedcompareexchange16)
- [Module pinning lifetime](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)

