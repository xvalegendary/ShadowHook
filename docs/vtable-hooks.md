# Vtable hooks: explicit layout and ownership (MSVC Windows x64)

## New API: instance-local by default
Supply the exact ABI method count and slot. Readable memory is not proof of a
vtable's semantic length; the backend never searches an arbitrary 1024 entries.

    sh_init();
    void* original{};
    shadowhook::ring3::vtable_options options;
    options.slot=1;                 // select method, not implicit slot 0
    options.method_count=3;         // exact count from your interface/ABI
    options.prefix_slots=1;         // MSVC RTTI COL; COM/no RTTI uses 0
    auto status=shadowhook::hook_vtable_slot(instance,options,detour,&original);
    {
        auto executing=shadowhook::enter_vtable_execution();
        // Check status and execution admission, then invoke the virtual method.
        // Keep this scope through detour/original execution.
    }
    sh_unhook(instance);

The source table is never changed in instance_local mode. The backend creates a
read-only clone including the explicitly specified metadata prefix, replaces the
selected slot in that private copy, and publishes the clone through ONLY the chosen
subobject's aligned vfptr. Unhook restores that vfptr, not the class's shared table.

hook_vtable_method(instance,method,options,detour,&original) performs a bounded
lookup within method_count. Zero matches -> not_hooked. Multiple identical method
addresses (e.g. ICF/aliases) -> unsupported: use an explicit slot to disambiguate.

## Shared mode is separate and explicit
Set options.mode=shadowhook::ring3::vtable_mode::shared_slot to patch an original
class table slot. All objects using that table are affected intentionally.
Duplicate same-slot ownership and mixed local/shared ownership of one table are
rejected. The old sh_hook(hook_type::vtable,...) remains shared slot 0 for source/API
compatibility, emits a warning, and is not presented as instance-local hooking.
Use the new API for explicit bounds, arbitrary slot selection and local ownership.

## Lifetime and ABI contract
- Only Windows x64 MSVC-style vfptr/table layout is handled, not portable C++.
- Pass the adjusted polymorphic base/subobject pointer whose FIRST field is the
  selected vfptr. Multiple-inheritance subobjects may be at nonzero offset.
- Supply the exact method count including ABI-generated destructor/thunk slots.
  A C++ virtual destructor can change slot numbering. No count is inferred.
- Prefix slots (default one for MSVC RTTI, zero for COM/raw/no-RTTI) are caller-owned
  ABI metadata. Do not infer a prefix for an arbitrary interface.
- Object, original table/metadata and private code/data remain alive through
  uninstall and completion of calls. Uninstall BEFORE destruction/free; never
  patch concurrently with constructors, destructors, object copying or vfptr writers.
- Every potentially affected call uses the backend's execution domain. Shared mode
  includes calls on every affected instance, not only the install target.
- Controller returns busy rather than mutating under an active execution scope.
  Interlocked CAS prevents torn/foreign overwrites; it does not make unguarded
  C++ virtual dispatch a portable data-race-free operation.
- Detour/original must match the real Windows x64 ABI, including adjusted this.
- Compiler-devirtualized/direct calls bypass the vtable and thus bypass this hook.
- One installation per vfptr address per backend. For multiple selected slots on
  one object a multi-slot API is not supplied in this change.
- Loaded code/table images are pinned; published clones remain immutable and
  retained until process exit to protect delayed vfptr loads. Memory grows per install.
- Instance-local hook changes the object's vfptr: do not promise bitwise object
  identity or compatibility with all third-party tooling/layout assumptions.

## Failure and shutdown
prepared / installed / restoring / failed reports include published state and
original/current/error page rights. Every protect/restore result is checked.
Foreign vfptr/slot values are preserved; partial rollback closes execution admission
and retains recovery records. recover(instance) retries restore. Failed destruction
retains the complete runtime rather than freeing installed clone/protection state.
Returning to a known original value can be recovered without reinstalling the hook.

## Validation
Independent manual probe (no CMake test targets):
slot 1, method lookup at slot 2, two instances, untouched source table, original,
RTTI/dynamic_cast, read-only clone, shared mode, alias rejection, invalid count/
alignment/null entry, guarded page boundary, COM/no-RTTI prefix 0, failed protection,
foreign writer recovery, 4 cooperative workers, delayed clone lookup, secondary
multiple-inheritance subobject and manager shutdown.

References:
- [Windows interlocked access](https://learn.microsoft.com/en-us/windows/win32/sync/interlocked-variable-access)
- [MSVC devirtualization](https://devblogs.microsoft.com/cppblog/the-performance-benefits-of-final-classes/)
The method-lookup parameter is a raw code address from a table slot, not a C++
pointer-to-member. Member pointers can encode this adjustment and are not blindly
converted into function addresses.
