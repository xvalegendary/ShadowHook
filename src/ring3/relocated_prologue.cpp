#include "shadowhook/ring3/relocated_prologue.hpp"
#include "shadowhook/utils/asm_stubs.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <climits>
namespace shadowhook::ring3 {
namespace {
struct instruction {
    std::size_t old_offset{}, new_offset{}, emitted_size{};
    asm_stubs::insn_info info{};
    std::uintptr_t destination{};
};
std::size_t output_size(const asm_stubs::insn_info& info) {
    switch (info.branch) {
    case asm_stubs::branch_kind::jump: return 14;
    case asm_stubs::branch_kind::call: return 16;
    case asm_stubs::branch_kind::conditional: return 16;
    default: return info.length;
    }
}
bool volatile_register(unsigned reg) {
    return reg == 0 || reg == 1 || reg == 2 || (reg >= 8 && reg <= 11);
}

bool leaf_instruction(const std::uint8_t* bytes, const asm_stubs::insn_info& info) {
    if (info.branch == asm_stubs::branch_kind::call) return false;
    if (info.branch != asm_stubs::branch_kind::none) return true;
    std::size_t pos{};
    while(pos<info.length) {
        const auto b=bytes[pos];
        if(b==0x66 || b==0x67 || b==0x64 || b==0x65 || b==0x2E || b==0x36 ||
           b==0x3E || b==0x26 || b==0xF2 || b==0xF3)++pos;
        else break;
    }
    unsigned rex{};
    if (pos < info.length && (bytes[pos] & 0xf0) == 0x40) rex = bytes[pos++];
    if (pos >= info.length) return false;
    const auto op = bytes[pos++];
    if (op == 0x90 || op == 0xC3 || op == 0xCC) return true;
    if (op >= 0xB8 && op <= 0xBF) return volatile_register((op - 0xB8) + ((rex & 1) ? 8 : 0));
    if(op==0x0F) {
        if(pos>=info.length)return false;
        const auto op2=bytes[pos++];
        if(op2==0x1F || (op2==0x1E && pos<info.length && bytes[pos]==0xFA))return true;
        if(pos>=info.length)return false;
        const auto modrm=bytes[pos];
        const auto xmm=((modrm>>3)&7)+((rex&4)?8:0);
        if(op2==0x10 || op2==0x28 || op2==0x6F || op2==0x58 ||
           op2==0x59 || op2==0x5C || op2==0x5E || op2==0x57)
            return xmm<6;
        if(op2==0x11 || op2==0x29 || op2==0x7F)
            return (modrm>>6)!=3 || ((modrm&7)+((rex&1)?8:0))<6;
        return false;
    }
    if (pos >= info.length) return false;
    const auto m = bytes[pos];
    const auto reg = ((m >> 3) & 7) + ((rex & 4) ? 8 : 0);
    const auto rm = (m & 7) + ((rex & 1) ? 8 : 0);
    const bool register_operand = (m >> 6) == 3;
    if (op == 0x8B || op == 0x8D || op == 0x63) return volatile_register(reg);
    if (op == 0x89) return register_operand && volatile_register(rm);
    if (op == 0x85 || op == 0x84 || op == 0x39 || op == 0x3B) return true;
    if (op == 0x31 || op == 0x33 || op == 0x01 || op == 0x03 || op == 0x29 || op == 0x2B)
        return (op & 2) ? volatile_register(reg) : register_operand && volatile_register(rm);
    if (op == 0x81 || op == 0x83)
        return ((m >> 3) & 7) == 7 || (register_operand && volatile_register(rm));
    if (op == 0xC7) return register_operand && volatile_register(rm);
    if (op == 0xFF) return ((m >> 3) & 7) == 4;
    return false;
}
} // namespace


hook_status prepare_prologue(void* target,std::size_t minimum,relocated_prologue& out,void* detour) try {
    out={};
    if(!target || minimum==0 || minimum>64 || !memory::is_executable(target))
        return hook_status::invalid_address;
    const void* controls[]={
        reinterpret_cast<const void*>(&GetCurrentThreadId),
        reinterpret_cast<const void*>(&VirtualProtect),reinterpret_cast<const void*>(&VirtualAlloc),
        reinterpret_cast<const void*>(&VirtualFree),reinterpret_cast<const void*>(&VirtualQuery),
        reinterpret_cast<const void*>(&FlushInstructionCache),
        reinterpret_cast<const void*>(&GetModuleHandleExW),
        reinterpret_cast<const void*>(&AcquireSRWLockExclusive),
        reinterpret_cast<const void*>(&ReleaseSRWLockExclusive),
        reinterpret_cast<const void*>(&AcquireSRWLockShared),
        reinterpret_cast<const void*>(&ReleaseSRWLockShared)
    };
    for(const auto* control:controls)if(target==control)return hook_status::unsupported;
    DWORD64 image_base{};

    const auto* source_function = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(target), &image_base, nullptr);
    std::vector<std::uint8_t> source_unwind;
    if (source_function) {
        if (image_base + source_function->BeginAddress != reinterpret_cast<DWORD64>(target))
            return hook_status::unsupported;
        std::uint8_t header[4]{};
        const auto* unwind = reinterpret_cast<const std::uint8_t*>(image_base + source_function->UnwindData);
        if (!memory::readable_range(unwind,4) || !memory::safe_copy(header,unwind,4))
            return hook_status::invalid_address;
        if (header[0] != 1) return hook_status::unsupported;
        source_unwind.resize(4 + ((header[2]+1u)&~1u)*2u);
        if (!memory::readable_range(unwind,source_unwind.size()) ||
            !memory::safe_copy(source_unwind.data(),unwind,source_unwind.size()))
            return hook_status::invalid_address;
    }

    const auto* source = static_cast<const std::uint8_t*>(target);
    const auto source_start = reinterpret_cast<std::uintptr_t>(target);
    std::vector<instruction> steps;
    std::size_t patch_size = 0, output_length = 0;
    while (patch_size < minimum) {
        const auto current = source_start + patch_size;
        const auto* addr = source + patch_size;
        std::size_t accessible{};
        while (accessible < 15 && memory::readable_range(addr + accessible, 1)) ++accessible;
        std::array<std::uint8_t, 15> scratch{};
        if (!accessible || !memory::safe_copy(scratch.data(), addr, accessible))
            return hook_status::invalid_address;
        const auto info = asm_stubs::decode(scratch.data(), accessible);
        if (!info.length || (!source_function && !leaf_instruction(scratch.data(), info)))
            return hook_status::unsupported;
        if ((info.terminates || info.branch==asm_stubs::branch_kind::jump) &&
            patch_size+info.length<minimum) return hook_status::unsupported;
        DWORD64 instruction_base{};
        const auto* current_function=RtlLookupFunctionEntry(current,&instruction_base,nullptr);
        if ((source_function && current >= image_base+source_function->EndAddress) ||
            (!source_function && current_function)) return hook_status::unsupported;

        instruction item{};
        item.old_offset = patch_size;
        item.new_offset = output_length;
        item.emitted_size = output_size(info);
        item.info = info;
        if (info.is_relative) {
            std::int64_t relative = 0;
            if (info.rel_size == 1) {
                std::int8_t value{};
                std::memcpy(&value, addr + info.rel_offset, 1);
                relative = value;
            } else if (info.rel_size == 4) {
                std::int32_t value{};
                std::memcpy(&value, addr + info.rel_offset, 4);
                relative = value;
            } else return hook_status::unsupported;
            const auto base_after = static_cast<std::int64_t>(current + info.length);
            item.destination = static_cast<std::uintptr_t>(base_after + relative);
        }
        steps.push_back(item);
        patch_size += info.length;
        output_length += item.emitted_size;
        if (patch_size > 256 || output_length > 1024) return hook_status::unsupported;
    }
    for (const auto& step : steps) {
        if (!step.info.is_relative) continue;
        if (step.destination >= source_start && step.destination - source_start < patch_size) {
            const auto offset = step.destination - source_start;
            if (std::none_of(steps.begin(), steps.end(),
                             [offset](const auto& x) { return x.old_offset == offset; }))
                return hook_status::unsupported;
        }
    }

    void* trampoline = memory::allocate_rwx_near(target, 8192);
    if (!trampoline) return hook_status::alloc_failed;
    auto owned = std::unique_ptr<void, decltype(&memory::free_rwx)>(trampoline, &memory::free_rwx);
    auto* destination = static_cast<std::uint8_t*>(trampoline);
    const auto relocated_start = reinterpret_cast<std::uintptr_t>(trampoline);

    for (const auto& step : steps) {
        const auto* from = source + step.old_offset;
        auto* to = destination + step.new_offset;
        const auto& info = step.info;
        if (info.is_relative) {
            auto branch_target = step.destination;
            if (branch_target >= source_start && branch_target - source_start < patch_size) {
                const auto offset = branch_target - source_start;
                const auto it = std::find_if(steps.begin(), steps.end(),
                    [offset](const auto& x) { return x.old_offset == offset; });
                branch_target = relocated_start + it->new_offset;
            }
            if (info.branch == asm_stubs::branch_kind::jump) {
                asm_stubs::write_jmp_abs(to, reinterpret_cast<void*>(branch_target));
            } else if (info.branch == asm_stubs::branch_kind::call) {
                asm_stubs::write_call_abs_safe(to, reinterpret_cast<void*>(branch_target));
            } else if (info.branch == asm_stubs::branch_kind::conditional) {
                to[0] = static_cast<std::uint8_t>(0x70 | (info.condition ^ 1));
                to[1] = 14;
                asm_stubs::write_jmp_abs(to + 2, reinterpret_cast<void*>(branch_target));
            } else return hook_status::unsupported;
        } else {
            std::memcpy(to, from, info.length);
            if (info.is_rip_relative) {
                std::int32_t old_disp{};
                std::memcpy(&old_disp, from + info.rip_disp_offset, 4);
                const auto absolute = static_cast<std::int64_t>(source_start + step.old_offset + info.length) + old_disp;

                if (absolute >= static_cast<std::int64_t>(source_start) &&
                    absolute < static_cast<std::int64_t>(source_start + patch_size))
                    return hook_status::unsupported;
                const auto next_new = static_cast<std::int64_t>(relocated_start + step.new_offset + info.length);
                const auto new_disp = absolute - next_new;
                if (new_disp < INT32_MIN || new_disp > INT32_MAX) return hook_status::unsupported;
                const auto rel32 = static_cast<std::int32_t>(new_disp);
                std::memcpy(to + info.rip_disp_offset, &rel32, 4);
            }
        }
    }
    asm_stubs::write_jmp_abs(destination + output_length, source + patch_size);


    auto* table = reinterpret_cast<RUNTIME_FUNCTION*>(destination+4096);
    if (source_function) {
        std::vector<std::uint8_t> codes;
        bool frame_saved=false;
        const auto map_end=[&](unsigned offset)->unsigned {
            if (offset==0) return 0;
            for (const auto& step:steps)
                if (step.old_offset+step.info.length==offset)
                    return static_cast<unsigned>(step.new_offset+step.emitted_size);
            return UINT_MAX;
        };
        for (unsigned i=0;i<source_unwind[2];) {
            const auto offset=source_unwind[4+i*2];
            const auto descriptor=source_unwind[5+i*2];
            const auto op=descriptor&15, argument=descriptor>>4;
            unsigned slots=1;
            switch(op) {
            case 0: case 2: case 3: break;
            case 1: if(argument>1)return hook_status::unsupported; slots=argument==0?2:3;break;
            case 4: case 8: slots=2;break;
            case 5: case 9: slots=3;break;
            default:return hook_status::unsupported;
            }
            if (i+slots>source_unwind[2])return hook_status::unsupported;
            if (offset<=patch_size) {
                const auto mapped=map_end(offset);
                if(mapped==UINT_MAX || mapped>255)return hook_status::unsupported;
                codes.push_back(static_cast<std::uint8_t>(mapped));
                codes.push_back(descriptor);
                codes.insert(codes.end(),source_unwind.begin()+6+i*2,source_unwind.begin()+4+(i+slots)*2);
                if(op==3)frame_saved=true;
            }
            i+=slots;
        }
        const auto original_prolog=std::min<unsigned>(source_unwind[1],static_cast<unsigned>(patch_size));
        const auto mapped_prolog=map_end(original_prolog);
        if(mapped_prolog==UINT_MAX || mapped_prolog>255)return hook_status::unsupported;
        auto* metadata=destination+4096+sizeof(RUNTIME_FUNCTION);
        metadata[0]=1;metadata[1]=static_cast<std::uint8_t>(mapped_prolog);
        metadata[2]=static_cast<std::uint8_t>(codes.size()/2);
        metadata[3]=frame_saved?source_unwind[3]:0;
        std::memcpy(metadata+4,codes.data(),codes.size());
        table->BeginAddress=0;
        table->EndAddress=static_cast<DWORD>(output_length+14);
        table->UnwindData=4096+sizeof(RUNTIME_FUNCTION);
    }
    if(detour)asm_stubs::write_jmp_abs(destination+2048,detour);
    DWORD previous{};
    if (!memory::protect(trampoline,8192,PAGE_EXECUTE_READ,&previous) ||
        !FlushInstructionCache(GetCurrentProcess(),trampoline,4096))
        return hook_status::protect_failed;
    bool registered=source_function!=nullptr;
    if(registered && !RtlAddFunctionTable(table,1,reinterpret_cast<DWORD64>(trampoline)))
        return hook_status::unsupported;
    auto* transferred=owned.release();
    std::shared_ptr<void> owner(transferred,[table,registered](void* p) noexcept {
        if(registered && !RtlDeleteFunctionTable(table)) return; 
        memory::free_rwx(p);
    });
    out.saved.resize(patch_size);
    if(!memory::safe_copy(out.saved.data(),target,patch_size))return hook_status::invalid_address;
    out.entry=trampoline;out.redirect=destination+2048;out.owner=std::move(owner);
    return hook_status::success;
}
catch(const std::bad_alloc&) {return hook_status::alloc_failed;}
} // namespace shadowhook::ring3
