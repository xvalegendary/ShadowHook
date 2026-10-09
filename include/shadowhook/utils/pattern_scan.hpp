#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>

namespace shadowhook {

    typedef LONG(WINAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

    typedef struct _RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section;
        PVOID  MappedBase;
        PVOID  ImageBase;
        ULONG  ImageSize;
        ULONG  Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR  FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    struct pattern_result {
        uintptr_t address;
        size_t     size;
        bool       found;
    };

    struct module_info {
        uintptr_t base;
        size_t    size;
        char      name[256];
    };

    class pattern_scanner {
    public:
        static module_info get_module(const char* name);
        static module_info get_kernel_module(const char* name);

        static pattern_result find(uintptr_t base, size_t size,
            const char* pattern, const char* mask);

        static pattern_result find_in_module(const char* module,
            const char* pattern, const char* mask);

        static pattern_result find_in_kernel(const char* module,
            const char* pattern, const char* mask);

        static std::vector<pattern_result> find_all(uintptr_t base, size_t size,
            const char* pattern, const char* mask);

        static uintptr_t resolve_call(uintptr_t call_site);
        static uintptr_t resolve_lea(uintptr_t insn_site);

        static uintptr_t find_ref(uintptr_t base, size_t size,
            uintptr_t target, size_t ref_size = 4);
    };

    class offset_resolver {
    public:
        void add_pattern(const char* name, const char* pattern, const char* mask, int32_t offset = 0);
        uintptr_t resolve(const char* name);
        void resolve_all();
        void dump() const;

    private:
        struct entry {
            std::string name;
            std::string pattern;
            std::string mask;
            int32_t     extra_offset;
            uintptr_t   resolved;
            bool        found;
        };
        std::vector<entry> entries_;
    };

} // namespace shadowhook