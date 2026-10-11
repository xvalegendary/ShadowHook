cmake_minimum_required(VERSION 3.16)
project(ShadowHook VERSION 1.0.0 LANGUAGES C CXX)
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "ShadowHook currently requires MSVC Windows x64")
endif()
enable_language(ASM_MASM)
option(SHADOWHOOK_BUILD_EXAMPLES "Build the API monitor example" ON)
option(SHADOWHOOK_BUILD_KERNEL_STUBS "Assemble separate kernel-only stubs (never link into ring3)" OFF)
set(SHADOWHOOK_SOURCES
    src/core/hook_base.cpp src/core/hook_manager.cpp src/core/hook_context.cpp
    src/ring0/ept_hook.cpp src/ring0/page_shadow.cpp src/ring0/iat_shadow.cpp src/ring0/ssdt_shadow.cpp
    src/ring3/vtable_hook.cpp src/ring3/exception_hook.cpp src/ring3/dll_hollow.cpp src/ring3/inline_hook.cpp
    src/utils/pattern_scan.cpp src/utils/logger.cpp src/utils/memory.cpp
    src/utils/asm_stubs.cpp src/utils/asm_stubs.asm src/utils/thread_quiescence.cpp src/shadowhook.cpp)
add_library(shadowhook STATIC ${SHADOWHOOK_SOURCES})
target_compile_features(shadowhook PUBLIC cxx_std_17)
target_compile_options(shadowhook PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>
                                          $<$<COMPILE_LANGUAGE:CXX>:/permissive->)
target_compile_definitions(shadowhook PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN
                           PRIVATE _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
target_include_directories(shadowhook PUBLIC include)
target_link_libraries(shadowhook PUBLIC psapi)
if(SHADOWHOOK_BUILD_EXAMPLES)
    add_executable(api_monitor examples/api_monitor.cpp)
    target_link_libraries(api_monitor PRIVATE shadowhook user32)
endif()
if(SHADOWHOOK_BUILD_KERNEL_STUBS)
    add_library(shadowhook_kernel_stubs OBJECT src/utils/asm_kernel.asm)
endif()
install(TARGETS shadowhook ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
