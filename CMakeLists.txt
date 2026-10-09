cmake_minimum_required(VERSION 3.16)

project(ShadowHook VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/W4>)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/permissive->)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/WX->)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/GS->)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/Gs9999999>)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
endif()

include_directories(include)

set(SHADOWHOOK_SOURCES
    src/core/hook_base.cpp
    src/core/hook_manager.cpp
    src/core/hook_context.cpp
    src/ring0/ept_hook.cpp
    src/ring0/page_shadow.cpp
    src/ring0/iat_shadow.cpp
    src/ring0/ssdt_shadow.cpp
    src/ring3/vtable_hook.cpp
    src/ring3/exception_hook.cpp
    src/ring3/dll_hollow.cpp
    src/ring3/inline_hook.cpp
    src/utils/pattern_scan.cpp
    src/utils/logger.cpp
    src/utils/memory.cpp
    src/utils/asm_stubs.cpp
    src/shadowhook.cpp
)

if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    
    set(CMAKE_ASM_MASM_FLAGS_INIT "")
    set(CMAKE_ASM_MASM_FLAGS_DEBUG "")
    set(CMAKE_ASM_MASM_FLAGS_RELEASE "")
    
    list(APPEND SHADOWHOOK_SOURCES src/utils/asm_stubs.asm)
    
    set_source_files_properties(src/utils/asm_stubs.asm PROPERTIES
        COMPILE_FLAGS "/nologo"
    )
endif()

add_library(shadowhook STATIC ${SHADOWHOOK_SOURCES})
target_include_directories(shadowhook PUBLIC include)

if(MSVC)
    target_link_libraries(shadowhook PUBLIC psapi)
endif()

add_executable(api_monitor examples/api_monitor.cpp)
target_link_libraries(api_monitor PRIVATE shadowhook)


install(TARGETS shadowhook
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include/shadowhook)