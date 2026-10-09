#pragma once
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <windows.h>

namespace shadowhook::log {

    enum class level : uint8_t {
        info = 0,
        warn = 1,
        error = 2,
        debug = 3,
        verbose = 4
    };

    void set_level(level lv);
    level get_level();

    void raw(level lv, const char* tag, const char* fmt, ...);

#define SH_LOG_INFO(fmt, ...)    ::shadowhook::log::raw(::shadowhook::log::level::info,  "+", fmt, ##__VA_ARGS__)
#define SH_LOG_WARN(fmt, ...)    ::shadowhook::log::raw(::shadowhook::log::level::warn,  "!", fmt, ##__VA_ARGS__)
#define SH_LOG_ERROR(fmt, ...)   ::shadowhook::log::raw(::shadowhook::log::level::error, "-", fmt, ##__VA_ARGS__)
#define SH_LOG_DEBUG(fmt, ...)   ::shadowhook::log::raw(::shadowhook::log::level::debug, "~", fmt, ##__VA_ARGS__)
#define SH_LOG_VERBOSE(fmt, ...) ::shadowhook::log::raw(::shadowhook::log::level::verbose, ">", fmt, ##__VA_ARGS__)

} // namespace shadowhook::log