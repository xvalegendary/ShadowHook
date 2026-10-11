#include "shadowhook/utils/logger.hpp"
#include <atomic>
#include <cstring>
#include <mutex>

namespace shadowhook::log {
namespace {
std::atomic<level> g_level{level::info};
std::mutex g_mutex;
HANDLE g_console{};
bool g_console_initialized{};

void init_console() {
    if (g_console_initialized) return;
    g_console_initialized = true;
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!g_console || g_console == INVALID_HANDLE_VALUE ||
        !GetConsoleScreenBufferInfo(g_console, &info)) g_console = nullptr;
}
bool enabled(level message, level verbosity) noexcept {

    if (message == level::debug || message == level::verbose)
        return static_cast<unsigned>(message) <= static_cast<unsigned>(verbosity);
    return true;
}
char marker_for(level message, const char* tag) noexcept {
    if (message == level::error) return '-';
    if (message != level::info || std::strcmp(tag, "~") == 0) return '~';
    return '+';
}
WORD foreground_for(char marker) noexcept {
    if (marker == '+') return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    if (marker == '-') return FOREGROUND_RED | FOREGROUND_INTENSITY;
    return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
}
bool is_marker(const char* tag) noexcept {
    return std::strcmp(tag, "+") == 0 || std::strcmp(tag, "-") == 0 ||
           std::strcmp(tag, "~") == 0 || std::strcmp(tag, "!") == 0 ||
           std::strcmp(tag, ">") == 0;
}
} // namespace

void set_level(level value) { g_level.store(value, std::memory_order_relaxed); }
level get_level() { return g_level.load(std::memory_order_relaxed); }

void raw(level message, const char* tag, const char* format, ...) {
    if (!tag || !format || !enabled(message, get_level())) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    init_console();
    const auto marker = marker_for(message, tag);
    CONSOLE_SCREEN_BUFFER_INFO previous{};
    bool colored = false;
    if (g_console) {
        if (GetConsoleScreenBufferInfo(g_console, &previous)) {
            constexpr WORD background_mask = BACKGROUND_RED | BACKGROUND_GREEN |
                                              BACKGROUND_BLUE | BACKGROUND_INTENSITY;
            colored = SetConsoleTextAttribute(g_console,
                (previous.wAttributes & background_mask) | foreground_for(marker)) != 0;
        }
        if (!colored) g_console = nullptr;
    }

    std::printf("[%c] ", marker);
    if (!is_marker(tag)) std::printf("%s: ", tag);
    va_list arguments;
    va_start(arguments, format);
    std::vprintf(format, arguments);
    va_end(arguments);
    std::putchar('\n');
    std::fflush(stdout);
    if (colored && !SetConsoleTextAttribute(g_console, previous.wAttributes)) g_console = nullptr;
}
} // namespace shadowhook::log

