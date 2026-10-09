#include "shadowhook/utils/logger.hpp"
#include <mutex>

namespace shadowhook::log {

    static level g_level = level::debug;
    static std::mutex g_mutex;

    static HANDLE g_console = nullptr;
    static WORD g_default_attr = 7;

    void init_console() {
        if (g_console) return;
        g_console = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_console) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(g_console, &csbi);
            g_default_attr = csbi.wAttributes;
        }
    }

    void set_level(level lv) { g_level = lv; }
    level get_level() { return g_level; }

    static WORD level_attr(level lv) {
        switch (lv) {
        case level::info:    return 10;  
        case level::warn:    return 14;  
        case level::error:   return 12;  
        case level::debug:   return 11;  
        case level::verbose: return 8;   
        default:             return 7;   
        }
    }

    void raw(level lv, const char* tag, const char* fmt, ...) {
        if (static_cast<uint8_t>(lv) > static_cast<uint8_t>(g_level)) return;

        init_console();
        std::lock_guard<std::mutex> lock(g_mutex);

       
        if (g_console) {
            SetConsoleTextAttribute(g_console, level_attr(lv));
        }
        printf("[%s] ", tag);

      
        if (g_console) {
            SetConsoleTextAttribute(g_console, g_default_attr);
        }

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

        printf("\n");
    }

} // namespace shadowhook::log