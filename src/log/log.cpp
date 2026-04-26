#include "log.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <bpf/libbpf.h>

namespace kwlog {

static Level current_level = Level::Info;

void set_level(Level l) {
    current_level = l;
}

Level get_level() {
    return current_level;
}

static const char* level_to_string(Level l) {
    switch (l) {
        case Level::Error: return "ERROR";
        case Level::Warn:  return "WARN ";
        case Level::Info:  return "INFO ";
        case Level::Debug: return "DEBUG";
        case Level::Trace: return "TRACE";
        default:           return "UNKNOWN";
    }
}

void emit(Level l, const char* component, const std::string& msg) {
    if (l > current_level) return;

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::cerr << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%S")
              << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z'
              << " " << level_to_string(l)
              << " " << component
              << " " << msg
              << "\n";
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && current_level < Level::Debug) return 0;
    if (level == LIBBPF_INFO && current_level < Level::Info) return 0;
    
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    
    // Remove trailing newline as our emit adds one
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    Level l = Level::Info;
    if (level == LIBBPF_WARN) l = Level::Warn;
    if (level == LIBBPF_DEBUG) l = Level::Debug;

    emit(l, "libbpf", buf);
    return 0;
}

void init_libbpf_logging() {
    libbpf_set_print(libbpf_print_fn);
}

} // namespace kwlog
