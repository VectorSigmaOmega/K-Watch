#include "log.h"
#include <cstdio>
#include <cstring>
#include <chrono>
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

    char ts_buf[32];
    std::tm tm_buf{};
    gmtime_r(&in_time_t, &tm_buf);
    std::strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    std::fprintf(stderr, "%s.%03ldZ %s %s %s\n",
                 ts_buf, (long)ms.count(),
                 level_to_string(l), component, msg.c_str());
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && current_level < Level::Debug) return 0;
    if (level == LIBBPF_INFO && current_level < Level::Info) return 0;

    char buf[1024];
    std::vsnprintf(buf, sizeof(buf), format, args);

    size_t len = std::strlen(buf);
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
