#pragma once
#include <string>

namespace kwlog {

enum class Level { Error, Warn, Info, Debug, Trace };

void set_level(Level l);
Level get_level();

void emit(Level l, const char *component, const std::string &msg);

#define LOG_ERROR(comp, msg) kwlog::emit(kwlog::Level::Error, comp, msg)
#define LOG_WARN(comp, msg) kwlog::emit(kwlog::Level::Warn, comp, msg)
#define LOG_INFO(comp, msg) kwlog::emit(kwlog::Level::Info, comp, msg)
#define LOG_DEBUG(comp, msg) kwlog::emit(kwlog::Level::Debug, comp, msg)
#define LOG_TRACE(comp, msg) kwlog::emit(kwlog::Level::Trace, comp, msg)

void init_libbpf_logging();

} // namespace kwlog
