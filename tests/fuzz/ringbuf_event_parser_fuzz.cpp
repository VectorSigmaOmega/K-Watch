#include <span>
#include <stddef.h>
#include <stdint.h>

#include "../../src/core/event_formatter.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const auto format = (size > 0 && (data[0] & 1U) != 0U) ? core::EventOutputFormat::Json
                                                           : core::EventOutputFormat::Text;
    auto rendered = core::parse_and_format_event(std::span<const uint8_t>(data, size), format,
                                                 "2026-01-01T00:00:00Z");
    if (rendered.is_ok()) {
        (void)rendered.value().size();
    }
    return 0;
}
