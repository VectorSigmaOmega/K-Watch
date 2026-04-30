#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include "../../bpf/kwatch_shared.h"
#include "../util/ipv4.h"
#include "../util/result.h"

namespace core {

enum class EventOutputFormat {
    Text,
    Json,
};

inline util::Result<kwatch_event> parse_ringbuf_event(std::span<const uint8_t> bytes) {
    if (bytes.size() < sizeof(kwatch_event)) {
        return util::Result<kwatch_event>::Err("event buffer too small");
    }

    kwatch_event event{};
    std::memcpy(&event, bytes.data(), sizeof(event));
    return util::Result<kwatch_event>::Ok(event);
}

inline const char *event_proto_name(uint8_t protocol) {
    switch (protocol) {
    case 1:
        return "ICMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    default:
        return "OTHER";
    }
}

inline std::string format_tcp_flags(uint8_t flags) {
    std::string out;
    if ((flags & 0x02U) != 0U)
        out += "S";
    if ((flags & 0x10U) != 0U)
        out += "A";
    if ((flags & 0x08U) != 0U)
        out += "P";
    if ((flags & 0x01U) != 0U)
        out += "F";
    if ((flags & 0x04U) != 0U)
        out += "R";
    if (out.empty())
        out = "-";
    return out;
}

inline std::string format_event(const kwatch_event &event, EventOutputFormat format,
                                std::string_view timestamp) {
    const std::string src = util::ipv4::format(event.src_ip);
    const std::string dst = util::ipv4::format(event.dst_ip);

    if (format == EventOutputFormat::Json) {
        return std::string("{\"ts\":\"") + std::string(timestamp) +
               "\",\"ts_ns\":" + std::to_string(event.ts_ns) + ",\"src_ip\":\"" + src +
               "\",\"dst_ip\":\"" + dst + "\",\"sport\":" + std::to_string(event.sport) +
               ",\"dport\":" + std::to_string(event.dport) +
               ",\"protocol\":" + std::to_string(event.protocol) +
               ",\"tcp_flags\":" + std::to_string(event.tcp_flags) +
               ",\"icmp_type\":" + std::to_string(event.icmp_type) +
               ",\"icmp_code\":" + std::to_string(event.icmp_code) +
               ",\"ttl\":" + std::to_string(event.ttl) + ",\"action\":\"" +
               ((event.action == 1U) ? "drop" : "pass") + "\"}";
    }

    std::string rendered =
        std::string(timestamp) + " " + event_proto_name(event.protocol) + " " + src + ":" +
        std::to_string(event.sport) + " -> " + dst + ":" + std::to_string(event.dport) +
        " flags=" + format_tcp_flags(event.tcp_flags) + " ttl=" + std::to_string(event.ttl);
    if (event.protocol == 1U) {
        rendered +=
            " type=" + std::to_string(event.icmp_type) + " code=" + std::to_string(event.icmp_code);
    }
    return rendered;
}

inline util::Result<std::string> parse_and_format_event(std::span<const uint8_t> bytes,
                                                        EventOutputFormat format,
                                                        std::string_view timestamp) {
    auto parsed = parse_ringbuf_event(bytes);
    if (!parsed.is_ok()) {
        return util::Result<std::string>::Err(parsed.error());
    }
    return util::Result<std::string>::Ok(format_event(parsed.value(), format, timestamp));
}

} // namespace core
