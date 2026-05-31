#include "../util/fd.h"
#include "demos.h"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace demo {

static uint16_t checksum(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    return htons(static_cast<uint16_t>(~acc));
}

util::Result<void> run_ping_flood(const DemoConfig &cfg) {
    auto valid = validate_target(cfg.target_ip, cfg.override_safety);
    if (!valid.is_ok())
        return valid;

    util::UniqueFd sock(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    if (!sock.is_valid()) {
        if (errno == EPERM || errno == EACCES) {
            return util::Result<void>::Err(
                "Permission denied creating raw ICMP socket. Need root or CAP_NET_RAW.");
        }
        return util::Result<void>::Err("Failed to create raw ICMP socket: " +
                                       std::string(std::strerror(errno)));
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, cfg.target_ip.c_str(), &dest.sin_addr);

    char packet[64];
    memset(packet, 0, sizeof(packet));

    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(1234);

    auto start = std::chrono::steady_clock::now();
    uint16_t seq = 0;

    long long sleep_ns = 1000000000LL / cfg.rate_pps;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >=
            cfg.duration_s) {
            break;
        }

        icmp->un.echo.sequence = htons(seq++);
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, sizeof(packet));

        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
    }

    return util::Result<void>::Ok();
}

} // namespace demo
