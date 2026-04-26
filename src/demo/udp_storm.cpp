#include "demos.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstring>
#include "../util/fd.h"

namespace demo {

util::Result<void> run_udp_storm(const DemoConfig& cfg) {
    auto valid = validate_target(cfg.target_ip, cfg.override_safety);
    if (!valid.is_ok()) return valid;

    util::UniqueFd sock(socket(AF_INET, SOCK_DGRAM, 0));
    if (!sock.is_valid()) {
        return util::Result<void>::Err("Failed to create UDP socket");
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(cfg.target_port);
    inet_pton(AF_INET, cfg.target_ip.c_str(), &dest.sin_addr);

    char packet[1024];
    memset(packet, 'A', sizeof(packet));

    auto start = std::chrono::steady_clock::now();
    long long sleep_ns = 1000000000LL / cfg.rate_pps;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= cfg.duration_s) {
            break;
        }

        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest));
        std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
    }

    return util::Result<void>::Ok();
}

} // namespace demo