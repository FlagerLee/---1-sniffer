//
// Created by FlagerLee on 2023/3/18.
//

#ifndef SNIFFER_PACKET_H
#define SNIFFER_PACKET_H

#include <pcap.h>
#include <array>

using std::array;

#define IPV4_TYPE 0
#define IPV6_TYPE 1
#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86DD
#define ETH_ARP 0x0806
#define ETH_HEADER_LEN 14
#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define IPV4_VERSION 4
#define IPV6_VERSION 6
#define IPV6_VERSION_MASK 0xF0000000
#define IPV6_TRAFFIC_MASK 0x0FF00000
#define IPV6_FLOW_MASK 0x000FFFFF
#define IPV6_VERSION_OFFSET 28
#define IPV6_TRAFFIC_OFFSET 20
#define IPV6_FLOW_OFFSET 0

class Packet {
public:
    Packet();
    ~Packet();

    char ip_type;
    timeval recv_time;
    in_addr src_addr;
    in_addr dst_addr;
    in6_addr src_addr6;
    in6_addr dst_addr6;
    u_char protocol;
    uint32_t length;
    array<char, 65535> packet_data;
};

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t eth_type;
};

struct IPV4Header {
    uint8_t header_len : 4;
    uint8_t version : 4;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t ident;
    uint16_t flag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    in_addr src_addr;
    in_addr dst_addr;
};

struct IPV6Header {
    uint32_t version_traffic_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    in6_addr src_addr;
    in6_addr dst_addr;
};

enum SIGNAL_NAME {
    PACKET_TABLE_WIDGET_PACKET_RECEIVED
};

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif //SNIFFER_PACKET_H
