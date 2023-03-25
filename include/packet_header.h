//
// Created by FlagerLee on 2023/3/23.
//

#ifndef SNIFFER_PACKET_HEADER_H
#define SNIFFER_PACKET_HEADER_H

#include <pcap.h>

#define PACKET_MAX_LENGTH 65535

#define IPV4_TYPE 0
#define IPV6_TYPE 1

#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86DD
#define ETH_ARP 0x0806

#define IPV4_HEADER_LEN 20
#define IPV4_VERSION 4
#define IPV4_FLAGS_MASK 0xE0
#define IPV4_OFFSET_MASK 0x1F
#define IPV4_FLAGS_OFFSET 5
#define IPV4_OFFSET_OFFSET 0

#define IPV6_HEADER_LEN 40
#define IPV6_VERSION 6
#define IPV6_VERSION_MASK 0xF0000000
#define IPV6_TRAFFIC_MASK 0x0FF00000
#define IPV6_FLOW_MASK 0x000FFFFF
#define IPV6_VERSION_OFFSET 28
#define IPV6_TRAFFIC_OFFSET 20
#define IPV6_FLOW_OFFSET 0

#define TCP_HL_MASK 0xF000
#define TCP_RSV_MASK 0x0E00
#define TCP_FLAGS_MASK 0x01FF
#define TCP_HL_OFFSET 12
#define TCP_RSV_OFFSET 9
#define TCP_FLAGS_OFFSET 0

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t eth_type;
};

struct IPV4Header {
    uint8_t header_len: 4;
    uint8_t version: 4;
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

struct IPV4Option {
    uint8_t option_type;
    uint8_t option_length;
    uint8_t *option_data;
};

struct IPV6Header {
    uint32_t version_traffic_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    in6_addr src_addr;
    in6_addr dst_addr;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hl_rsv_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

struct ICMPV6Header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

#endif //SNIFFER_PACKET_HEADER_H
