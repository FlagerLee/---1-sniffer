//
// Created by FlagerLee on 2023/3/21.
//

#ifndef SNIFFER_PROTOCOL_H
#define SNIFFER_PROTOCOL_H

#include <cstdint>

#define TCP_DO_MASK 0xF000
#define TCP_RSV_MASK 0x0E00
#define TCP_FLAGS_MASK 0x01FF
#define TCP_DO_OFFSET 12
#define TCP_RSV_OFFSET 9
#define TCP_FLAGS_OFFSET 0

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t do_rsv_flags;
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

#endif //SNIFFER_PROTOCOL_H
