//
// Created by FlagerLee on 2023/3/21.
//

#ifndef SNIFFER_PROTOCOL_H
#define SNIFFER_PROTOCOL_H

#include <cstdint>
#include <string>
#include <QTreeWidget>
#include <QTableWidget>
#include <pcap.h>
#include "packet_header.h"


class ParsedPacket {
public:
    ParsedPacket(const u_char *data, uint32_t length);

    ~ParsedPacket() = default;

    virtual void get_info(char *) = 0;

    virtual void get_protocol(char *) = 0;

    virtual void fill(QTreeWidget *widget);

    virtual void get_src_addr(char *) = 0;

    virtual void get_dst_addr(char *) = 0;

    virtual bool is_ipv4() = 0;

    virtual bool is_ipv6() = 0;

    virtual bool is_arp() = 0;

    virtual bool is_tcp() = 0;

    virtual bool is_udp() = 0;

    virtual bool is_icmp() = 0;

    virtual bool is_icmpv6() = 0;

    virtual bool is_http() = 0;

    virtual bool is_tls() = 0;

    void fill_table(QTableWidget *widget);

    u_char data[10000];
    uint32_t packet_length;
};

class EthernetPacket : public ParsedPacket {
public:
    EthernetPacket(const u_char *data, uint32_t length);

    ~EthernetPacket() = default;

    void fill(QTreeWidget *widget) override;

    static uint16_t parse_protocol(const u_char *data);

    EthernetHeader ethernet_header;
    uint32_t offset;
};

class IPV4Packet : virtual public EthernetPacket {
public:
    IPV4Packet(const u_char *data, uint32_t length);

    ~IPV4Packet() = default;

    void fill(QTreeWidget *widget) override;

    static uint8_t parse_protocol(const u_char *data);

    void get_src_addr(char *) override;

    void get_dst_addr(char *) override;

    bool is_ipv4() override;

    bool is_ipv6() override;

    bool is_arp() override;

    IPV4Header ipv4_header;
    IPV4Option ipv4_option;
    uint32_t offset;
};

class IPV6Packet : virtual public EthernetPacket {
public:
    IPV6Packet(const u_char *data, uint32_t length);

    ~IPV6Packet() = default;

    void fill(QTreeWidget *widget) override;

    static uint8_t parse_protocol(const u_char *data);

    void get_src_addr(char *) override;

    void get_dst_addr(char *) override;

    bool is_ipv4() override;

    bool is_ipv6() override;

    bool is_arp() override;

    IPV6Header ipv6_header;
    uint32_t offset;
};

class ARPPacket : public EthernetPacket {
public:
    ARPPacket(const u_char *data, uint32_t length);

    ~ARPPacket() = default;

    void fill(QTreeWidget *widget) override;

    void get_info(char *) override;

    void get_protocol(char *) override;

    bool is_ipv4() override;

    bool is_ipv6() override;

    bool is_arp() override;

    bool is_tcp() override;

    bool is_udp() override;

    bool is_icmp() override;

    bool is_icmpv6() override;

    bool is_http() override;

    bool is_tls() override;

    uint32_t offset;
};

class TCPPacket : public IPV4Packet, public IPV6Packet {
public:
    explicit TCPPacket(const u_char *data, uint32_t length);

    ~TCPPacket() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    void get_src_addr(char *) override;

    void get_dst_addr(char *) override;

    bool is_ipv4() override;

    bool is_ipv6() override;

    bool is_arp() override;

    bool is_tcp() override;

    bool is_udp() override;

    bool is_icmp() override;

    bool is_icmpv6() override;

    bool is_http() override;

    bool is_tls() override;

    [[nodiscard]] std::string get_flag_name() const;

    [[nodiscard]] bool detect_http() const;

    [[nodiscard]] bool detect_tls() const;

    TCPHeader tcp_header;
    uint32_t offset;
    uint32_t total_offset;
    bool packet_is_ipv4;

    bool acc, cwr, ech, urg, ack, psh, rst, syn, fin;
};

class UDPPacket : public IPV4Packet, public IPV6Packet {
public:
    explicit UDPPacket(const u_char *data, uint32_t length);

    ~UDPPacket() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    void get_src_addr(char *) override;

    void get_dst_addr(char *) override;

    bool is_ipv4() override;

    bool is_ipv6() override;

    bool is_arp() override;

    bool is_tcp() override;

    bool is_udp() override;

    bool is_icmp() override;

    bool is_icmpv6() override;

    bool is_http() override;

    bool is_tls() override;

    UDPHeader udp_header;
    uint32_t offset;
    uint32_t total_offset;
    bool packet_is_ipv4;
};

class ICMPPacket : public IPV4Packet {
public:
    explicit ICMPPacket(const u_char *data, uint32_t length);

    ~ICMPPacket() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    bool is_tcp() override;

    bool is_udp() override;

    bool is_icmp() override;

    bool is_icmpv6() override;

    bool is_http() override;

    bool is_tls() override;

    ICMPHeader icmp_header;

    struct Echo {
        uint16_t identifier;
        uint16_t seq_num;
    } echo_data;

    u_char *data;
};

class ICMPV6Packet : public IPV6Packet {
public:
    explicit ICMPV6Packet(const u_char *data, uint32_t length);

    ~ICMPV6Packet() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    bool is_tcp() override;

    bool is_udp() override;

    bool is_icmp() override;

    bool is_icmpv6() override;

    bool is_http() override;

    bool is_tls() override;

    ICMPV6Header icmpv6_header;

    struct Echo {
        uint16_t identifier;
        uint16_t seq_num;
        u_char *data;
    } echo_data;

    struct Multicast {
        uint16_t max_response_delay;
        uint16_t rsv;
        in6_addr multicast_addr;
    } multicast_data;
    struct T135 {
        u_char rsv[4];
        in6_addr target_addr;
        u_char option[8];
    } s135;
    struct T136 {
        uint8_t rso_rsv;
        uint8_t rsv[3];
        in6_addr target_addr;
        u_char option;
    } s136;
};

class HTTPPacket : public TCPPacket {
public:
    explicit HTTPPacket(const u_char *data, uint32_t length);

    ~HTTPPacket() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    bool is_http() override;
};

class TLSPacket : public TCPPacket {
public:
    explicit TLSPacket(const u_char *data, uint32_t length);

    ~TLSPacket() = default;

    void get_info(char *) override;

    void fill(QTreeWidget *widget) override;

    void get_protocol(char *) override;

    bool is_tls() override;

    TLSHeader tls_header;
};

ParsedPacket *parse(const u_char *data, uint32_t length);

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif //SNIFFER_PROTOCOL_H
