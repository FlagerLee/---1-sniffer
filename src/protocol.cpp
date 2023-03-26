//
// Created by FlagerLee on 2023/3/23.
//

#include "protocol.h"
#include "ui/sniffer_mainwindow.h"

// ------------------------------ParsedPacket------------------------------

ParsedPacket::ParsedPacket(const u_char *data, uint32_t length) {
    packet_length = length;
    memcpy(this->data, data, length);
}

void ParsedPacket::fill(QTreeWidget *widget) {
    char info[100];
    sprintf(info, "%d bytes captured (%d bits)", packet_length, packet_length * 4);
    QStringList str_list{info};
    auto item = new QTreeWidgetItem(str_list);
    widget->addTopLevelItem(item);
}

void ParsedPacket::fill_table(QTableWidget *widget) {
    uint32_t rows = (packet_length - 1) / 16 + 1;
    widget->setRowCount(rows);
    for (int i = 0; i < rows - 1; i++) {
        char header_cell[10], cell1[30], cell2[30], cell3[20];
        sprintf(header_cell, "%04x", i * 16);
        sprintf(cell1, "%02x %02x %02x %02x %02x %02x %02x %02x",
                data[i * 16], data[i * 16 + 1], data[i * 16 + 2], data[i * 16 + 3],
                data[i * 16 + 4], data[i * 16 + 5], data[i * 16 + 6], data[i * 16 + 7]
        );
        cell1[23] = '\0';
        sprintf(cell2, "%02x %02x %02x %02x %02x %02x %02x %02x",
                data[i * 16 + 8], data[i * 16 + 9], data[i * 16 + 10], data[i * 16 + 11],
                data[i * 16 + 12], data[i * 16 + 13], data[i * 16 + 14], data[i * 16 + 15]
        );
        cell2[23] = '\0';
        for (int j = 0; j < 16; j++) {
            if (isprint(data[i * 16 + j])) cell3[j] = data[i * 16 + j];
            else cell3[j] = '.';
        }
        cell3[16] = '\0';
        widget->setItem(i, 0, new QTableWidgetItem(cell1));
        widget->setItem(i, 1, new QTableWidgetItem(cell2));
        widget->setItem(i, 2, new QTableWidgetItem(cell3));
        widget->setVerticalHeaderItem(i, new QTableWidgetItem(header_cell));
    }
    char header_cell[10], cell1[30], cell2[30], cell3[20];
    int index = rows * 16 - 16, tail = packet_length - index;
    for (int i = 0; i < tail; i++, index++) {
        if (i < 8) {
            sprintf(cell1 + (i == 0 ? 0 : i * 3), "%02x ", data[index]);
        } else {
            sprintf(cell2 + (i == 8 ? 0 : (i - 8) * 3), "%02x ", data[index]);
        }
        if (isprint(data[index])) cell3[i] = data[index];
        else cell3[i] = '.';
    }
    if (tail <= 8) {
        cell1[tail * 3] = '\0';
        cell2[0] = '\0';
    } else {
        cell1[23] = '\0';
        cell2[(tail - 8) * 3] = '\0';
    }
    cell3[16] = '\0';
    sprintf(header_cell, "%04x", rows * 16 - 16);
    widget->setItem(rows - 1, 0, new QTableWidgetItem(cell1));
    widget->setItem(rows - 1, 1, new QTableWidgetItem(cell2));
    widget->setItem(rows - 1, 2, new QTableWidgetItem(cell3));
    widget->setVerticalHeaderItem(rows - 1, new QTableWidgetItem(header_cell));
}

// ------------------------------EthernetPacket------------------------------

EthernetPacket::EthernetPacket(const u_char *data, uint32_t length) : ParsedPacket(data, length) {
    this->ethernet_header = *(EthernetHeader *) (ParsedPacket::data);
    this->ethernet_header.eth_type = ntohs(this->ethernet_header.eth_type);
    this->offset = 14;
}

uint16_t EthernetPacket::parse_protocol(const u_char *data) {
    return ((uint16_t) data[0x0c] << 8) + (uint16_t) data[0x0d];
}

void EthernetPacket::fill(QTreeWidget *widget) {
    ParsedPacket::fill(widget);
    char top_info[100];
    sprintf(top_info, "Ethernet II, Src: %02x:%02x:%02x:%02x:%02x:%02x, Dst: %02x:%02x:%02x:%02x:%02x:%02x",
            ethernet_header.src[0], ethernet_header.src[1], ethernet_header.src[2],
            ethernet_header.src[3], ethernet_header.src[4], ethernet_header.src[5],
            ethernet_header.dst[0], ethernet_header.dst[1], ethernet_header.dst[2],
            ethernet_header.dst[3], ethernet_header.dst[4], ethernet_header.dst[5]
    );
    auto top_item = new QTreeWidgetItem(QStringList{top_info});
    char dst_info[100];
    sprintf(dst_info, "Destination: %02x:%02x:%02x:%02x:%02x:%02x",
            ethernet_header.dst[0], ethernet_header.dst[1], ethernet_header.dst[2],
            ethernet_header.dst[3], ethernet_header.dst[4], ethernet_header.dst[5]
    );
    auto dst_item = new QTreeWidgetItem(QStringList{dst_info});
    char src_info[100];
    sprintf(src_info, "Source: %02x:%02x:%02x:%02x:%02x:%02x",
            ethernet_header.src[0], ethernet_header.src[1], ethernet_header.src[2],
            ethernet_header.src[3], ethernet_header.src[4], ethernet_header.src[5]
    );
    auto src_item = new QTreeWidgetItem(QStringList{src_info});
    char type_info[30];
    switch (ethernet_header.eth_type) {
        case ETH_IPV4:
            sprintf(type_info, "Type: IPV4 (0x0800)");
            break;
        case ETH_IPV6:
            sprintf(type_info, "Type: IPV6 (0x86DD)");
            break;
        case ETH_ARP:
            sprintf(type_info, "Type: ARP (0x0806)");
            break;
        default:
            sprintf(type_info, "Unknown Type (0x%x)", ethernet_header.eth_type);
    }
    auto type_item = new QTreeWidgetItem(QStringList{type_info});
    top_item->addChildren(QList<QTreeWidgetItem *>{dst_item, src_item, type_item});
    widget->addTopLevelItem(top_item);
}

// ------------------------------IPV4Packet------------------------------

IPV4Packet::IPV4Packet(const u_char *data, uint32_t length) {
    this->ipv4_header = *(IPV4Header *) (ParsedPacket::data + EthernetPacket::offset);
    if (this->ipv4_header.header_len > 5) {
        this->ipv4_option = *(IPV4Option *) (ParsedPacket::data + EthernetPacket::offset + 20);
        this->ipv4_option.option_data = (uint8_t *) (ParsedPacket::data + EthernetPacket::offset + 22);
    }
    this->offset = this->ipv4_header.header_len * 4;

    this->ipv4_header.total_length = ntohs(this->ipv4_header.total_length);
    this->ipv4_header.ident = ntohs(this->ipv4_header.ident);
    this->ipv4_header.flag_offset = ntohs(this->ipv4_header.flag_offset);
    this->ipv4_header.checksum = ntohs(this->ipv4_header.checksum);
}

uint8_t IPV4Packet::parse_protocol(const u_char *data) {
    return (uint8_t) data[0x17];
}

void IPV4Packet::get_src_addr(char *str) {
    inet_ntop(AF_INET, &ipv4_header.src_addr, str, 20);
}

void IPV4Packet::get_dst_addr(char *str) {
    inet_ntop(AF_INET, &ipv4_header.dst_addr, str, 20);
}

void IPV4Packet::fill(QTreeWidget *widget) {
    EthernetPacket::fill(widget);
    char top_info[100], src_addr[20], dst_addr[20];
    inet_ntop(AF_INET, &ipv4_header.src_addr, src_addr, 20);
    inet_ntop(AF_INET, &ipv4_header.dst_addr, dst_addr, 20);
    sprintf(top_info, "Internet Protocol Version 4, Src: %s, Dst: %s", src_addr, dst_addr);
    auto top_item = new QTreeWidgetItem(QStringList{top_info});

    char version_info[30];
    sprintf(version_info, "%d%d%d%d .... = Version: %d",
            (ipv4_header.version & 0b1000) >> 3,
            (ipv4_header.version & 0b0100) >> 2,
            (ipv4_header.version & 0b0010) >> 1,
            (ipv4_header.version & 0b0001),
            ipv4_header.version
    );
    auto version_item = new QTreeWidgetItem(QStringList{version_info});

    char length_info[30];
    sprintf(length_info, ".... %d%d%d%d = Header Length: %d bytes (%d)",
            (ipv4_header.header_len & 0b1000) >> 3,
            (ipv4_header.header_len & 0b0100) >> 2,
            (ipv4_header.header_len & 0b0010) >> 1,
            (ipv4_header.header_len & 0b0001),
            ipv4_header.header_len * 4, ipv4_header.header_len
    );
    auto length_item = new QTreeWidgetItem(QStringList{length_info});

    char tos_info[50];
    sprintf(tos_info, "Differentiated Services Fields: %02x", ipv4_header.type_of_service);
    auto tos_item = new QTreeWidgetItem(QStringList{tos_info});

    char total_length_info[30];
    sprintf(total_length_info, "Total Length: %d", ipv4_header.total_length);
    auto total_length_item = new QTreeWidgetItem(QStringList{total_length_info});

    char ident_info[30];
    sprintf(ident_info, "Identification: %04x", ipv4_header.ident);
    auto ident_item = new QTreeWidgetItem(QStringList{ident_info});

    char flags_info[30];
    uint8_t flags = (ipv4_header.flag_offset & IPV4_FLAGS_MASK) >> IPV4_FLAGS_OFFSET;
    sprintf(flags_info, "%d%d%d. .... = Flags: %x",
            (flags & 0b100) >> 2, (flags & 0b010) >> 1, (flags & 0b001), flags
    );
    auto flags_item = new QTreeWidgetItem(QStringList{flags_info});

    char offset_info[40];
    uint16_t frag_offset = (ipv4_header.flag_offset & IPV4_OFFSET_MASK) >> IPV4_OFFSET_OFFSET;
    sprintf(offset_info, "...%d %d%d%d%d %d%d%d%d %d%d%d%d = Fragment Offset: %d",
            (frag_offset & 0x1000) >> 12,
            (frag_offset & 0x0800) >> 11, (frag_offset & 0x0400) >> 10, (frag_offset & 0x0200) >> 9,
            (frag_offset & 0x0100) >> 8,
            (frag_offset & 0x0080) >> 7, (frag_offset & 0x0040) >> 6, (frag_offset & 0x0020) >> 5,
            (frag_offset & 0x0010) >> 4,
            (frag_offset & 0x0008) >> 3, (frag_offset & 0x0004) >> 2, (frag_offset & 0x0002) >> 1,
            (frag_offset & 0x0001),
            frag_offset
    );
    auto offset_item = new QTreeWidgetItem(QStringList{offset_info});

    char ttl_info[30];
    sprintf(ttl_info, "Time to Live: %d", ipv4_header.ttl);
    auto ttl_item = new QTreeWidgetItem(QStringList{ttl_info});

    char protocol_info[30];
    switch (ipv4_header.protocol) {
        case IPPROTO_ICMP:
            sprintf(protocol_info, "Protocol: ICMP (%d)", IPPROTO_ICMP);
            break;
        case IPPROTO_UDP:
            sprintf(protocol_info, "Protocol: UDP (%d)", IPPROTO_UDP);
            break;
        case IPPROTO_TCP:
            sprintf(protocol_info, "Protocol: TCP (%d)", IPPROTO_TCP);
            break;
        case IPPROTO_IGMP:
            sprintf(protocol_info, "Protocol: IGMP (%d)", IPPROTO_IGMP);
            break;
        default:
            sprintf(protocol_info, "Unknown Protocol: %d", ipv4_header.protocol);
    }
    auto protocol_item = new QTreeWidgetItem(QStringList{protocol_info});

    char checksum_info[50];
    sprintf(checksum_info, "Header Checksum: %04x", ipv4_header.checksum);
    auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

    char src_addr_info[50];
    sprintf(src_addr_info, "Source Address: %s", src_addr);
    auto src_addr_item = new QTreeWidgetItem(QStringList{src_addr_info});

    char dst_addr_info[50];
    sprintf(dst_addr_info, "Destination Address: %s", dst_addr);
    auto dst_addr_item = new QTreeWidgetItem(QStringList{dst_addr_info});

    top_item->addChildren(QList<QTreeWidgetItem *>{
            version_item, length_item, tos_item, total_length_item, ident_item, flags_item,
            offset_item, ttl_item, protocol_item, checksum_item, src_addr_item, dst_addr_item
    });
    widget->addTopLevelItem(top_item);
}

bool IPV4Packet::is_ipv4() {
    return true;
}

bool IPV4Packet::is_ipv6() {
    return false;
}

bool IPV4Packet::is_arp() {
    return false;
}

// ------------------------------IPV6Packet------------------------------

IPV6Packet::IPV6Packet(const u_char *data, uint32_t length) : EthernetPacket(data, length) {
    this->ipv6_header = *(IPV6Header *) (ParsedPacket::data + EthernetPacket::offset);
    this->offset = 40;

    this->ipv6_header.version_traffic_flow = ntohl(this->ipv6_header.version_traffic_flow);
    this->ipv6_header.payload_length = ntohs(this->ipv6_header.payload_length);
}

uint8_t IPV6Packet::parse_protocol(const u_char *data) {
    return (uint8_t) data[0x14];
}

void IPV6Packet::get_src_addr(char *str) {
    inet_ntop(AF_INET6, &ipv6_header.src_addr, str, 45);
}

void IPV6Packet::get_dst_addr(char *str) {
    inet_ntop(AF_INET6, &ipv6_header.dst_addr, str, 45);
}

void IPV6Packet::fill(QTreeWidget *widget) {
    EthernetPacket::fill(widget);

    char top_info[200], src_addr[50], dst_addr[50];
    inet_ntop(AF_INET6, &ipv6_header.src_addr, src_addr, 50);
    inet_ntop(AF_INET6, &ipv6_header.dst_addr, dst_addr, 50);
    sprintf(top_info, "Internet Protocol Version 6, Src: %s, Dst: %s", src_addr, dst_addr);
    auto top_item = new QTreeWidgetItem(QStringList{top_info});

    char version_info[40];
    uint8_t version = (ipv6_header.version_traffic_flow & IPV6_VERSION_MASK) >> IPV6_VERSION_OFFSET;
    sprintf(version_info, "%d%d%d%d .... = Version %d",
            (version & 0b1000) >> 3, (version & 0b0100) >> 2, (version & 0b0010) >> 1, (version & 0b0001),
            version
    );
    auto version_item = new QTreeWidgetItem(QStringList{version_info});

    char traffic_info[100];
    uint8_t traffic = (ipv6_header.version_traffic_flow & IPV6_TRAFFIC_MASK) >> IPV6_TRAFFIC_OFFSET;
    sprintf(traffic_info, ".... %d%d%d%d %d%d%d%d .... .... .... .... .... = Traffic Class: 0x%02x",
            (traffic & 0b10000000) >> 7, (traffic & 0b01000000) >> 6, (traffic & 0b00100000) >> 5,
            (traffic & 0b00010000) >> 4, (traffic & 0b00001000) >> 3, (traffic & 0b00000100) >> 2,
            (traffic & 0b00000010) >> 1, (traffic & 0b00000001),
            traffic
    );
    auto traffic_item = new QTreeWidgetItem(QStringList{traffic_info});

    char flow_info[100];
    uint32_t flow = (ipv6_header.version_traffic_flow & IPV6_FLOW_MASK) >> IPV6_FLOW_OFFSET;
    sprintf(flow_info, ".... %d%d%d%d %d%d%d%d %d%d%d%d %d%d%d%d %d%d%d%d = Flow Label: 0x%05x",
            (flow & 0x80000) >> 19, (flow & 0x40000) >> 18, (flow & 0x20000) >> 17, (flow & 0x10000) >> 16,
            (flow & 0x08000) >> 15, (flow & 0x04000) >> 14, (flow & 0x02000) >> 13, (flow & 0x01000) >> 12,
            (flow & 0x00800) >> 11, (flow & 0x00400) >> 10, (flow & 0x00200) >> 9, (flow & 0x00100) >> 8,
            (flow & 0x00080) >> 7, (flow & 0x00040) >> 6, (flow & 0x00020) >> 5, (flow & 0x00010) >> 4,
            (flow & 0x00008) >> 3, (flow & 0x00004) >> 2, (flow & 0x00002) >> 1, (flow & 0x00001),
            flow
    );
    auto flow_item = new QTreeWidgetItem(QStringList{flow_info});

    char payload_length_info[40];
    sprintf(payload_length_info, "Payload Length: %d", ipv6_header.payload_length);
    auto payload_length_item = new QTreeWidgetItem(QStringList{payload_length_info});

    char next_header_info[40];
    switch (ipv6_header.next_header) {
        case IPPROTO_TCP:
            sprintf(next_header_info, "Next Header: TCP (%d)", IPPROTO_TCP);
            break;
        case IPPROTO_UDP:
            sprintf(next_header_info, "Next Header: UDP (%d)", IPPROTO_UDP);
            break;
        case IPPROTO_ICMPV6:
            sprintf(next_header_info, "Next Header: ICMPv6 (%d)", IPPROTO_ICMPV6);
            break;
        default:
            sprintf(next_header_info, "Unknown Next Header: %d", ipv6_header.next_header);
    }
    auto next_header_item = new QTreeWidgetItem(QStringList{next_header_info});

    char hop_limit_info[40];
    sprintf(hop_limit_info, "Hop Limit: %d", ipv6_header.hop_limit);
    auto hop_limit_item = new QTreeWidgetItem(QStringList{hop_limit_info});

    char src_addr_info[100];
    sprintf(src_addr_info, "Source Address: %s", src_addr);
    auto src_addr_item = new QTreeWidgetItem(QStringList{src_addr_info});

    char dst_addr_info[100];
    sprintf(dst_addr_info, "Destination Address: %s", dst_addr);
    auto dst_addr_item = new QTreeWidgetItem(QStringList{dst_addr_info});

    top_item->addChildren(QList<QTreeWidgetItem *>{
            version_item, traffic_item, flow_item, payload_length_item,
            next_header_item, hop_limit_item, src_addr_item, dst_addr_item
    });
    widget->addTopLevelItem(top_item);
}

bool IPV6Packet::is_ipv4() {
    return false;
}

bool IPV6Packet::is_ipv6() {
    return true;
}

bool IPV6Packet::is_arp() {
    return false;
}

// ------------------------------ARPPacket------------------------------

ARPPacket::ARPPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length) {

}

void ARPPacket::fill(QTreeWidget *widget) {
    EthernetPacket::fill(widget);
}

void ARPPacket::get_info(char *str) {
    sprintf(str, "ARP");
}

void ARPPacket::get_protocol(char *str) {
    sprintf(str, "ARP");
}

bool ARPPacket::is_ipv4() {
    return false;
}

bool ARPPacket::is_ipv6() {
    return false;
}

bool ARPPacket::is_arp() {
    return true;
}

bool ARPPacket::is_tcp() {
    return false;
}

bool ARPPacket::is_udp() {
    return false;
}

bool ARPPacket::is_icmp() {
    return false;
}

bool ARPPacket::is_icmpv6() {
    return false;
}

bool ARPPacket::is_http() {
    return false;
}

bool ARPPacket::is_tls() {
    return false;
}

// ------------------------------TCPPacket------------------------------

TCPPacket::TCPPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length), IPV4Packet(data, length),
                                                            IPV6Packet(data, length) {
    packet_is_ipv4 = EthernetPacket::ethernet_header.eth_type == ETH_IPV4;
    if (packet_is_ipv4)
        tcp_header = *(TCPHeader *) (ParsedPacket::data + EthernetPacket::offset + IPV4Packet::offset);
    else
        tcp_header = *(TCPHeader *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset);
    tcp_header.src_port = ntohs(tcp_header.src_port);
    tcp_header.dst_port = ntohs(tcp_header.dst_port);
    tcp_header.seq_num = ntohl(tcp_header.seq_num);
    tcp_header.ack_num = ntohl(tcp_header.ack_num);
    tcp_header.hl_rsv_flags = ntohs(tcp_header.hl_rsv_flags);
    tcp_header.window = ntohs(tcp_header.window);
    tcp_header.checksum = ntohs(tcp_header.checksum);
    tcp_header.urgent_ptr = ntohs(tcp_header.urgent_ptr);
    offset = ((tcp_header.hl_rsv_flags & TCP_HL_MASK) >> TCP_HL_OFFSET) * 4;
    if (packet_is_ipv4) total_offset = EthernetPacket::offset + IPV4Packet::offset + offset;
    else total_offset = EthernetPacket::offset + IPV6Packet::offset + offset;

    uint16_t flags = (tcp_header.hl_rsv_flags & TCP_FLAGS_MASK) >> TCP_FLAGS_OFFSET;
    acc = flags & 0b100000000;
    cwr = flags & 0b010000000;
    ech = flags & 0b001000000;
    urg = flags & 0b000100000;
    ack = flags & 0b000010000;
    psh = flags & 0b000001000;
    rst = flags & 0b000000100;
    syn = flags & 0b000000010;
    fin = flags & 0b000000001;
}

void TCPPacket::get_src_addr(char *str) {
    if (packet_is_ipv4) IPV4Packet::get_src_addr(str);
    else IPV6Packet::get_src_addr(str);
}

void TCPPacket::get_dst_addr(char *str) {
    if (packet_is_ipv4) IPV4Packet::get_dst_addr(str);
    else IPV6Packet::get_dst_addr(str);
}

void TCPPacket::fill(QTreeWidget *widget) {
    if (packet_is_ipv4) IPV4Packet::fill(widget);
    else IPV6Packet::fill(widget);

    char top_info[200];
    sprintf(top_info, "Transmission Control Protocol, Src Port: %d, Dst Prot: %d, Seq: %d, Ack: %d",
            tcp_header.src_port, tcp_header.dst_port, tcp_header.seq_num, tcp_header.ack_num
    );
    auto top_item = new QTreeWidgetItem(QStringList{top_info});

    char src_port_info[40];
    sprintf(src_port_info, "Source Port: %d", tcp_header.src_port);
    auto src_port_item = new QTreeWidgetItem(QStringList{src_port_info});

    char dst_port_info[40];
    sprintf(dst_port_info, "Destination Port: %d", tcp_header.dst_port);
    auto dst_port_item = new QTreeWidgetItem(QStringList{dst_port_info});

    char seq_info[80];
    sprintf(seq_info, "Sequence Number (raw): %d", tcp_header.seq_num);
    auto seq_item = new QTreeWidgetItem(QStringList{seq_info});

    char ack_info[80];
    sprintf(ack_info, "Acknowledgment Number (raw): %d", tcp_header.ack_num);
    auto ack_item = new QTreeWidgetItem(QStringList{ack_info});

    char length_info[60];
    sprintf(length_info, "%d%d%d%d .... = Header Length: %d bytes (%d)",
            (offset & 0b1000) >> 3, (offset & 0b0100) >> 2, (offset & 0b0010) >> 1, offset & 0b0001,
            offset * 4, offset
    );
    auto length_item = new QTreeWidgetItem(QStringList{length_info});

    char flags_info[70], flags_RSV[50], flags_ACC[50], flags_CWR[50], flags_ECH[50],
            flags_URG[50], flags_ACK[50], flags_PSH[50], flags_RST[50], flags_SYN[50], flags_FIN[50];
    uint16_t flags = (tcp_header.hl_rsv_flags & TCP_FLAGS_MASK) >> TCP_FLAGS_OFFSET;
    sprintf(flags_RSV, "000. .... .... = Reserved: Not set");
    sprintf(flags_ACC, "...%d .... .... = Accurate ECN: %s", acc, acc ? "Set" : "Not Set");
    sprintf(flags_CWR, ".... %d... .... = Congestion Window Reduced: %s", cwr, cwr ? "Set" : "Not Set");
    sprintf(flags_ECH, ".... .%d.. .... = ECN-Echo: %s", ech, ech ? "Set" : "Not Set");
    sprintf(flags_URG, ".... ..%d. .... = Urgent: %s", urg, urg ? "Set" : "Not Set");
    sprintf(flags_ACK, ".... ...%d .... = Acknowledgement: %s", ack, ack ? "Set" : "Not Set");
    sprintf(flags_PSH, ".... .... %d... = Push: %s", psh, psh ? "Set" : "Not Set");
    sprintf(flags_RST, ".... .... .%d.. = Reset: %s", rst, rst ? "Set" : "Not Set");
    sprintf(flags_SYN, ".... .... ..%d. = Syn: %s", syn, syn ? "Set" : "Not Set");
    sprintf(flags_FIN, ".... .... ...%d = Fin: %s", fin, fin ? "Set" : "Not Set");
    auto rsv_flag_item = new QTreeWidgetItem(QStringList{flags_RSV});
    auto acc_flag_item = new QTreeWidgetItem(QStringList{flags_ACC});
    auto cwr_flag_item = new QTreeWidgetItem(QStringList{flags_CWR});
    auto ech_flag_item = new QTreeWidgetItem(QStringList{flags_ECH});
    auto urg_flag_item = new QTreeWidgetItem(QStringList{flags_URG});
    auto ack_flag_item = new QTreeWidgetItem(QStringList{flags_ACK});
    auto psh_flag_item = new QTreeWidgetItem(QStringList{flags_PSH});
    auto rst_flag_item = new QTreeWidgetItem(QStringList{flags_RST});
    auto syn_flag_item = new QTreeWidgetItem(QStringList{flags_SYN});
    auto fin_flag_item = new QTreeWidgetItem(QStringList{flags_FIN});
    sprintf(flags_info, "Flags: 0x%03x %s", flags, ("(" + get_flag_name() + ")").c_str());
    auto flags_item = new QTreeWidgetItem(QStringList{flags_info});
    flags_item->addChildren(QList<QTreeWidgetItem *>{
            rsv_flag_item, acc_flag_item, cwr_flag_item, ech_flag_item, urg_flag_item,
            ack_flag_item, psh_flag_item, rst_flag_item, syn_flag_item, fin_flag_item
    });

    char window_info[40];
    sprintf(window_info, "Window: %d", tcp_header.window);
    auto window_item = new QTreeWidgetItem(QStringList{window_info});

    char checksum_info[40];
    sprintf(checksum_info, "Checksum: 0x%04x", tcp_header.checksum);
    auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

    char urg_ptr_info[40];
    sprintf(urg_ptr_info, "Urgent Pointer: %d", tcp_header.urgent_ptr);
    auto urg_ptr_item = new QTreeWidgetItem(QStringList{urg_ptr_info});

    top_item->addChildren(QList<QTreeWidgetItem *>{
            src_port_item, dst_port_item, seq_item, ack_item, length_item,
            flags_item, window_item, checksum_item, urg_ptr_item
    });
    widget->addTopLevelItem(top_item);
}

void TCPPacket::get_info(char *str) {
    sprintf(str, "%d -> %d [%s] Ack=%d Win=%d Len=%d",
            tcp_header.src_port, tcp_header.dst_port, get_flag_name().c_str(), tcp_header.ack_num,
            tcp_header.window,
            ParsedPacket::packet_length - EthernetPacket::offset -
            (packet_is_ipv4 ? IPV4Packet::offset : IPV6Packet::offset) -
            offset
    );
}

void TCPPacket::get_protocol(char *str) {
    sprintf(str, "TCP");
}

bool TCPPacket::is_ipv4() {
    return packet_is_ipv4;
}

bool TCPPacket::is_ipv6() {
    return !packet_is_ipv4;
}

bool TCPPacket::is_arp() {
    return false;
}

bool TCPPacket::is_tcp() {
    return true;
}

bool TCPPacket::is_udp() {
    return false;
}

bool TCPPacket::is_icmp() {
    return false;
}

bool TCPPacket::is_icmpv6() {
    return false;
}

bool TCPPacket::is_http() {
    return false;
}

bool TCPPacket::is_tls() {
    return false;
}

std::string TCPPacket::get_flag_name() const {
    bool is_first = true;
    std::string name;
    if (acc) {
        name += "ACC";
        is_first = false;
    }
    if (cwr) {
        if (is_first) {
            name += "CWR";
            is_first = false;
        } else name += ", CWR";
    }
    if (ech) {
        if (is_first) {
            name += "ECH";
            is_first = false;
        } else name += ", ECH";
    }
    if (urg) {
        if (is_first) {
            name += "URG";
            is_first = false;
        } else name += ", URG";
    }
    if (ack) {
        if (is_first) {
            name += "ACK";
            is_first = false;
        } else name += ", ACK";
    }
    if (psh) {
        if (is_first) {
            name += "PSH";
            is_first = false;
        } else name += ", PSH";
    }
    if (rst) {
        if (is_first) {
            name += "RST";
            is_first = false;
        } else name += ", RST";
    }
    if (syn) {
        if (is_first) {
            name += "SYN";
            is_first = false;
        } else name += ", SYN";
    }
    if (fin) {
        if (is_first) {
            name += "FIN";
        } else name += ", FIN";
    }
    return name;
}

bool TCPPacket::detect_http() const {
    if ((data[total_offset] == 'G' && data[total_offset + 1] == 'E' && data[total_offset + 2] == 'T') ||
        (data[total_offset] == 'H' && data[total_offset + 1] == 'E' && data[total_offset + 2] == 'A' &&
         data[total_offset + 3] == 'D') ||
        (data[total_offset] == 'P' && data[total_offset + 1] == 'O' && data[total_offset + 2] == 'S' &&
         data[total_offset + 3] == 'T') ||
        (data[total_offset] == 'P' && data[total_offset + 1] == 'U' && data[total_offset + 2] == 'T') ||
        (data[total_offset] == 'D' && data[total_offset + 1] == 'E' && data[total_offset + 2] == 'L' &&
         data[total_offset + 3] == 'E' && data[total_offset + 4] == 'T' && data[total_offset + 5] == 'E') ||
        (data[total_offset] == 'O' && data[total_offset + 1] == 'P' && data[total_offset + 2] == 'T' &&
         data[total_offset + 3] == 'I' && data[total_offset + 4] == 'O' && data[total_offset + 5] == 'N' &&
         data[total_offset + 6] == 'S') ||
        (data[total_offset] == 'T' && data[total_offset + 1] == 'R' && data[total_offset + 2] == 'A' &&
         data[total_offset + 3] == 'C' && data[total_offset + 4] == 'E') ||
        (data[total_offset] == 'C' && data[total_offset + 1] == 'O' && data[total_offset + 2] == 'N' &&
         data[total_offset + 3] == 'N' && data[total_offset + 4] == 'E' && data[total_offset + 5] == 'C' &&
         data[total_offset + 6] == 'T') ||
        (data[total_offset] == 'H' && data[total_offset + 1] == 'T' && data[total_offset + 2] == 'T' &&
         data[total_offset + 3] == 'P')
            )
        return true;
    return false;
}

bool TCPPacket::detect_tls() const {
    TLSHeader header = *(TLSHeader *) (data + total_offset);
    return (header.version_major == 0x03 && (header.version_minor == 0x01 || header.version_minor == 0x03)) &&
           (header.type == 20 || header.type == 21 || header.type == 22 || header.type == 23 || header.type == 24);
}

// ------------------------------UDPPacket------------------------------

UDPPacket::UDPPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length), IPV4Packet(data, length),
                                                            IPV6Packet(data, length) {
    packet_is_ipv4 = EthernetPacket::ethernet_header.eth_type == ETH_IPV4;
    if (packet_is_ipv4)
        udp_header = *(UDPHeader *) (ParsedPacket::data + EthernetPacket::offset + IPV4Packet::offset);
    else
        udp_header = *(UDPHeader *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset);
    udp_header.src_port = ntohs(udp_header.src_port);
    udp_header.dst_port = ntohs(udp_header.dst_port);
    udp_header.length = ntohs(udp_header.length);
    udp_header.checksum = ntohs(udp_header.checksum);
    offset = 8;
    if (packet_is_ipv4) total_offset = EthernetPacket::offset + IPV4Packet::offset + offset;
    else total_offset = EthernetPacket::offset + IPV6Packet::offset + offset;
}

void UDPPacket::get_src_addr(char *str) {
    if (packet_is_ipv4) IPV4Packet::get_src_addr(str);
    else IPV6Packet::get_src_addr(str);
}

void UDPPacket::get_dst_addr(char *str) {
    if (packet_is_ipv4) IPV4Packet::get_dst_addr(str);
    else IPV6Packet::get_dst_addr(str);
}

void UDPPacket::fill(QTreeWidget *widget) {
    if (packet_is_ipv4) IPV4Packet::fill(widget);
    else IPV6Packet::fill(widget);

    char top_info[80];
    sprintf(top_info, "User Datagram Protocol, Src Port: %d, Dst Port: %d", udp_header.src_port, udp_header.dst_port);
    auto top_item = new QTreeWidgetItem(QStringList{top_info});

    char src_port_info[40];
    sprintf(src_port_info, "Source Port: %d", udp_header.src_port);
    auto src_port_item = new QTreeWidgetItem(QStringList{src_port_info});

    char dst_port_info[40];
    sprintf(dst_port_info, "Destination Port: %d", udp_header.dst_port);
    auto dst_port_item = new QTreeWidgetItem(QStringList{dst_port_info});

    char length_info[40];
    sprintf(length_info, "Length: %d", udp_header.length);
    auto length_item = new QTreeWidgetItem(QStringList{length_info});

    char checksum_info[40];
    sprintf(checksum_info, "Checksum: 0x%04x", udp_header.checksum);
    auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

    top_item->addChildren(QList<QTreeWidgetItem *>{
            src_port_item, dst_port_item, length_item, checksum_item
    });
    widget->addTopLevelItem(top_item);
}

void UDPPacket::get_info(char *str) {
    sprintf(str, "%d -> %d Len=%d", udp_header.src_port, udp_header.dst_port,
            udp_header.length - 8);
}

void UDPPacket::get_protocol(char *str) {
    sprintf(str, "UDP");
}

bool UDPPacket::is_ipv4() {
    return packet_is_ipv4;
}

bool UDPPacket::is_ipv6() {
    return !packet_is_ipv4;
}

bool UDPPacket::is_arp() {
    return false;
}

bool UDPPacket::is_tcp() {
    return false;
}

bool UDPPacket::is_udp() {
    return true;
}

bool UDPPacket::is_icmp() {
    return false;
}

bool UDPPacket::is_icmpv6() {
    return false;
}

bool UDPPacket::is_http() {
    return false;
}

bool UDPPacket::is_tls() {
    return false;
}

// ------------------------------ICMPPacket------------------------------

ICMPPacket::ICMPPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length), IPV4Packet(data, length) {
    icmp_header = *(ICMPHeader *) (ParsedPacket::data + EthernetPacket::offset + IPV4Packet::offset);
    icmp_header.checksum = ntohs(icmp_header.checksum);
    switch (icmp_header.type) {
        case 0:
        case 8:
            // echo request and response
            echo_data = *(Echo *) (ParsedPacket::data + EthernetPacket::offset + IPV4Packet::offset + 4);
            echo_data.identifier = ntohs(echo_data.identifier);
            echo_data.seq_num = ntohs(echo_data.seq_num);
        case 3:
        case 4:
        case 11:
            data = ParsedPacket::data + EthernetPacket::offset + IPV4Packet::offset + 8;
            break;
    }
}

void ICMPPacket::fill(QTreeWidget *widget) {
    IPV4Packet::fill(widget);

    auto top_item = new QTreeWidgetItem(QStringList{"Internet Control Message Protocol"});

    if (icmp_header.type == 0 || icmp_header.type == 8) {
        auto type_item = icmp_header.type == 0 ?
                         new QTreeWidgetItem(QStringList{"Type: 0 (Echo (ping) reply"}) :
                         new QTreeWidgetItem(QStringList{"Type: 8 (Echo (pint) request)"});

        char code_info[20];
        sprintf(code_info, "Code: %d", icmp_header.code);
        auto code_item = new QTreeWidgetItem(QStringList{code_info});

        char checksum_info[40];
        sprintf(checksum_info, "Checksum: 0x%04x", icmp_header.checksum);
        auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

        char ident_be_info[50], ident_le_info[50];
        sprintf(ident_be_info, "Identifier (BE): %d (0x%04x)",
                htons(echo_data.identifier), htons(echo_data.identifier)
        );
        sprintf(ident_le_info, "Identifier (LE): %d (0x%04x)",
                echo_data.identifier, echo_data.identifier
        );
        auto ident_be_item = new QTreeWidgetItem(QStringList{ident_be_info});
        auto ident_le_item = new QTreeWidgetItem(QStringList{ident_le_info});

        char seq_num_be_info[50], seq_num_le_info[50];
        sprintf(seq_num_be_info, "Sequence Number (BE): %d (0x%04x)",
                htons(echo_data.seq_num), htons(echo_data.seq_num)
        );
        sprintf(seq_num_le_info, "Sequence Number (LE): %d (0x%04x)",
                echo_data.seq_num, echo_data.seq_num
        );
        auto seq_num_be_item = new QTreeWidgetItem(QStringList{seq_num_be_info});
        auto seq_num_le_item = new QTreeWidgetItem(QStringList{seq_num_le_info});

        top_item->addChildren(QList<QTreeWidgetItem *>{
                type_item, code_item, checksum_item, ident_be_item, ident_le_item,
                seq_num_be_item, seq_num_le_item
        });

        uint32_t data_length = ParsedPacket::packet_length - EthernetPacket::offset - IPV4Packet::offset - 8;
        if (data_length > 0) {
            char data_top_info[20];
            sprintf(data_top_info, "Data (%d bytes)", data_length);
            auto data_top_item = new QTreeWidgetItem(QStringList{data_top_info});

            char data_length_info[20];
            sprintf(data_length_info, "[Length: %d]", data_length);
            auto data_length_item = new QTreeWidgetItem(QStringList{data_length_info});
            data_top_item->addChildren(QList<QTreeWidgetItem *>{data_length_item});
            top_item->addChild(data_top_item);
        }
    } else if (icmp_header.type == 11) {
        auto type_item = new QTreeWidgetItem(QStringList{"Type: 11 (Time-to-live exceeded)"});

        char code_info[20];
        sprintf(code_info, "Code: %d", icmp_header.code);
        auto code_item = new QTreeWidgetItem(QStringList{code_info});

        char checksum_info[40];
        sprintf(checksum_info, "Checksum: 0x%04x", icmp_header.checksum);
        auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

        auto unused_item = new QTreeWidgetItem(QStringList{"Unused: 00000000"});

        top_item->addChildren(QList<QTreeWidgetItem *>{
                type_item, code_item, checksum_item, unused_item
        });
    }

    widget->addTopLevelItem(top_item);
}

void ICMPPacket::get_info(char *str) {
    switch (icmp_header.type) {
        case 0:
            sprintf(str, "Echo (ping) reply    id=0x%04x, seq=%d/%d, ttl=%d",
                    htons(echo_data.identifier), htons(echo_data.seq_num), echo_data.seq_num,
                    IPV4Packet::ipv4_header.ttl
            );
            break;
        case 8:
            sprintf(str, "Echo (ping) request  id=0x%04x, seq=%d/%d, ttl=%d",
                    htons(echo_data.identifier), htons(echo_data.seq_num), echo_data.seq_num,
                    IPV4Packet::ipv4_header.ttl
            );
            break;
        case 11:
            if (icmp_header.code == 0)
                sprintf(str, "Time-to-live exceeded (Time to live exceeded in transit)");
            break;
        default:
            sprintf(str, "Unresolved type %d", icmp_header.type);
    }
}

void ICMPPacket::get_protocol(char *str) {
    sprintf(str, "ICMP");
}

bool ICMPPacket::is_tcp() {
    return false;
}

bool ICMPPacket::is_udp() {
    return false;
}

bool ICMPPacket::is_icmp() {
    return true;
}

bool ICMPPacket::is_icmpv6() {
    return false;
}

bool ICMPPacket::is_http() {
    return false;
}

bool ICMPPacket::is_tls() {
    return false;
}

// ------------------------------ICMPV6Packet------------------------------

ICMPV6Packet::ICMPV6Packet(const u_char *data, uint32_t length) : EthernetPacket(data, length),
                                                                  IPV6Packet(data, length) {
    icmpv6_header = *(ICMPV6Header *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset);
    switch (icmpv6_header.type) {
        case 128:
        case 129:
            // echo
            echo_data = *(Echo *) (ICMPV6Header *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset +
                                                    4);
            echo_data.data = ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset + 8;
            break;
        case 130:
        case 131:
        case 132:
            multicast_data = *(Multicast *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset + 4);
            break;
        case 135:
            // neighbor solicitation
            s135 = *(T135 *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset + 4);
            break;
        case 136:
            s136 = *(T136 *) (ParsedPacket::data + EthernetPacket::offset + IPV6Packet::offset + 4);
            break;
    }
}

void ICMPV6Packet::fill(QTreeWidget *widget) {
    IPV6Packet::fill(widget);

    auto top_item = new QTreeWidgetItem(QStringList{"Internet Control Message Protocol v6"});

    char type_info[40];
    switch (icmpv6_header.type) {
        case 130:
            sprintf(type_info, "Type: Multicast Listener Query (130)");
            break;
        case 131:
            sprintf(type_info, "Type: Multicast Listener Report (131)");
            break;
        case 132:
            sprintf(type_info, "Type: Multicast Listener Done (132)");
            break;
        case 135:
            sprintf(type_info, "Type: Neighbor Solicitation (135)");
            break;
        case 136:
            sprintf(type_info, "Type: Neighbor Advertisement (136)");
            break;
        default:
            sprintf(type_info, "Type: Unresolved type (%d)", icmpv6_header.type);
    }
    auto type_item = new QTreeWidgetItem(QStringList{type_info});

    char code_info[15];
    sprintf(code_info, "Code: %d", icmpv6_header.code);
    auto code_item = new QTreeWidgetItem(QStringList{code_info});

    char checksum_info[30];
    sprintf(checksum_info, "Checksum: 0x%04x", icmpv6_header.checksum);
    auto checksum_item = new QTreeWidgetItem(QStringList{checksum_info});

    top_item->addChildren(QList<QTreeWidgetItem *>{type_item, code_item, checksum_item});

    switch (icmpv6_header.type) {
        case 130:
            break;
        case 131:
            break;
        case 132:
            break;
        case 135: {
            auto rsv_item = new QTreeWidgetItem(QStringList{"Reserved: 00000000"});
            char addr_info[60] = "Target Address: ";
            inet_ntop(AF_INET6, &s135.target_addr, addr_info + 16, 43);
            auto addr_item = new QTreeWidgetItem(QStringList{addr_info});
            top_item->addChildren(QList<QTreeWidgetItem *>{rsv_item, addr_item});
            if (ParsedPacket::packet_length > EthernetPacket::offset + IPV6Packet::offset + 24) {
                // has option
                char option_info[80];
                sprintf(option_info, "ICMPv6 Option (Source link-layer address : %02x:%02x:%02x:%02x:%02x:%02x)",
                        s135.option[2], s135.option[3], s135.option[4], s135.option[5], s135.option[6], s135.option[7]
                );
                top_item->addChild(new QTreeWidgetItem(QStringList{option_info}));
            }
            break;
        }
        case 136: {
            break;
        }
    }

    widget->addTopLevelItem(top_item);
}

void ICMPV6Packet::get_info(char *str) {
    char addr6[45];
    switch (icmpv6_header.type) {
        case 130:
            sprintf(str, "Multicast Listener Query");
            break;
        case 131:
            sprintf(str, "Multicast Listener Report");
            break;
        case 132:
            sprintf(str, "Multicast Listener Done");
            break;
        case 135:
            inet_ntop(AF_INET6, &s135.target_addr, addr6, 45);
            if (ParsedPacket::packet_length > EthernetPacket::offset + IPV6Packet::offset + 24) // has option
                sprintf(str, "Neighbor Solicitation for %s from %02x:%02x:%02x:%02x:%02x:%02x",
                        addr6, s135.option[2], s135.option[3], s135.option[4], s135.option[5],
                        s135.option[6], s135.option[7]
                );
            else
                sprintf(str, "Neighbor Solicitation for %s", addr6);
            break;
        case 136: {
            inet_ntop(AF_INET6, &s136.target_addr, addr6, 45);
            std::string flags = " (";
            bool is_first = true;
            if (s136.rso_rsv & 0b10000000) {
                flags += "rtr";
                is_first = false;
            }
            if (s136.rso_rsv & 0b01000000) {
                if (is_first) {
                    flags += "sol";
                    is_first = false;
                } else flags += ", sol";
            }
            if (s136.rso_rsv & 0b00100000) {
                if (is_first) flags += "ovr";
                else flags += ", ovr";
            }
            flags += ")";
            sprintf(str, "Neighbor Advertisement %s%s", addr6, flags.c_str());
            break;
        }
        default:
            sprintf(str, "Unresolved type: %d", icmpv6_header.type);
            break;
    }
}

void ICMPV6Packet::get_protocol(char *str) {
    sprintf(str, "ICMPv6");
}

bool ICMPV6Packet::is_tcp() {
    return false;
}

bool ICMPV6Packet::is_udp() {
    return false;
}

bool ICMPV6Packet::is_icmp() {
    return false;
}

bool ICMPV6Packet::is_icmpv6() {
    return true;
}

bool ICMPV6Packet::is_http() {
    return false;
}

bool ICMPV6Packet::is_tls() {
    return false;
}

ParsedPacket *parse(const u_char *data, uint32_t length) {
    uint16_t eth_protocol = EthernetPacket::parse_protocol(data);
    ParsedPacket *packet = nullptr;
    try {
        switch (eth_protocol) {
            case ETH_IPV4: {
                uint8_t ipv4_protocol = IPV4Packet::parse_protocol(data);
                switch (ipv4_protocol) {
                    case IPPROTO_TCP: {
                        auto tcp_packet = new TCPPacket(data, length);
                        if (tcp_packet->detect_tls()) packet = new TLSPacket(data, length);
                        else if (tcp_packet->detect_http()) packet = new HTTPPacket(data, length);
                        else packet = tcp_packet;
                        break;
                    }
                    case IPPROTO_UDP: {
                        packet = new UDPPacket(data, length);
                        break;
                    }
                    case IPPROTO_ICMP: {
                        packet = new ICMPPacket(data, length);
                        break;
                    }
                }
                break;
            }
            case ETH_IPV6: {
                uint8_t ipv6_protocol = IPV6Packet::parse_protocol(data);
                switch (ipv6_protocol) {
                    case IPPROTO_TCP: {
                        auto tcp_packet = new TCPPacket(data, length);
                        if (tcp_packet->detect_tls()) packet = new TLSPacket(data, length);
                        else if (tcp_packet->detect_http()) packet = new HTTPPacket(data, length);
                        else packet = tcp_packet;
                        break;
                    }
                    case IPPROTO_UDP: {
                        packet = new UDPPacket(data, length);
                        break;
                    }
                    case IPPROTO_ICMPV6: {
                        packet = new ICMPV6Packet(data, length);
                        break;
                    }
                }
                break;
            }
        }
    }
    catch (...) {
        qDebug() << "error";
    }
    return packet;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *pktheader, const u_char *pkt_data) {
    auto mainwindow = (sniffer_mainwindow *) param;
    if (pktheader->caplen == pktheader->len) {
        auto packet = parse(pkt_data, pktheader->len);
        if (packet != nullptr) emit mainwindow->packet_table_widget_packet_received(packet, pktheader->ts);
    }
}

HTTPPacket::HTTPPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length), TCPPacket(data, length) {}

void HTTPPacket::get_info(char *str) {
    uint32_t index = TCPPacket::total_offset;
    for (; data[index] != '\n'; index++) {
        str[index - TCPPacket::total_offset] = data[index];
    }
    str[index - TCPPacket::total_offset] = '\0';
}

void HTTPPacket::fill(QTreeWidget *widget) {
    TCPPacket::fill(widget);
    auto top_item = new QTreeWidgetItem(QStringList{"Hypertext Transfer Protocol"});
    char content[70];
    uint32_t index = TCPPacket::total_offset;
    for (; data[index] != '\n'; index++) {
        content[index - TCPPacket::total_offset] = data[index];
    }
    content[index - TCPPacket::total_offset] = '\0';
    auto content_item = new QTreeWidgetItem(QStringList{content});
    top_item->addChild(content_item);
    widget->addTopLevelItem(top_item);
}

void HTTPPacket::get_protocol(char *str) {
    sprintf(str, "HTTP");
}

bool HTTPPacket::is_http() {
    return true;
}

TLSPacket::TLSPacket(const u_char *data, uint32_t length) : EthernetPacket(data, length), TCPPacket(data, length) {
    tls_header = *(TLSHeader *) (ParsedPacket::data + TCPPacket::total_offset);
}

void TLSPacket::get_info(char *str) {
    switch (tls_header.type) {
        case 20:
            sprintf(str, "ChangeCipherSpec");
            break;
        case 21:
            sprintf(str, "Alert");
            break;
        case 22:
            sprintf(str, "HandShake");
            break;
        case 23:
            sprintf(str, "Application");
            break;
        case 24:
            sprintf(str, "HeartBeat");
            break;
    }
}

void TLSPacket::fill(QTreeWidget *widget) {
    TCPPacket::fill(widget);

    auto top_item = new QTreeWidgetItem(QStringList{"Transport Layer Security"});

    char intro_info[40];
    sprintf(intro_info, "TLSv1.%d Record Layer", tls_header.version_minor == 0x01 ? 0 : 2);
    auto intro_item = new QTreeWidgetItem(QStringList{intro_info});

    char type_info[40];
    switch (tls_header.type) {
        case 20:
            sprintf(type_info, "ChangeCipherSpec (20)");
            break;
        case 21:
            sprintf(type_info, "Alert (21)");
            break;
        case 22:
            sprintf(type_info, "HandShake (22)");
            break;
        case 23:
            sprintf(type_info, "Application (23)");
            break;
        case 24:
            sprintf(type_info, "HeartBeat (24)");
            break;
    }
    auto type_item = new QTreeWidgetItem(QStringList{type_info});

    char version_info[40];
    sprintf(version_info, "Version: TLS 1.%d (0x%04x)", tls_header.version_minor == 0x01 ? 0 : 2,
            (uint16_t) tls_header.version_major << 8 | (uint16_t) tls_header.version_minor);
    auto version_item = new QTreeWidgetItem(QStringList{version_info});

    char length_info[40];
    sprintf(length_info, "Length: %d", ntohs(tls_header.length));
    auto length_item = new QTreeWidgetItem(QStringList{length_info});

    intro_item->addChildren(QList<QTreeWidgetItem *>{type_item, version_item, length_item});
    top_item->addChild(intro_item);
    widget->addTopLevelItem(top_item);
}

void TLSPacket::get_protocol(char *str) {
    sprintf(str, "TLS");
}

bool TLSPacket::is_tls() {
    return true;
}
