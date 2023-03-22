//
// Created by FlagerLee on 2023/3/18.
//

#include "ui/sniffer_mainwindow.h"
#include "packet.h"
#include <QDebug>
#include <algorithm>

Packet::Packet() {
}

Packet::~Packet() {
}

struct SignalInfo {
    SIGNAL_NAME name;
    sniffer_mainwindow *mainwindow;
};

void packet_handler(u_char *param, const struct pcap_pkthdr *pktheader, const u_char *pkt_data) {
    // get QT handler
    auto signal_info = (SignalInfo *) param;

    // deal with packet
    Packet packet;
    if(pktheader->caplen == pktheader->len) {
        // length
        packet.length = pktheader->len;
        // time
        packet.recv_time = pktheader->ts;
        // addr & protocol
        auto ethernet = (EthernetHeader *) pkt_data;
        if (ntohs(ethernet->eth_type) == ETH_IPV4) {
            auto header = (IPV4Header *) (pkt_data + ETH_HEADER_LEN);
            packet.src_addr = header->src_addr;
            packet.dst_addr = header->dst_addr;
            packet.protocol = header->protocol;
            packet.ip_type = IPV4_TYPE;
        } else if (ntohs(ethernet->eth_type) == ETH_IPV6) {
            auto header = (IPV6Header *) (pkt_data + ETH_HEADER_LEN);
            packet.src_addr6 = header->src_addr;
            packet.dst_addr6 = header->dst_addr;
            // only icmpv6 now
            if (header->next_header == IPPROTO_ICMPV6) packet.protocol = IPPROTO_ICMPV6;
            else packet.protocol = IPPROTO_RAW;
            packet.ip_type = IPV6_TYPE;
        }
        std::copy_n(pkt_data, packet.length, packet.packet_data.begin());
        //memcpy(packet.packet_data, pkt_data, packet.length);
        switch (signal_info->name) {
            case PACKET_TABLE_WIDGET_PACKET_RECEIVED:
                emit signal_info->mainwindow->packet_table_widget_packet_received(packet);
                break;
        }
    }

}