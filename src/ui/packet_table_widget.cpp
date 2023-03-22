//
// Created by FlagerLee on 2023/3/19.
//

#include "ui/packet_table_widget.h"
#include <QHeaderView>
#include "protocol.h"

#define IP_STR_LEN 40

// from glibc
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating @var{y}. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       @code{tv_usec} is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

void PacketTableWidget::on_packet_received(Packet packet) {
    if(start_time.tv_sec == 0 && start_time.tv_usec == 0) start_time = packet.recv_time;
    char *src_ip = new char[IP_STR_LEN];
    char *dst_ip = new char[IP_STR_LEN];
    if (packet.ip_type == IPV4_TYPE) {
        inet_ntop(AF_INET, &packet.src_addr, src_ip, IP_STR_LEN);
        inet_ntop(AF_INET, &packet.src_addr, dst_ip, IP_STR_LEN);
    } else if (packet.ip_type == IPV6_TYPE) {
        inet_ntop(AF_INET6, &packet.src_addr6, src_ip, IP_STR_LEN);
        inet_ntop(AF_INET6, &packet.src_addr6, dst_ip, IP_STR_LEN);
    }
    // insert row
    int row = this->rowCount();
    this->insertRow(row);
    // set NO.
    this->setItem(row, 0, new QTableWidgetItem(std::to_string(index++).c_str()));
    // set time
    char time_str[100];
    timeval time_since_start;
    timeval_subtract(&time_since_start, &packet.recv_time, &start_time);
    sprintf(time_str, "%ld.%06ld", time_since_start.tv_sec, time_since_start.tv_usec);
    this->setItem(row, 1, new QTableWidgetItem(time_str));
    // set source
    this->setItem(row, 2, new QTableWidgetItem(src_ip));
    // set destination
    this->setItem(row, 3, new QTableWidgetItem(dst_ip));
    // set protocol
    switch (packet.protocol) {
        case IPPROTO_ICMP:
            this->setItem(row, 4, new QTableWidgetItem("ICMP"));
            break;
        case IPPROTO_IGMP:
            this->setItem(row, 4, new QTableWidgetItem("IGMP"));
            break;
        case IPPROTO_TCP:
            this->setItem(row, 4, new QTableWidgetItem("TCP"));
            break;
        case IPPROTO_UDP:
            this->setItem(row, 4, new QTableWidgetItem("UDP"));
            break;
        case IPPROTO_ICMPV6:
            this->setItem(row, 4, new QTableWidgetItem("ICMPV6"));
            break;
        default:
            this->setItem(row, 4, new QTableWidgetItem((std::string("Unknown Protocol") + std::to_string((int)packet.protocol)).c_str()));
    }
    // set length
    this->setItem(row, 5, new QTableWidgetItem(std::to_string(packet.length).c_str()));
    // set info

    // add packet
    packets.emplace_back(packet);
}

PacketTableWidget::PacketTableWidget() : index(1) {
    this->setEditTriggers(QAbstractItemView::NoEditTriggers);
    this->setColumnCount(7);
    QStringList table_header = {
            "NO.",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info"
    };
    this->setHorizontalHeaderLabels(table_header);
    this->horizontalHeader()->setStretchLastSection(true);
    this->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

    start_time.tv_sec = 0;
    start_time.tv_usec = 0;
}
