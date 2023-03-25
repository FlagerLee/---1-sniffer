//
// Created by FlagerLee on 2023/3/19.
//

#include "ui/packet_table_widget.h"
#include <QHeaderView>
#include "protocol.h"

#define IP_STR_LEN 45

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

void PacketTableWidget::on_packet_received(ParsedPacket *packet, timeval tv) {
    if(start_time.tv_sec == 0 && start_time.tv_usec == 0) start_time = tv;
    char *src_ip = new char[IP_STR_LEN];
    char *dst_ip = new char[IP_STR_LEN];
    packet->get_src_addr(src_ip);
    packet->get_dst_addr(dst_ip);
    // insert row
    int row = this->rowCount();
    this->insertRow(row);
    // set NO.
    this->setItem(row, 0, new QTableWidgetItem(std::to_string(index++).c_str()));
    // set time
    char time_str[100];
    timeval time_since_start;
    timeval_subtract(&time_since_start, &tv, &start_time);
    sprintf(time_str, "%ld.%06ld", time_since_start.tv_sec, time_since_start.tv_usec);
    this->setItem(row, 1, new QTableWidgetItem(time_str));
    // set source
    this->setItem(row, 2, new QTableWidgetItem(src_ip));
    // set destination
    this->setItem(row, 3, new QTableWidgetItem(dst_ip));
    // set protocol
    char protocol_name[20];
    packet->get_protocol(protocol_name);
    this->setItem(row, 4, new QTableWidgetItem(protocol_name));
    // set length
    this->setItem(row, 5, new QTableWidgetItem(std::to_string(packet->packet_length).c_str()));
    // set info
    char info[200];
    packet->get_info(info);
    this->setItem(row, 6, new QTableWidgetItem(info));
    // set tree widget

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
    this->setSelectionBehavior(QTableWidget::SelectRows);
    this->verticalHeader()->setVisible(false);
    this->setShowGrid(false);
    this->setFont(QFont("Source Code Pro", 9));

    start_time.tv_sec = 0;
    start_time.tv_usec = 0;
}

PacketTableWidget::~PacketTableWidget() {
}

void PacketTableWidget::on_cell_clicked(int row, int column) {
    emit packet_chosen(packets[row]);
}
