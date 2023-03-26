//
// Created by FlagerLee on 2023/3/18.
//

#ifndef SNIFFER_PACKET_TABLE_WIDGET_H
#define SNIFFER_PACKET_TABLE_WIDGET_H

#include <QTableWidget>
#include <vector>
#include "protocol.h"

class PacketTableWidget : public QTableWidget {
Q_OBJECT
public:
    PacketTableWidget();

    ~PacketTableWidget();

    void clear();

private:
    std::vector<ParsedPacket *> packets;
    std::vector<std::string> filter;
    std::vector<timeval> tvs;
    int index;
    timeval start_time;

signals:

    void packet_chosen(ParsedPacket *packet);

public slots:

    void on_packet_received(ParsedPacket *packet, timeval tv);
    void on_cell_clicked(int row, int column);
    void on_filter_set(std::vector<std::string> filter);

};

#endif //SNIFFER_PACKET_TABLE_WIDGET_H
