//
// Created by FlagerLee on 2023/3/18.
//

#ifndef SNIFFER_PACKET_TABLE_WIDGET_H
#define SNIFFER_PACKET_TABLE_WIDGET_H

#include <QTableWidget>
#include <vector>
#include "packet.h"

class PacketTableWidget: public QTableWidget {
    Q_OBJECT
public:
    PacketTableWidget();
    ~PacketTableWidget() override =default;

private:
    std::vector<Packet> packets;
    int index;
    timeval start_time;

signals:
    void packet_received(Packet);

public slots:
    void on_packet_received(Packet packet);
};

#endif //SNIFFER_PACKET_TABLE_WIDGET_H
