//
// Created by FlagerLee on 2023/3/25.
//

#ifndef SNIFFER_ORIGIN_PACKET_WIDGET_H
#define SNIFFER_ORIGIN_PACKET_WIDGET_H

#include <QTableWidget>
#include "protocol.h"

class OriginPacketWidget : public QTableWidget {
public:

    OriginPacketWidget();

public slots:

    void show_packet(ParsedPacket *packet);
};

#endif //SNIFFER_ORIGIN_PACKET_WIDGET_H
