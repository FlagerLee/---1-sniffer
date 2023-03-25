//
// Created by FlagerLee on 2023/3/25.
//

#ifndef SNIFFER_META_INFO_WIDGET_H
#define SNIFFER_META_INFO_WIDGET_H

#include <QTreeWidget>
#include "protocol.h"

class MetaInfoWidget: public QTreeWidget {
public:
    MetaInfoWidget();

public slots:
    void show_packet(ParsedPacket *packet);
};

#endif //SNIFFER_META_INFO_WIDGET_H
