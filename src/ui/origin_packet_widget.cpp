//
// Created by FlagerLee on 2023/3/25.
//

#include "ui/origin_packet_widget.h"
#include <QHeaderView>

OriginPacketWidget::OriginPacketWidget() {
    this->horizontalHeader()->setVisible(false);
    this->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    this->setEditTriggers(QAbstractItemView::NoEditTriggers);
    this->setColumnCount(3);
    this->setFont(QFont("Source Code Pro", 9));
    this->setColumnWidth(0, 170);
    this->setColumnWidth(1, 170);
    this->setColumnWidth(2, 200);
    this->setShowGrid(false);
}

void OriginPacketWidget::show_packet(ParsedPacket *packet) {
    this->clear();
    packet->fill_table(this);
}
