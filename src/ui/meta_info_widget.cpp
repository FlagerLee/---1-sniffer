//
// Created by FlagerLee on 2023/3/25.
//

#include "ui/meta_info_widget.h"

MetaInfoWidget::MetaInfoWidget() {
    this->setHeaderHidden(true);
    this->setFont(QFont("Source Code Pro", 9));
}

void MetaInfoWidget::show_packet(ParsedPacket *packet) {
    this->clear();
    packet->fill(this);
}