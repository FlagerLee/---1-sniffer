//
// Created by FlagerLee on 2023/3/17.
//

// You may need to build the project (run Qt uic code generator) to get "ui_sniffer_mainwindow.h" resolved

#include "ui/sniffer_mainwindow.h"
#include "ui/packet_table_widget.h"
#include "ui/meta_info_widget.h"
#include "ui/origin_packet_widget.h"
#include "ui_sniffer_mainwindow.h"
#include "sniffer.h"
#include <QListWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLayout>

sniffer_mainwindow::sniffer_mainwindow(QWidget *parent) :
        QMainWindow(parent), ui(new Ui::sniffer_mainwindow) {
    this->start_central = new QWidget();
    this->setCentralWidget(start_central);
    auto layout = new QVBoxLayout();
    start_central->setLayout(layout);
    set_adapter_list();

    // init sniff widget
    this->sniff_central = new QWidget();
    auto sniff_layout = new QVBoxLayout();
    // display packets received
    auto packet_table_widget = new PacketTableWidget();
    sniff_layout->addWidget(packet_table_widget);

    // display meta info and origin packet
    auto hlayout = new QHBoxLayout();
    auto meta_info_widget = new MetaInfoWidget();
    hlayout->addWidget(meta_info_widget);
    auto origin_packet_widget = new OriginPacketWidget();
    hlayout->addWidget(origin_packet_widget);

    sniff_layout->addLayout(hlayout);

    this->sniff_central->setLayout(sniff_layout);

    // connection
    connect(this, &sniffer_mainwindow::packet_table_widget_packet_received, packet_table_widget,
            &PacketTableWidget::on_packet_received, Qt::DirectConnection);
    connect(packet_table_widget, &PacketTableWidget::cellClicked, packet_table_widget,
            &PacketTableWidget::on_cell_clicked);
    connect(packet_table_widget, &PacketTableWidget::packet_chosen, meta_info_widget, &MetaInfoWidget::show_packet,
            Qt::DirectConnection);
    connect(packet_table_widget, &PacketTableWidget::packet_chosen, origin_packet_widget,
            &OriginPacketWidget::show_packet, Qt::DirectConnection);


    ui->setupUi(this);
}

sniffer_mainwindow::~sniffer_mainwindow() {
    delete ui;
}

void sniffer_mainwindow::set_adapter_list() {
    auto adapter_widget = new QListWidget();
    adaptors_info = getAllAdapters();
    for (auto info: adaptors_info) {
        adapter_widget->addItem(QString::fromLocal8Bit(info.description.c_str()));
    }
    this->centralWidget()->layout()->addWidget(adapter_widget);
    connect(adapter_widget, &QListWidget::doubleClicked, this, &sniffer_mainwindow::adapter_chosen);
}

void sniffer_mainwindow::closeEvent(QCloseEvent *) {
    if (sniff_thread.joinable()) {
        pcap_breakloop(adapter_fp);
    }
}

void sniffer_mainwindow::adapter_chosen(const QModelIndex &index) {
    auto adapters = getAllAdapters();
    adapter_fp = pcap_open_live(adaptors_info[index.row()].name.c_str(), 65535, 1, 1000, nullptr);
    sniff_thread = startSniffing(adapter_fp, packet_handler, this);
    this->setCentralWidget(sniff_central);
}
