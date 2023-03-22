//
// Created by FlagerLee on 2023/3/17.
//

// You may need to build the project (run Qt uic code generator) to get "ui_sniffer_mainwindow.h" resolved

#include "ui/sniffer_mainwindow.h"
#include "ui/packet_table_widget.h"
#include "ui_sniffer_mainwindow.h"
#include "sniffer.h"
#include <QListWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QLayout>

sniffer_mainwindow::sniffer_mainwindow(QWidget *parent) :
        QMainWindow(parent), ui(new Ui::sniffer_mainwindow) {
    ui->setupUi(this);
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
    packet_table_widget->setObjectName("packet_table_widget");
    sniff_layout->addWidget(packet_table_widget);
    // display meta info
    auto meta_info_widget = new QTreeWidget();
    meta_info_widget->setObjectName("meta_info_widget");
    sniff_layout->addWidget(meta_info_widget);
    this->sniff_central->setLayout(sniff_layout);

    // connection
    connect(this, &sniffer_mainwindow::packet_table_widget_packet_received, packet_table_widget, &PacketTableWidget::on_packet_received, Qt::DirectConnection);
}

sniffer_mainwindow::~sniffer_mainwindow() {
    delete ui;
}

void sniffer_mainwindow::set_adapter_list() {
    auto adapter_widget = new QListWidget();
    adaptors_info = getAllAdapters();
    for(auto info: adaptors_info) {
        adapter_widget->addItem(QString::fromLocal8Bit(info.description.c_str()));
    }
    this->centralWidget()->layout()->addWidget(adapter_widget);
    connect(adapter_widget, &QListWidget::doubleClicked, this, &sniffer_mainwindow::adapter_chosen);
}

void sniffer_mainwindow::closeEvent(QCloseEvent *) {
    if(sniff_thread.joinable()) {
        pcap_breakloop(adapter_fp);
    }
}

void sniffer_mainwindow::adapter_chosen(const QModelIndex &index) {
    auto adapters = getAllAdapters();
    adapter_fp = pcap_open_live(adaptors_info[index.row()].name.c_str(), 65535, 1, 1000, nullptr);
    sniff_thread = startSniffing(adapter_fp, packet_handler, SIGNAL_NAME::PACKET_TABLE_WIDGET_PACKET_RECEIVED, this);
    this->setCentralWidget(sniff_central);
}
