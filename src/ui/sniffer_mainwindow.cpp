//
// Created by FlagerLee on 2023/3/17.
//

// You may need to build the project (run Qt uic code generator) to get "ui_sniffer_mainwindow.h" resolved

#include "ui/sniffer_mainwindow.h"
#include "ui_sniffer_mainwindow.h"
#include "sniffer.h"
#include <QListWidget>
#include <QLayout>
#include <QToolBar>
#include <QComboBox>
#include <QLabel>

sniffer_mainwindow::sniffer_mainwindow(QWidget *parent) :
        QMainWindow(parent), ui(new Ui::sniffer_mainwindow) {
    adapter_fp = nullptr;

    // init actions
    auto start_action = new QAction(QIcon(":/icon/icons8-play-64.png"), QString::fromLocal8Bit("开始嗅探"), this);
    auto stop_action = new QAction(QIcon(":/icon/icons8-stop-64.png"), QString::fromLocal8Bit("停止嗅探"), this);

    start_action->setDisabled(true);
    stop_action->setDisabled(true);
    // set actions
    tool_bar = addToolBar("toolBar");
    tool_bar->addAction(start_action);
    tool_bar->addAction(stop_action);

    // init sniff widget
    this->sniff_central = new QWidget();
    auto sniff_layout = new QVBoxLayout();
    // adapter combobox
    adaptors_info = getAllAdapters();
    auto adapter_layout = new QHBoxLayout();
    auto adapter_combobox = new QComboBox();
    for(const auto& info: adaptors_info) {
        adapter_combobox->addItem(QString::fromLocal8Bit(info.description.c_str()));
    }
    adapter_combobox->setCurrentIndex(-1);
    adapter_combobox->setFixedWidth(400);
    adapter_layout->addWidget(adapter_combobox);
    adapter_layout->addWidget(new QLabel(QString::fromLocal8Bit("select adapter")));
    sniff_layout->addLayout(adapter_layout);
    // filter combobox
    auto filter_layout = new QHBoxLayout();
    auto filter_combobox = new QComboBox();
    filter_combobox->addItems(QStringList{
            "Clear Filter", "ARP", "TCP", "UDP", "ICMP", "ICMPv6", "HTTP", "TLS", "IPV4", "IPV6"
    });
    filter_combobox->setCurrentIndex(-1);
    filter_combobox->setFixedWidth(400);
    filter_layout->addWidget(filter_combobox);
    filter_layout->addWidget(new QLabel("select protocol"));
    sniff_layout->addLayout(filter_layout);

    // display packets received
    packet_table_widget = new PacketTableWidget();
    sniff_layout->addWidget(packet_table_widget);

    // display meta info and origin packet
    auto hlayout = new QHBoxLayout();
    meta_info_widget = new MetaInfoWidget();
    hlayout->addWidget(meta_info_widget);
    origin_packet_widget = new OriginPacketWidget();
    hlayout->addWidget(origin_packet_widget);

    sniff_layout->addLayout(hlayout);

    this->sniff_central->setLayout(sniff_layout);

    this->setCentralWidget(sniff_central);

    // connection
    connect(this, &sniffer_mainwindow::packet_table_widget_packet_received, packet_table_widget,
            &PacketTableWidget::on_packet_received, Qt::DirectConnection);
    connect(packet_table_widget, &PacketTableWidget::cellClicked, packet_table_widget,
            &PacketTableWidget::on_cell_clicked);
    connect(packet_table_widget, &PacketTableWidget::packet_chosen, meta_info_widget, &MetaInfoWidget::show_packet,
            Qt::DirectConnection);
    connect(packet_table_widget, &PacketTableWidget::packet_chosen, origin_packet_widget,
            &OriginPacketWidget::show_packet, Qt::DirectConnection);
    connect(start_action, &QAction::triggered, this, &sniffer_mainwindow::start_sniffing);
    connect(stop_action, &QAction::triggered, this, &sniffer_mainwindow::stop_sniffing);
    connect(adapter_combobox, &QComboBox::activated, this, &sniffer_mainwindow::adapter_chosen);
    connect(filter_combobox, &QComboBox::activated, this, &sniffer_mainwindow::filter_chosen);
    connect(this, &sniffer_mainwindow::filter_set, packet_table_widget, &PacketTableWidget::on_filter_set, Qt::DirectConnection);


    ui->setupUi(this);
}

sniffer_mainwindow::~sniffer_mainwindow() {
    delete ui;
}

void sniffer_mainwindow::closeEvent(QCloseEvent *) {
    if(sniff_thread.joinable()) {
        pcap_breakloop(adapter_fp);
        sniff_thread.detach();
    }
}

void sniffer_mainwindow::adapter_chosen(int index) {
    auto adapters = getAllAdapters();
    if(adapter_fp != nullptr) pcap_close(adapter_fp);
    adapter_fp = pcap_open_live(adaptors_info[index].name.c_str(), 65535, 1, 1000, nullptr);
    //setFilter(adapter_fp, "", 0xFFFFFF);
    this->setCentralWidget(sniff_central);
    QList<QAction *> actions = tool_bar->actions();
    actions[0]->setEnabled(true);
}

void sniffer_mainwindow::stop_sniffing() {
    if(sniff_thread.joinable()) {
        pcap_breakloop(adapter_fp);
        sniff_thread.detach();
    }
    QList<QAction *> actions = tool_bar->actions();
    actions[0]->setEnabled(true);
    actions[1]->setDisabled(true);
}

void sniffer_mainwindow::start_sniffing() {
    packet_table_widget->clear();
    meta_info_widget->clear();
    origin_packet_widget->clear();
    sniff_thread = startSniffing(adapter_fp, packet_handler, this);
    QList<QAction *> actions = tool_bar->actions();
    actions[0]->setDisabled(true);
    actions[1]->setEnabled(true);
}

void sniffer_mainwindow::filter_chosen(int index) {
    std::string filter_list[] = {
            "", "ARP", "TCP", "UDP", "ICMP", "ICMPv6", "HTTP", "TLS", "IPV4", "IPV6"
    };
    emit filter_set(std::vector<std::string>{filter_list[index]});
}
