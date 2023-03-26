//
// Created by FlagerLee on 2023/3/17.
//

#ifndef SNIFFER_SNIFFER_MAINWINDOW_H
#define SNIFFER_SNIFFER_MAINWINDOW_H

#include <QMainWindow>
#include <QModelIndex>
#include <pcap.h>
#include <thread>
#include "protocol.h"
#include "sniffer.h"

#include "ui/packet_table_widget.h"
#include "ui/meta_info_widget.h"
#include "ui/origin_packet_widget.h"


QT_BEGIN_NAMESPACE
namespace Ui { class sniffer_mainwindow; }
QT_END_NAMESPACE

class sniffer_mainwindow : public QMainWindow {
Q_OBJECT

public:
    explicit sniffer_mainwindow(QWidget *parent = nullptr);

    ~sniffer_mainwindow() override;

protected:
    void closeEvent(QCloseEvent*) override;

private:
    Ui::sniffer_mainwindow *ui;
    QWidget *sniff_central;
    std::thread sniff_thread;
    pcap_t *adapter_fp;
    std::vector<AdaptorInfo> adaptors_info;
    QToolBar *tool_bar;

    PacketTableWidget *packet_table_widget;
    MetaInfoWidget *meta_info_widget;
    OriginPacketWidget *origin_packet_widget;

signals:
    void packet_table_widget_packet_received(ParsedPacket *, timeval);
    void filter_set(std::vector<std::string>);

public slots:
    void adapter_chosen(int index);
    void filter_chosen(int index);
    void stop_sniffing();
    void start_sniffing();
};


#endif //SNIFFER_SNIFFER_MAINWINDOW_H
