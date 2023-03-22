//
// Created by FlagerLee on 2023/3/17.
//

#ifndef SNIFFER_SNIFFER_MAINWINDOW_H
#define SNIFFER_SNIFFER_MAINWINDOW_H

#include <QMainWindow>
#include <QModelIndex>
#include <pcap.h>
#include <thread>
#include "packet.h"
#include "sniffer.h"


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
    QWidget *start_central;
    QWidget *sniff_central;
    std::thread sniff_thread;
    pcap_t *adapter_fp;
    std::vector<AdaptorInfo> adaptors_info;

    void set_adapter_list();

signals:
    void packet_table_widget_packet_received(Packet);

public slots:
    void adapter_chosen(const QModelIndex& index);
};


#endif //SNIFFER_SNIFFER_MAINWINDOW_H
