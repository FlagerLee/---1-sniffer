//
// Created by 13694 on 2023/3/16.
//

#ifndef SNIFFER_SNIFFER_H
#define SNIFFER_SNIFFER_H

#include <QMainWindow>
#include <vector>
#include <pcap.h>
#include <thread>
#include <string>

class Packet;

struct AdaptorInfo {
    std::string description;
    std::string name;
};

std::vector<AdaptorInfo> getAllAdapters();

int setFilter(pcap_t *fp, const char *filter, bpf_u_int32 net_mask);

std::thread startSniffing(pcap_t *fp, pcap_handler handler, QMainWindow *mainwindow);

void stopSniffing(pcap_t *fp);

#endif //SNIFFER_SNIFFER_H
