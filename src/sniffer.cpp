//
// Created by 13694 on 2023/3/16.
//

#include "ui/sniffer_mainwindow.h"
#include "sniffer.h"

using std::vector;

vector<AdaptorInfo> getAllAdapters() {
    pcap_if_t *allAdapters = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    vector<AdaptorInfo> adapters;

    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &allAdapters, errbuf) != -1) {
        for(auto ptr = allAdapters; ptr != nullptr; ptr = ptr->next) {
            adapters.push_back(AdaptorInfo{std::string(ptr->description), std::string(ptr->name)});
        }
    }

    pcap_freealldevs(allAdapters);
    return adapters;
}

int setFilter(pcap_t *fp, const char *filter, bpf_u_int32 net_mask) {
    if(filter == nullptr) return false;

    bpf_program code{};
    if(int res = pcap_compile(fp, &code, filter, 1, net_mask) < 0) {
        fprintf(stderr,"\nError compiling filter: %s\n", pcap_statustostr(res));
        return res;
    }
    if(int res = pcap_setfilter(fp, &code) < 0) {
        fprintf(stderr,"\nError setting the filter: %s\n", pcap_statustostr(res));
        return res;
    }
    return 0;
}

std::thread startSniffing(pcap_t *fp, pcap_handler handler, QMainWindow *mainwindow) {
    std::thread sniff_thread([](pcap_t *fp, pcap_handler handler, QMainWindow *mainwindow) {
        printf("Start Sniffing\n");
        int res = pcap_loop(fp, -1, handler, (u_char*)mainwindow);
        printf("Stop Sniffing\n");
    }, fp, handler, mainwindow);
    return sniff_thread;
}

void stopSniffing(pcap_t *fp) {
    pcap_breakloop(fp);
}