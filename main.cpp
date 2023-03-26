#include <QApplication>
#include <QPushButton>
#include "sniffer.h"
#include <windows.h>
#include <iostream>
#include "ui/sniffer_mainwindow.h"


int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    sniffer_mainwindow mainwindow;
    mainwindow.show();
    return QApplication::exec();
}
