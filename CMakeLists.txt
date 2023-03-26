cmake_minimum_required(VERSION 3.24)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_PREFIX_PATH "D:/Qt/6.4.3/mingw_64/lib/cmake")

find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_subdirectory(src)

set(CPP_SRC
        main.cpp
        src/sniffer.cpp
        src/ui/sniffer_mainwindow.cpp
        src/ui/packet_table_widget.cpp src/protocol.cpp src/ui/meta_info_widget.cpp)
set(QRC_SRC
        resources/resource.qrc)
set(UI_SRC
        src/ui/sniffer_mainwindow.ui
        )
set(HEADERS
        include/sniffer.h
        include/packet_header.h)
set(QT_HEADERS
        include/ui/sniffer_mainwindow.h
        include/ui/packet_table_widget.h include/protocol.h include/ui/meta_info_widget.h include/ui/origin_packet_widget.h src/ui/origin_packet_widget.cpp)

add_executable(sniffer
        ${CPP_SRC}
        ${QRC_SRC}
        ${UI_SRC}
        ${HEADERS}
        ${QT_HEADERS}
        )

target_include_directories(sniffer PUBLIC
        npcap-1.13/Include
        include
        )
target_link_directories(sniffer PUBLIC
        npcap-1.13/Lib/x64
        )
target_link_libraries(sniffer
        Qt::Core
        Qt::Gui
        Qt::Widgets
        Packet
        wpcap
        ws2_32
        )

if (WIN32)
    set(DEBUG_SUFFIX)
    if (MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif ()
    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif ()
    endif ()
    if (EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms/")
    endif ()
    foreach (QT_LIB Core Gui Widgets)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach (QT_LIB)
endif ()
