cmake_minimum_required(VERSION 3.17)
project(BLE_SC)

set(CMAKE_CXX_STANDARD 14)

include_directories("/home/itemqq/Desktop/Sniffer_Linux_1.1.0/lib/linux64/")
link_directories("/home/itemqq/Desktop/Sniffer_Linux_1.1.0/lib/linux64/")
set(EXTRA_LIBS ble_sniffer_driver usb-1.0)

aux_source_directory(. DIR_SRCS)
add_executable(BLE_SC ${DIR_SRCS})
target_link_libraries(BLE_SC ${EXTRA_LIBS})