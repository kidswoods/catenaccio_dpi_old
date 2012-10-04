add_definitions(-g -O0 -Wall -DDEBUG)

add_executable(cattenacio_dpi cdpi_main.cpp cdpi_pcap.cpp)

target_link_libraries(cattenacio_dpi pcap)
