#include "cdpi_pcap.hpp"

int
main(int argc, char *argv[])
{
    cdpi_pcap pcap;

    if (argc > 1) {
        pcap.set_dev(argv[1]);
    }

    pcap.run();

    return 0;
}
