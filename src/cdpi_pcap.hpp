#ifndef CDPI_PCAP_HPP
#define CDPI_PCAP_HPP

#include "cdpi_common.hpp"

#include <string>

class cdpi_pcap {
public:
    cdpi_pcap() {}
    virtual ~cdpi_pcap() {}

    void set_dev(std::string dev);
    void run();

    void callback(const struct pcap_pkthdr *h, const uint8_t *bytes);

private:
    enum L3_proto {
        IPv4,
        IPv6
    };

    std::string m_dev;
    int m_dl_type;

    void get_flow_id(const uint8_t *ip_hdr, L3_proto proto, flow_id &id);
    const uint8_t *get_ip_hdr(const uint8_t *bytes, uint32_t len,
                              L3_proto &proto);
};

#endif // CDPI_PCAP_HPP
