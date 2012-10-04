#include "cdpi_pcap.hpp"

#include "ethernet.h"
#include "ip.h"

#include <pcap.h>

#include <arpa/inet.h>

#include <iostream>

using namespace std;

void
pcap_callback(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    cdpi_pcap *pcap = (cdpi_pcap*)user;

    pcap->callback(h, bytes);
}

void
cdpi_pcap::callback(const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    flow_id  id;
    L3_proto proto;
    const uint8_t *ip_hdr = get_ip_hdr(bytes, h->caplen, proto);

    if (ip_hdr == NULL)
        return;

    get_flow_id(ip_hdr, proto, id);
}

void
cdpi_pcap::set_dev(std::string dev)
{
    m_dev = dev;
}

void
cdpi_pcap::run()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (m_dev == "") {
        char *dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            cerr << "Couldn't find default device: " << errbuf << endl;
            return;
        }

        m_dev = dev;
    }

    cout << "start caputring " << m_dev << endl;

    handle = pcap_open_live(m_dev.c_str(), 1518, 1, 1000, errbuf);

    m_dl_type = pcap_datalink(handle);

    if (handle == NULL) {
        cerr << "Couldn't open device " << m_dev << ": " << errbuf << endl;
        return;
    }

    switch (pcap_loop(handle, -1, pcap_callback, (u_char*)this)) {
    case 0:
        break;
    case -1:
        cerr << "An error was encouterd while pcap_loop()" << endl;
        break;
    case -2:
        break;
    }
}

void
cdpi_pcap::get_flow_id(const uint8_t *ip_hdr, L3_proto proto, flow_id &id)
{
    switch (proto) {
    case IPv4: {
        const ip *hdr = (const ip*)ip_hdr;
        break;
    }
    case IPv6: {
        const ip *hdr = (const ip*)ip_hdr;
        break;
    }
    }
}

const uint8_t *
cdpi_pcap::get_ip_hdr(const uint8_t *bytes, uint32_t len, L3_proto &proto)
{
    const uint8_t *ip_hdr = NULL;

    switch (m_dl_type) {
    case DLT_EN10MB: {
        if (len < sizeof(ether_header))
            break;

        const ether_header *ehdr = (const ether_header*)bytes;


        switch (ntohs(ehdr->ether_type)) {
        case ETHERTYPE_IP:
            proto = IPv4;
            ip_hdr = bytes + sizeof(ether_header);
            break;
        case ETHERTYPE_IPV6:
            proto = IPv6;
            ip_hdr = bytes + sizeof(ether_header);
            break;
        default:
            break;
        }

        break;
    }
    case DLT_IEEE802_11:
        // TODO
    default:
        break;
    }

    return ip_hdr;
}
