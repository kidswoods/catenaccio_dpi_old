#include "cdpi_pcap.hpp"

#include "ethernet.h"
#include "ip.h"

#include <pcap.h>
#include <string.h>

#include <arpa/inet.h>

#include <netinet/ip6.h>

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
    flow_id id;
    uint8_t proto;
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

    if (handle == NULL) {
        cerr << "Couldn't open device " << m_dev << ": " << errbuf << endl;
        return;
    }

    m_dl_type = pcap_datalink(handle);

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

bool
cdpi_pcap::get_flow_id(const uint8_t *ip_hdr, uint8_t proto, flow_id &id)
{
    char src[512], dst[512];

    memset(&id, 0, sizeof(id));

    switch (proto) {
    case IPPROTO_IP: {
        const ip *hdr = (const ip*)ip_hdr;

        if (hdr->ip_v != 4)
            return false;

        id.l3_proto   = IPPROTO_IP;
        id.l3_src.b32 = hdr->ip_src.s_addr;
        id.l3_dst.b32 = hdr->ip_dst.s_addr;

        inet_ntop(PF_INET, &hdr->ip_src, src, sizeof(src));
        inet_ntop(PF_INET, &hdr->ip_dst, dst, sizeof(dst));

        cout << "IPv4: src = " << src << ", dst = " << dst << endl;

        switch (hdr->ip_p) {
        case IPPROTO_TCP:
            id.l4_proto = IPPROTO_TCP;
            break;
        case IPPROTO_UDP:
            id.l4_proto = IPPROTO_UDP;
            break;
        default:
            return true;
        }

        // TODO: read port numbers

        break;
    }
    case IPPROTO_IPV6: {
        const ip6_hdr *hdr = (const ip6_hdr*)ip_hdr;

        if ((hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
            return false;

        id.l3_proto = IPPROTO_IPV6;
        memcpy(id.l3_src.b128, &hdr->ip6_src, sizeof(id.l3_src.b128));
        memcpy(id.l3_dst.b128, &hdr->ip6_dst, sizeof(id.l3_dst.b128));

        inet_ntop(PF_INET6, &hdr->ip6_src, src, sizeof(src));
        inet_ntop(PF_INET6, &hdr->ip6_dst, dst, sizeof(dst));

        cout << "IPv6: src = " << src << ", dst = " << dst << endl;

        // TODO: handle extended header

        break;
    }
    }

    return true;
}

const uint8_t *
cdpi_pcap::get_ip_hdr(const uint8_t *bytes, uint32_t len, uint8_t &proto)
{
    const uint8_t *ip_hdr = NULL;

    switch (m_dl_type) {
    case DLT_EN10MB: {
        if (len < sizeof(ether_header))
            break;

        const ether_header *ehdr = (const ether_header*)bytes;


        switch (ntohs(ehdr->ether_type)) {
        case ETHERTYPE_IP:
            proto  = IPPROTO_IP;
            ip_hdr = bytes + sizeof(ether_header);
            break;
        case ETHERTYPE_IPV6:
            proto  = IPPROTO_IPV6;
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
