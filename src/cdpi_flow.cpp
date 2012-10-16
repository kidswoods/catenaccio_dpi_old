#include "cdpi_flow.hpp"

#include <string.h>

const uint32_t MAX_WINDOW_SIZE = 65535;

using namespace std;

bool
cdpi_flow::get_flow_id_ipv4(uint8_t *bytes, size_t len, cdpi_flow_id &flow_id,
                            cdpi_data_origin &origin, uint8_t **l4hdr)
{
    cdpi_flow_edge addr1, addr2;
    ip     *hdr = (ip*)*bytes;
    tcphdr *tcph;
    udphdr *udph;

    if (hdr->ip_v != 4)
        return false;

    memset(&flow_id, 0, sizeof(flow_id));

    flow_id.l3_proto = IPPROTO_IPV4;

    addr1.l3_addr.b32 = hdr->ip_src.s_addr;
    addr2.l3_addr.b32 = hdr->ip_dst.s_addr;

    switch (hdr->ip_p) {
    case IPPROTO_TCP:
        flow_id.l4_proto = IPPROTO_TCP;

        *l4hdr = bytes + hdr->ip_hl * 4;
        tcph   = (tcphdr*)*l4hdr;

        addr1.l4_port = ntohs(tcph->th_sport);
        addr2.l4_port = ntohs(tcph->th_dport);

        break;
    case IPPROTO_UDP:
        flow_id.l4_proto = IPPROTO_UDP;

        *l4hdr = bytes + hdr->ip_hl * 4;
        udph = (udphdr*)*l4hdr;

        addr1.l4_port = ntohs(udph->uh_sport);
        addr2.l4_port = ntohs(udph->uh_dport);

        break;
    default:
        flow_id.l4_proto = hdr->ip_p;
        break;
    }

    if (memcmp(&addr1, &addr2, sizeof(addr1)) < 0) {
        memcpy(&flow_id.addr1, &addr1, sizeof(addr1));
        memcpy(&flow_id.addr2, &addr2, sizeof(addr2));
        origin = FROM_ADDR1;
    } else {
        memcpy(&flow_id.addr1, &addr2, sizeof(addr2));
        memcpy(&flow_id.addr2, &addr1, sizeof(addr1));
        origin = FROM_ADDR2;
    }

    return true;
}

bool
cdpi_flow_id_wrapper::operator< (const cdpi_flow_id_wrapper &rhs) const
{
    if (memcmp(m_id.get(), rhs.m_id.get(), sizeof(cdpi_flow_id) < 0))
        return true;

    return false;
}

bool
cdpi_flow_id_wrapper::operator== (const cdpi_flow_id_wrapper &rhs) const
{
    if (memcmp(m_id.get(), rhs.m_id.get(), sizeof(*this) == 0))
        return true;

    return false;
}

void
cdpi_flow::input_ipv4(uint8_t *bytes, size_t len)
{
    cdpi_flow_id_wrapper id;
    cdpi_data_origin     origin;
    uint8_t *l4hdr;

    if (get_flow_id_ipv4(bytes, len, *id.m_id, origin, &l4hdr)) {
        // TODO:
        if (id.m_id->l4_proto == IPPROTO_TCP) {
            input_tcp(bytes, len, (tcphdr*)l4hdr, id, origin);
        } else if (id.m_id->l4_proto == IPPROTO_UDP) {
        }
    }
}

void
cdpi_flow::input_tcp(uint8_t *bytes, size_t len, tcphdr *tcph,
                     cdpi_flow_id_wrapper id, cdpi_data_origin origin)
{
    map<cdpi_flow_id_wrapper, ptr_tcp_flow>::iterator it;
    tcp_flow_unidir *flow_uni;
    ptr_uint8_t      data(new uint8_t[len]);
    uint32_t         seq = ntohl(tcph->th_seq);
    uint32_t         ack = ntohl(tcph->th_ack);

    // TODO: checksum

    memcpy(data.get(), bytes, len);

    it = m_tcp_flow.find(id);
    if (it == m_tcp_flow.end()) {
        ptr_tcp_flow p_flow(new tcp_flow);

        if (origin == FROM_ADDR1)
            flow_uni = &p_flow->m_flow1;
        else
            flow_uni = &p_flow->m_flow2;

        flow_uni->m_packets[seq] = data;
        flow_uni->m_flags        = tcph->th_flags;
        flow_uni->m_seq          = seq;
        flow_uni->m_ack          = ack;
        flow_uni->m_min_seq      = seq;
        flow_uni->m_time         = time(NULL);
        flow_uni->m_num++;

        m_tcp_flow[id] = p_flow;

        return;
    } else {
        if (origin == FROM_ADDR1)
            flow_uni = &it->second->m_flow1;
        else
            flow_uni = &it->second->m_flow2;

        if (flow_uni->m_time == 0) {
            flow_uni->m_packets[seq] = data;
            flow_uni->m_flags        = tcph->th_flags;
            flow_uni->m_seq          = seq;
            flow_uni->m_ack          = ack;
            flow_uni->m_min_seq      = seq;
            flow_uni->m_time         = time(NULL);
            flow_uni->m_num++;

            return;
        }

        if ((seq & 0xFFFF0000 == 0 &&
             flow_uni->m_seq & 0xFFFF0000 == 0xFFFF0000) ||
            seq > flow_uni->m_seq) {
            flow_uni->m_seq  = seq;
            flow_uni->m_ack  = ack;
        }

        if (flow_uni->m_packets.find(seq) == flow_uni->m_packets.end())
            flow_uni->m_packets[seq] = data;
        else
            flow_uni->m_dup_num++;

        flow_uni->m_time = time(NULL);
    }
}
