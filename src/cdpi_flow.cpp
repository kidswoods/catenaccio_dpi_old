#include "cdpi_flow.hpp"

#include <arpa/inet.h>

#include <string.h>

#include <boost/bind.hpp>
#include <boost/regex.hpp>

const uint32_t MAX_WINDOW_SIZE = 65535;

static const char *regex_http_req = "^[A-Z] .? HTTP/(1.0|1.1)\r\n([a-zA-Z][a-zA-Z-]?: .?\r\n)?";
static const char *regex_http_res = "^HTTP/(1.0|1.1) [0-9]{3} .?\r\n([a-zA-Z-][a-zA-Z]?: .?\r\n)?";

using namespace std;

cdpi_flow::cdpi_flow() : m_regex_http_req(regex_http_req),
                         m_regex_http_res(regex_http_res),
                         m_thread(boost::bind(&cdpi_flow::run, this))
{

}

bool
cdpi_flow::get_flow_id_ipv4(uint8_t *bytes, size_t len, cdpi_flow_id &flow_id,
                            cdpi_data_origin &origin, uint8_t **l4hdr)
{
    cdpi_flow_peer addr1, addr2;
    ip     *hdr = (ip*)bytes;
    tcphdr *tcph;
    udphdr *udph;

    if (hdr->ip_v != 4 || ntohs(hdr->ip_len) != len)
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
        if (id.m_id->l4_proto == IPPROTO_TCP) {
            input_tcp(bytes, len, (tcphdr*)l4hdr, id, origin);
        } else if (id.m_id->l4_proto == IPPROTO_UDP) {
            // TODO: UDP
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
    ip              *iph = (ip*)bytes;
    int              data_len;

    // TODO: checksum

    memcpy(data.get(), bytes, len);

    boost::mutex::scoped_lock lock(m_mutex);

    data_len = (int)len - (int)iph->ip_hl * 4 - (int)tcph->th_off * 4;

#ifdef DEBUG
    cout << "flags = ";
    if (tcph->th_flags & TH_SYN)
        cout << "S";
    if (tcph->th_flags & TH_ACK)
        cout << "A";
    if (tcph->th_flags & TH_FIN)
        cout << "F";
    if (tcph->th_flags & TH_RST)
        cout << "R";
    cout << endl;
#endif // DEBUG

    if (data_len < 0)
        return;

    it = m_tcp_flow.find(id);
    if (it == m_tcp_flow.end()) {
        ptr_tcp_flow p_flow(new tcp_flow);

        if (origin == FROM_ADDR1)
            flow_uni = &p_flow->m_flow1;
        else
            flow_uni = &p_flow->m_flow2;

        if (tcph->th_flags & TH_RST) {
            flow_uni->m_is_rst = true;
        } else {
            if (data_len > 0) {
                D((cout << "insert: seq = " << seq
                   << ", len = " << data_len << endl));

                flow_uni->m_packets[seq] = data;
                flow_uni->m_seq          = seq;
                flow_uni->m_min_seq      = seq;
            }
        }

        if (tcph->th_flags & TH_ACK)
            flow_uni->m_ack = ack;

        if (tcph->th_flags & TH_FIN)
            flow_uni->m_is_fin = true;

        flow_uni->m_flags = tcph->th_flags;
        flow_uni->m_time  = time(NULL);
        flow_uni->m_num++;

        // TODO: event, new flow

        m_tcp_flow[id] = p_flow;
    } else {
        if (origin == FROM_ADDR1)
            flow_uni = &it->second->m_flow1;
        else
            flow_uni = &it->second->m_flow2;

        if (tcph->th_flags & TH_RST) {
            flow_uni->m_is_rst = true;
        } else {
            if (flow_uni->m_time == 0) {
                if (data_len > 0) {
                    D((cout << "insert: seq = " << seq
                       << ", len = " << data_len << endl));

                    flow_uni->m_packets[seq] = data;
                    flow_uni->m_seq          = seq;
                    flow_uni->m_min_seq      = seq;
                }

                if (tcph->th_flags & TH_ACK)
                    flow_uni->m_ack = ack;
            } else {
                if (data_len > 0) {
                    if ((seq & 0xFFFF0000 == 0 &&
                         flow_uni->m_seq & 0xFFFF0000 == 0xFFFF0000) ||
                        seq > flow_uni->m_seq) {
                        flow_uni->m_seq = seq;
                    }

                    if (flow_uni->m_packets.find(seq) ==
                        flow_uni->m_packets.end()) {

                        if (! flow_uni->m_is_gaveup) {
                            if (flow_uni->m_packets.size() == 0)
                                flow_uni->m_min_seq = seq;

                            D((cout << "insert: seq = " << seq
                               << ", len = " << data_len << endl));

                            flow_uni->m_packets[seq] = data;
                        }
                    } else {
                        flow_uni->m_dup_num++;
                    }
                }

                if (tcph->th_flags & TH_ACK &&
                    ((ack & 0xFFFF0000 == 0 &&
                      flow_uni->m_ack & 0xFFFF0000 == 0xFFFF0000) ||
                     ack > flow_uni->m_ack)) {
                    flow_uni->m_ack = ack;
                }
            }
        }

        if (tcph->th_flags & TH_FIN)
            flow_uni->m_is_fin = true;

        flow_uni->m_flags = tcph->th_flags;
        flow_uni->m_time  = time(NULL);
        flow_uni->m_num++;
    }

    id_dir q;

    q.m_id  = id;
    q.m_org = origin;

    m_inq.insert(q);
    m_condition.notify_one();
}

void
cdpi_flow::run()
{
    for (;;) {
        set<id_dir> inq;
        set<id_dir>::iterator it_inq;

        {
            boost::mutex::scoped_lock lock(m_mutex);

            while (m_inq.size() == 0) {
                m_condition.wait(lock);
            }

            // consume
            for (it_inq = m_inq.begin(); it_inq != m_inq.end(); ++it_inq) {
                uint8_t l4_proto = it_inq->m_id.m_id->l4_proto;

                if (l4_proto == IPPROTO_TCP) {
                    map<uint32_t, ptr_uint8_t>::iterator it_pkt;
                    map<id_dir, pkt_buf>::iterator       it_m_pkt;
                    tcp_flow_unidir *flow;

                    if (it_inq->m_org == FROM_ADDR1)
                        flow = &m_tcp_flow[it_inq->m_id]->m_flow1;
                    else
                        flow = &m_tcp_flow[it_inq->m_id]->m_flow2;

                    it_m_pkt = m_packets.find(*it_inq);
                    if (it_m_pkt == m_packets.end()) {
                        m_packets[*it_inq].m_buf.clear();
                        it_m_pkt = m_packets.find(*it_inq);
                    }

                    it_pkt = flow->m_packets.find(flow->m_min_seq);
                    while (it_pkt != flow->m_packets.end()) {
                        ip     *iph  = (ip*)it_pkt->second.get();
                        tcphdr *tcph = (tcphdr*)((uint8_t*)iph +
                                                 iph->ip_hl * 4);
                        uint32_t seq = it_pkt->first;
                        uint32_t len = ntohs(iph->ip_len) - iph->ip_hl * 4 -
                                       tcph->th_off * 4;

                        it_m_pkt->second.m_buf.push_back(it_pkt->second);
                        flow->m_packets.erase(seq);

                        D((cout << "consume: seq = " << seq << ", len = " << len << endl));

                        seq += len;
                        
                        flow->m_min_seq = seq;

                        it_pkt = flow->m_packets.find(seq);
                    }

                    if (flow->m_packets.size() > 0 &&
                        flow->m_seq - flow->m_min_seq > 0x00020000) {
                        flow->m_packets.clear();
                        flow->m_is_gaveup = true;
                    }

                    if (flow->m_proto)
                        it_inq->m_type = flow->m_proto->m_type;
                    else
                        it_inq->m_type = PROTO_NONE;

                    inq.insert(*it_inq);
                } else if (l4_proto == IPPROTO_UDP) {
                    // TODO: UDP
                }
            }

            m_inq.clear();
        }

        for (it_inq = inq.begin(); it_inq != inq.end(); ++it_inq) {
            if (it_inq->m_id.m_id->l4_proto == IPPROTO_TCP)
                input_tcp_l7(inq);
        }
    }
}

void
cdpi_flow::input_tcp_l7(set<id_dir> &inq)
{
    set<id_dir>::iterator it_inq;

    for (it_inq = inq.begin(); it_inq != inq.end(); ++it_inq) {
        if (it_inq->m_type == PROTO_NONE) {
            if (is_http_client(*it_inq)) {
                // TODO: event, detect http client
                init_http_client(*it_inq);
            } else if (is_http_server(*it_inq)) {
                // TODO: event, detect http server
                init_http_server(*it_inq);
            } else {
                map<id_dir, pkt_buf>::iterator it_pkt = m_packets.find(*it_inq);
                if (it_pkt->second.m_buf.size() > 32) {
                    m_packets.erase(*it_inq);

                    boost::mutex::scoped_lock lock(m_mutex);
                    tcp_flow_unidir *flow;

                    if (it_inq->m_org == FROM_ADDR1)
                        flow = &m_tcp_flow[it_inq->m_id]->m_flow1;
                    else
                        flow = &m_tcp_flow[it_inq->m_id]->m_flow2;

                    flow->m_is_gaveup = true;
                    flow->m_packets.clear();
                }

                goto skip_parse;
            }
        }

        // TODO: analyze L7
        //       remove connection when FIN or RST was recieved

    skip_parse:
        m_packets.erase(*it_inq);
    }
}

void
cdpi_flow::init_http_client(const id_dir &id)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<cdpi_flow_id_wrapper, ptr_tcp_flow>::iterator it_tcp;
    tcp_flow_unidir *flow;

    it_tcp = m_tcp_flow.find(id.m_id);

    if (id.m_org == FROM_ADDR1) {
        flow = &it_tcp->second->m_flow1;
    } else {
        flow = &it_tcp->second->m_flow2;
    }

    flow->m_proto = boost::shared_ptr<cdpi_protocols>(new cdpi_http);
    flow->m_proto->m_type = PROTO_HTTP_CLIENT;

    cdpi_http *p_http = dynamic_cast<cdpi_http*>(flow->m_proto.get());
    p_http->m_state = cdpi_http::HTTP_METHOD;
}

void
cdpi_flow::init_http_server(const id_dir &id)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<cdpi_flow_id_wrapper, ptr_tcp_flow>::iterator it_tcp;
    tcp_flow_unidir *server, *client;

    it_tcp = m_tcp_flow.find(id.m_id);

    if (id.m_org == FROM_ADDR1) {
        server = &it_tcp->second->m_flow1;
        client = &it_tcp->second->m_flow2;
    } else {
        server = &it_tcp->second->m_flow2;
        client = &it_tcp->second->m_flow1;
    }

    server->m_proto = boost::shared_ptr<cdpi_protocols>(new cdpi_http);
    server->m_proto->m_type = PROTO_HTTP_SERVER;

    cdpi_http *p_http = dynamic_cast<cdpi_http*>(server->m_proto.get());
    p_http->m_state = cdpi_http::HTTP_RESPONSE;

    if (! client->m_proto || client->m_proto->m_type != PROTO_HTTP_CLIENT) {
        cdpi_flow_peer *peer_src, *peer_dst;
        char addr_src[32], addr_dst[32];

        if (id.m_org == FROM_ADDR1) {
            peer_src = &id.m_id.m_id->addr1;
            peer_dst = &id.m_id.m_id->addr2;
        } else {
            peer_src = &id.m_id.m_id->addr2;
            peer_dst = &id.m_id.m_id->addr1;
        }

        inet_ntop(id.m_id.m_id->l3_proto, &peer_src->l3_addr,
                  addr_src, sizeof(addr_src));
        inet_ntop(id.m_id.m_id->l3_proto, &peer_dst->l3_addr,
                  addr_dst, sizeof(addr_dst));

        cout << "warning: " << addr_src << ":" << ntohs(peer_src->l4_port)
             << " is a http server, but the peer(" << addr_dst << ":"
             << ntohs(peer_dst->l4_port) << ") isn't an HTTP client" << endl;
    }
}

bool
cdpi_flow::is_http_client(const id_dir &id)
{
    map<id_dir, pkt_buf>::iterator it = m_packets.find(id);
    ip     *iph  = (ip*)it->second.m_buf.begin()->get();
    tcphdr *tcph = (tcphdr*)((uint8_t*)iph + iph->ip_hl * 4);
    int     hlen = iph->ip_hl * 4 - tcph->th_off * 4;
    int     len  = iph->ip_len - hlen;
    string  data((char*)iph + hlen, (char*)iph + hlen + len);

    return boost::regex_match(data, m_regex_http_req);
}

bool
cdpi_flow::is_http_server(const id_dir &id)
{
    map<id_dir, pkt_buf>::iterator it = m_packets.find(id);
    ip     *iph  = (ip*)it->second.m_buf.begin()->get();
    tcphdr *tcph = (tcphdr*)((uint8_t*)iph + iph->ip_hl * 4);
    int     hlen = iph->ip_hl * 4 - tcph->th_off * 4;
    int     len  = iph->ip_len - hlen;
    string  data((char*)iph + hlen, (char*)iph + hlen + len);

    return boost::regex_match(data, m_regex_http_req);
}

bool
cdpi_flow::is_tls_1_0(id_dir &id)
{
    // TODO
    return false;
}

int
cdpi_flow::read_buf(const id_dir &id, uint8_t *buf, int len)
{
    map<id_dir, pkt_buf>::iterator it_pkt;
    list<ptr_uint8_t>::iterator    it_buf;
    int pos;
    int readlen = 0;

    it_pkt = m_packets.find(id);
    if (it_pkt == m_packets.end())
        return 0;

    pos = it_pkt->second.m_pos;

    for (it_buf = it_pkt->second.m_buf.begin();
         it_buf != it_pkt->second.m_buf.end(); ++it_buf) {
        ip     *iph  = (ip*)it_buf->get();
        tcphdr *tcph = (tcphdr*)(it_buf->get() + iph->ip_hl * 4);
        int     datalen  = ntohs(iph->ip_len) - iph->ip_hl * 4 - tcph->th_off * 4;
        int     reqlen   = len - readlen;
        int     availlen = datalen - pos;
        int     cpylen;

        if (availlen <= reqlen) {
            cpylen = availlen;
        } else {
            cpylen = reqlen;
        }

        memcpy(buf, it_buf->get() + iph->ip_hl * 4 + tcph->th_off * 4 + pos,
               cpylen);

        readlen += cpylen;

        if (readlen == len)
            break;

        pos = 0;
    }

    return readlen;
}

int
cdpi_flow::skip_buf(const id_dir &id, int len)
{
    map<id_dir, pkt_buf>::iterator it_pkt;
    list<ptr_uint8_t>::iterator    it_buf;
    int readlen = 0;

    it_pkt = m_packets.find(id);
    if (it_pkt == m_packets.end())
        return 0;

    for (it_buf = it_pkt->second.m_buf.begin();
         it_buf != it_pkt->second.m_buf.end();) {
        ip     *iph  = (ip*)it_buf->get();
        tcphdr *tcph = (tcphdr*)(it_buf->get() + iph->ip_hl * 4);
        int     datalen  = ntohs(iph->ip_len) - iph->ip_hl * 4 - tcph->th_off * 4;
        int     reqlen   = len - readlen;
        int     availlen = datalen - it_pkt->second.m_pos;
        int     cpylen;

        if (availlen <= reqlen) {
            cpylen = availlen;
            it_pkt->second.m_pos = 0;
            it_pkt->second.m_buf.erase(++it_buf);
        } else {
            cpylen = reqlen;
            it_pkt->second.m_pos += reqlen;
        }

        readlen += cpylen;

        if (readlen == len)
            break;
    }

    return readlen;
}
