#ifndef CDPI_FLOW_HPP
#define CDPI_FLOW_HPP

#include "cdpi_common.hpp"

#include <time.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <list>
#include <map>
#include <set>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

struct cdpi_flow_peer {
    union {
        uint32_t b32;
        uint8_t  b128[16];
    } l3_addr;

    uint32_t l4_port;
};

struct cdpi_flow_id {
    // addr1 must be less than addr2
    cdpi_flow_peer addr1, addr2;
    uint8_t  l3_proto;
    uint8_t  l4_proto;
};

class cdpi_flow_id_wrapper {
public:
    cdpi_flow_id_wrapper() : m_id(new cdpi_flow_id) { }
    virtual ~cdpi_flow_id_wrapper() { }

    boost::shared_ptr<cdpi_flow_id> m_id;

    bool operator< (const cdpi_flow_id_wrapper &rhs) const;
    bool operator> (const cdpi_flow_id_wrapper &rhs) const
    {
        return rhs < *this;
    }
    bool operator== (const cdpi_flow_id_wrapper &rhs) const;
};

#define ipv4_addr1 addr1.l3_addr.b32
#define ipv4_addr2 addr2.l3_addr.b32
#define ipv6_addr1 addr1.l3_addr.b128
#define ipv6_addr2 addr2.l3_addr.b128
#define l4_port1 addr1.l4_port
#define l4_port2 addr2.l4_port

enum cdpi_data_origin {
    FROM_ADDR1,
    FROM_ADDR2
};

class tcp_flow_unidir {
public:
    std::map<uint32_t, ptr_uint8_t> m_packets;
    uint8_t  m_flags;
    uint32_t m_seq;
    uint32_t m_ack;
    uint32_t m_min_seq;
    time_t   m_time;
    uint64_t m_chksum_err;
    uint64_t m_dup_num;
    uint64_t m_num;
    bool     m_is_gaveup;
    bool     m_is_rst;
    bool     m_is_fin;

    tcp_flow_unidir() : m_flags(0), m_seq(0), m_ack(0), m_min_seq(0),
                        m_time(0), m_chksum_err(0), m_dup_num(0), m_num(0),
                        m_is_gaveup(false), m_is_rst(false), m_is_fin(false) { }
    virtual ~tcp_flow_unidir() { }
};

struct tcp_flow {
    tcp_flow_unidir m_flow1;
    tcp_flow_unidir m_flow2;
};

class udp_flow {
public:
    std::list<ptr_uint8_t> m_flow1;
    std::list<ptr_uint8_t> m_flow2;
    uint64_t m_flow1_chksum_err;
    uint64_t m_flow2_chksum_err;
    uint64_t m_flow1_num;
    uint64_t m_flow2_num;

    udp_flow() : m_flow1_chksum_err(0),
                 m_flow2_chksum_err(0),
                 m_flow1_num(0),
                 m_flow2_num(0) { }
    virtual ~udp_flow() { }

};

typedef boost::shared_ptr<tcp_flow> ptr_tcp_flow;
typedef boost::shared_ptr<udp_flow> ptr_udp_flow;

class id_dir
{
public:
    cdpi_flow_id_wrapper m_id;
    cdpi_data_origin     m_org;

    bool operator< (const id_dir &rhs) const {
        if (m_id == rhs.m_id)
            return m_org < rhs.m_org;

        return m_id < rhs.m_id;
    }

    bool operator> (const id_dir &rhs) const { return rhs < *this; }
    bool operator== (const id_dir &rhs) const {
        return m_id == rhs.m_id && m_org == rhs.m_org;
    }
};

class pkt_buf {
public:
    std::list<ptr_uint8_t> m_buf;
    int m_pos;

    pkt_buf() : m_pos(0) { }
    virtual ~pkt_buf() { }
};

class cdpi_flow {
public:
    cdpi_flow();
    virtual ~cdpi_flow() { }

    void input_ipv4(uint8_t *bytes, size_t len);
    void run();

private:
    bool get_flow_id_ipv4(uint8_t *bytes, size_t len, cdpi_flow_id &flow_id,
                          cdpi_data_origin &origin, uint8_t **l4hdr);
    void input_tcp(uint8_t *bytes, size_t len, tcphdr *tcph,
                   cdpi_flow_id_wrapper id, cdpi_data_origin origin);
    void input_tcp_l7(std::set<id_dir> &inq);
    int  read_buf(id_dir &id, uint8_t *buf, int len);
    int  skip_buf(id_dir &id, int len);

    std::map<cdpi_flow_id_wrapper, ptr_tcp_flow> m_tcp_flow;
    std::map<cdpi_flow_id_wrapper, ptr_udp_flow> m_udp_flow;
    std::set<id_dir> m_inq;

    // for thread
    std::map<id_dir, pkt_buf> m_packets;
    boost::thread    m_thread;
    boost::mutex     m_mutex;
    boost::condition m_condition;

};


#endif // CDPI_FLOW_HPP
