#ifndef CDPI_FLOW_HPP
#define CDPI_FLOW_HPP

#include <stdio.h>
#include <stdint.h>

struct cdpi_flow_edge {
    union {
        uint32_t b32;
        uint8_t  b128[16];
    } l3_addr;

    uint32_t l4_port;
};

struct cdpi_flow_id {
    // addr1 must be less than addr2
    cdpi_flow_edge addr1, addr2;
    uint8_t  l3_proto;
    uint8_t  l4_proto;
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

bool get_flow_id_ipv4(uint8_t **bytes, size_t len, cdpi_flow_id &flow_id,
                      cdpi_data_origin &origin);

class cdpi_flow {
};


#endif // CDPI_FLOW_HPP
