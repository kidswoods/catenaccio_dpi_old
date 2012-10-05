#include "cdpi_flow.hpp"

#include <string.h>

#include <netinet/ip.h>

bool
get_flow_id_ipv4(uint8_t **bytes, size_t len, cdpi_flow_id &flow_id,
                 cdpi_data_origin &origin)
{
    cdpi_flow_edge addr1, addr2;
    ip *hdr = (ip*)*bytes;

    if (hdr->ip_v != 4)
        return false;

    memset(&flow_id, 0, sizeof(flow_id));

    flow_id.l3_proto = IPPROTO_IPV4;

    addr1.l3_addr.b32 = hdr->ip_src.s_addr;
    addr2.l3_addr.b32 = hdr->ip_dst.s_addr;

    switch (hdr->ip_p) {
    case IPPROTO_TCP:
        flow_id.l4_proto = IPPROTO_TCP;
        // TODO: get port
        // TODO: update bytes to refere application data
        break;
    case IPPROTO_UDP:
        flow_id.l4_proto = IPPROTO_UDP;
        // TODO: get port
        // TODO: update bytes to refere application data
        break;
    default:
        flow_id.l4_proto = hdr->ip_p;
        break;
    }

    if (memcmp(&addr1, &addr2, sizeof(addr1)) < 0) {
        flow_id.addr1 = addr1;
        flow_id.addr2 = addr2;
        origin = FROM_ADDR1;
    } else {
        flow_id.addr1 = addr2;
        flow_id.addr2 = addr1;
        origin = FROM_ADDR2;
    }

    return true;
}
