#ifndef CDPI_COMMON_HPP
#define CDPI_COMMON_HPP

#include <stdint.h>

struct flow_id {
    uint8_t l3_proto;

    union {
        uint32_t b32;
        uint8_t  b128[16];
    } l3_src;

    union {
        uint32_t b32;
        uint8_t  b128[16];
    } l3_dst;
    
    uint8_t  l4_proto;
    uint16_t l4_port_src;
    uint16_t l4_port_dst;
};

#endif CDPI_COMMON_HPP
