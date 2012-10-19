#ifndef CDPI_COMMON_HPP
#define CDPI_COMMON_HPP

#ifdef DEBUG
#define D(S) S
#endif // DEBUG

#include <stdint.h>
#include <stdio.h>

#include <boost/shared_array.hpp>

typedef boost::shared_array<uint8_t> ptr_uint8_t;

#endif // CDPI_COMMON_HPP
