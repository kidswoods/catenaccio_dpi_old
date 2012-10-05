#ifndef CDPI_COMMON_HPP
#define CDPI_COMMON_HPP

#include <stdint.h>
#include <stdio.h>

#include <boost/shared_ptr.hpp>

class cdpi_callback {
public:
    cdpi_callback() { }
    virtual ~cdpi_callback() { }

    virtual void operator()(uint8_t *bytes, size_t len) = 0;
};

typedef boost::shared_ptr<cdpi_callback> cdpi_callback_ptr;

#endif // CDPI_COMMON_HPP
