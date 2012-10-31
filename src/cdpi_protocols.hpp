#ifndef CDPI_PROTOCOLS
#define CDPI_PROTOCOLS

#include "cdpi_common.hpp"

#include <map>
#include <string>

enum cdpi_proto_type {
    PROTO_HTTP_CLIENT,
    PROTO_HTTP_SERVER,
    PROTO_TLS_1_0,
    PROTO_NONE
};

class cdpi_protocols
{
public:
    cdpi_protocols() { }
    virtual ~cdpi_protocols() { };

    cdpi_proto_type m_type;
};

class cdpi_http : public cdpi_protocols
{
public:
    enum http_state {
        HTTP_METHOD,
        HTTP_RESPONSE,
        HTTP_HEAD,
        HTTP_BODY,
        HTTP_CHUNK
    };

    cdpi_http() { }
    virtual ~cdpi_http() { }

    std::map<std::string, std::string> m_headers;
    http_state  m_state;
    std::string m_method;
    std::string m_uri;
    std::string m_ver;
};

#endif // CDPI_PROTOCOLS
