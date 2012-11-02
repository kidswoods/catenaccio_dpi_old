#ifndef CDPI_PROTOCOLS
#define CDPI_PROTOCOLS

#include "cdpi_common.hpp"

#include <map>
#include <string>
#include <queue>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

enum cdpi_proto_type {
    PROTO_HTTP_CLIENT,
    PROTO_HTTP_SERVER,
    PROTO_HTTP_PROXY,
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
        HTTP_CHUNK_LEN,
        HTTP_CHUNK_BODY,
        HTTP_CHUNK_EL,
        HTTP_CHUNK_TRAILER,
    };

    cdpi_http() : m_body_read(0) { }
    virtual ~cdpi_http() { }

    void set_header(std::string key, std::string val);
    std::string get_header(std::string key);

    http_state  m_state;
    std::string m_uri;
    std::string m_ver;
    std::string m_code;
    std::string m_res_msg;
    std::queue<std::string> m_method;
    int m_body_read;
    int m_chunk_len;

private:
    std::map<std::string, std::string> m_headers;
    boost::mutex m_mutex;

};

typedef boost::shared_ptr<cdpi_protocols> ptr_cdpi_proto;
typedef boost::shared_ptr<cdpi_http> ptr_cdpi_http;

#endif // CDPI_PROTOCOLS
