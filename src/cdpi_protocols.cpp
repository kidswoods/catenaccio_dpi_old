#include "cdpi_protocols.hpp"

using namespace std;

void
cdpi_http::set_header(string key, string val)
{
    boost::mutex::scoped_lock lock(m_mutex);

    m_headers[key] = val;
}

string
cdpi_http::get_header(std::string key)
{
    boost::mutex::scoped_lock lock(m_mutex);
    map<string, string>::iterator it = m_headers.find(key);

    if (it == m_headers.end())
        return string("");

    return it->second;
}

