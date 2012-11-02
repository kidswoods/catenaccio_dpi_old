#include "cdpi_protocols.hpp"
#include "cdpi_string.hpp"

#include <algorithm>

using namespace std;

void
cdpi_http::set_header(string key, string val)
{
    transform(key.begin(), key.end(), key.begin(), lower_case);

    boost::mutex::scoped_lock lock(m_mutex);

    m_headers[key] = val;
}

string
cdpi_http::get_header(std::string key)
{
    transform(key.begin(), key.end(), key.begin(), lower_case);

    boost::mutex::scoped_lock lock(m_mutex);
    map<string, string>::iterator it = m_headers.find(key);

    if (it == m_headers.end())
        return string("");

    return it->second;
}
