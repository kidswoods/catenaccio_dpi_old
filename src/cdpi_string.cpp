#include "cdpi_string.hpp"

int
find_char(char *buf, int len, char c)
{
    int   n = 0;
    char *end = buf + len;

    for (; buf < end; buf++) {
        if (*buf == c)
            return n;

        n++;
    }

    return -1;
}
