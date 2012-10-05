#include "cdpi_divert.hpp"

#include <iostream>

using namespace std;

int
main(int argc, char *argv[])
{
    event_base *ev_base = event_base_new();
    cdpi_divert dvt;

    if (!ev_base) {
        cerr << "could'n new event_base" << endl;
        return -1;
    }

    dvt.set_ev_base(ev_base);
    dvt.run(100, 200);

    event_base_dispatch(ev_base);

    return 0;
}
