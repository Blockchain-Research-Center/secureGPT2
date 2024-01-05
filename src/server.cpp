#include "server.h"
#include <iostream>
#include <string>
#include <zmq.hpp>
#include "params.h"

int main()
{
    auto parms = SealParameters::GetParameters1();

    Channel *c = new Channel(Channel::Type::Server);

    Server server(parms, c);
    server.recvParams();
    server.run(Server::func::GELU);

    free(c);

    return 0;
}
