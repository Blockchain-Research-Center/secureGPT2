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
    server.run(Server::func::SOFTMAX);

    std::cout << (server.ckks->comm_recv) / 1024.0 / 1024.0 << " MB" << std::endl;
    std::cout << (server.ckks->comm_send) / 1024.0 / 1024.0 << " MB" << std::endl;

    free(c);

    return 0;
}
