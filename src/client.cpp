#include "client.h"
#include <iostream>
#include <string>
#include <zmq.hpp>
#include "channel.h"
#include "params.h"

int main()
{
    auto parms = SealParameters::GetParameters1();

    Channel *c = new Channel(Channel::Type::Client);

    Client client(parms, c);
    client.sendParams();
    client.reEncrypt();
    return 0;
}
