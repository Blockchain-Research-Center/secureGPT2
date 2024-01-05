#include "server.h"
#include <iostream>
#include <string>
#include <zmq.hpp>

int main()
{
    EncryptionParameters parms(scheme_type::ckks);
    long logN = 14;
    size_t poly_modulus_degree = 1 << logN;
    double scale = pow(2.0, 40);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 58, 40, 40, 40, 40, 40, 40, 40, 40, 58 }));

    Channel *c = new Channel(Channel::Type::Server);

    Server server(parms, c);
    server.recvParams();
    server.run(Server::func::GELU);

    std::cout << (server.ckks->comm_recv) / 1024.0 / 1024.0 << " MB" << std::endl;
    std::cout << (server.ckks->comm_send) / 1024.0 / 1024.0 << " MB" << std::endl;

    free(c);

    return 0;
}
