#pragma once
#include <iostream>
#include <seal/context.h>
#include "seal/seal.h"
#include "zmq.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

class Channel {
public:
    enum class Type { Server = 0x0, Client = 0x1 };
    Channel(Type t) : zmqcontext(1), socket(zmqcontext, ZMQ_PAIR)
    {
        switch (t) {
        case Type::Server:
            socket.bind("tcp://*:1234");
            break;
        case Type::Client:
            socket.connect("tcp://localhost:1234");
            break;
        }
    }

    void sendCiphertext(Ciphertext &encrypted)
    {
        vector<seal::seal_byte> ct(encrypted.save_size());
        auto ct_size = encrypted.save(ct.data(), ct.size());
        const byte *ct_ptr = reinterpret_cast<const byte *>(ct.data());
        zmq::message_t message(ct_ptr, ct_size);
        socket.send(message, zmq::send_flags::none);
        std::cout << "Sent: "
                  << "Cipher" << std::endl;
    }

    void recvCiphertext(seal::SEALContext sealcontext, Ciphertext &encrypted)
    {
        zmq::message_t request;
        auto _ = socket.recv(request);
        byte *ptr = request.data<byte>();
        encrypted.unsafe_load(sealcontext, ptr, request.size());
    }

    zmq::context_t zmqcontext;
    zmq::socket_t socket;
    std::string address;
};