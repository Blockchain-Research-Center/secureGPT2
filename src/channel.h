#pragma once
#include <cstddef>
#include <iostream>
#include <seal/context.h>
#include <sys/types.h>
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
    ~Channel()
    {
        socket.close();
        zmqcontext.close();
    }

    size_t sendCiphertext(Ciphertext &encrypted)
    {
        vector<seal::seal_byte> ct(encrypted.save_size());
        auto ct_size = encrypted.save(ct.data(), ct.size());
        const byte *ct_ptr = reinterpret_cast<const byte *>(ct.data());
        zmq::message_t message(ct_ptr, ct_size);
        auto m_size = message.size();
        socket.send(message, zmq::send_flags::none);

        std::cout << "Sent: "
                  << "Cipher" << std::endl;
        return m_size;
    }

    size_t recvCiphertext(seal::SEALContext sealcontext, Ciphertext &encrypted)
    {
        zmq::message_t request;
        auto _ = socket.recv(request);
        byte *ptr = request.data<byte>();
        encrypted.unsafe_load(sealcontext, ptr, request.size());
        return request.size();
    }

    void send_vec_Ciphertexts(std::vector<seal::Ciphertext> &ciphertexts)
    {
        uint64_t size = ciphertexts.size();
        zmq::message_t size_msg(&size, sizeof(size));
        socket.send(size_msg, zmq::send_flags::sndmore);

        // 逐个发送 ciphertexts
        for (const auto &ct : ciphertexts) {
            std::stringstream ss;
            ct.save(ss);
            std::string str = ss.str();
            zmq::message_t message(str.begin(), str.end());
            socket.send(message, zmq::send_flags::sndmore);
        }
    }

    void recv_vec_Ciphertexts(seal::SEALContext &context, std::vector<seal::Ciphertext> &ciphertexts)
    {
        // 接收 ciphertexts 的数量
        zmq::message_t size_msg;
        auto _ = socket.recv(size_msg);
        uint64_t size = *size_msg.data<uint64_t>();

        // 重建 ciphertexts
        ciphertexts.clear();
        ciphertexts.reserve(size);
        for (uint64_t i = 0; i < size; ++i) {
            zmq::message_t ct_msg;
            _ = socket.recv(ct_msg);
            std::string str(ct_msg.data<char>(), ct_msg.size());
            std::stringstream ss(str);
            seal::Ciphertext ct(context);
            ct.load(context, ss);
            ciphertexts.push_back(std::move(ct));
        }
    }

    zmq::context_t zmqcontext;
    zmq::socket_t socket;
    std::string address;
};