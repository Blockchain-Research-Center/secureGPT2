#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <seal/ciphertext.h>
#include <seal/encryptor.h>
#include <seal/galoiskeys.h>
#include <seal/relinkeys.h>
#include <seal/seal.h>
#include <seal/valcheck.h>
#include <utility>
#include <vector>
#include <zmq.h>
#include "channel.h"
#include "ckks_evaluator.h"
#include "gelu.h"
#include "layer_norm.h"
#include "matrix_mul.h"
#include "softmax.h"
#include "util.h"
#include "zmq.hpp"

using namespace std::chrono;

class Server {
public:
    enum class func { GELU = 0x0, LN = 0x1, MM = 0x2, SOFTMAX = 0x3 };
    CKKSEvaluator *ckks = nullptr;
    Server(EncryptionParameters parms, Channel *channel) : context(parms), io(channel)
    {}
    void recvParams()
    {
        double scale = pow(2.0, 40.0);

        Evaluator *evaluator = new Evaluator(context);
        CKKSEncoder *encoder = new CKKSEncoder(context);

        zmq::message_t request;
        auto _ = io->socket.recv(request);

        printf("Server: Received key\n");

        MySealKeys *key = new MySealKeys(context);
        key->deserialize(std::string(static_cast<char *>(request.data()), request.size()));
        auto publicKey = key->publicKey;
        RelinKeys *relin_keys = new RelinKeys(key->relinKeys);

        GaloisKeys *galois_keys = new GaloisKeys(key->rotKeys);

        Encryptor *encryptor = new Encryptor(context, publicKey);

        Plaintext pt;
        Ciphertext ct;
        encoder->encode(1.23456789, scale, pt);
        encryptor->encrypt(pt, ct);
        io->sendCiphertext(ct);

        CKKSEvaluator *ckks_evaluator =
            new CKKSEvaluator(&context, encryptor, encoder, evaluator, scale, relin_keys, galois_keys, io);

        this->ckks = ckks_evaluator;
    }

    void run(func t)
    {
        switch (t) {
        case func::GELU: {
            vector<double> input = { -0.4, -0.3, -0.2, -0.1, 0.1, 0.2, 0.3, 0.4 };
            Plaintext plain_input;
            Ciphertext cipher_input;
            Ciphertext cipher_output;
            vector<double> output;
            ckks->encoder->encode(input, pow(2.0, 40.0), plain_input);
            ckks->encryptor->encrypt(plain_input, cipher_input);
            GeLUEvaluator gelu_evaluator(*ckks);
            auto start = high_resolution_clock::now();
            gelu_evaluator.gelu(cipher_input, cipher_output);
            auto end = high_resolution_clock::now();
            cout << ckks->N / 2 << " times gelu() takes: " << duration_cast<milliseconds>(end - start).count() << " ms"
                 << endl;

            std::cout << (ckks->comm_recv + ckks->comm_send) / 1024.0 / 1024.0 << " MB" << std::endl;
        }

        case func::LN: {
            vector<double> input = { -0.4, -0.3, -0.2, -0.1, 0.1, 0.2, 0.3, 0.4 };
            Plaintext plain_input;
            Ciphertext cipher_input;
            Ciphertext cipher_output;
            vector<double> output;
            ckks->encoder->encode(input, pow(2.0, 40.0), plain_input);
            ckks->encryptor->encrypt(plain_input, cipher_input);
            auto start = high_resolution_clock::now();
            int size = input.size();
            LNEvaluator ln_evaluator(*ckks);
            ln_evaluator.layer_norm(cipher_input, cipher_output, size);
            // //ckks_evaluator.sgn_eval(cipher_input, 7, 3, 0.5);
            auto end = high_resolution_clock::now();
            cout << ckks->N / 4 << " times LN() takes: " << duration_cast<milliseconds>(end - start).count() / 1.0
                 << " milliseconds" << endl;
            std::cout << (ckks->comm_recv + ckks->comm_send) / 1024.0 / 1024.0 << " MB" << std::endl;
        }

        // case func::MM: {
        //     vector<Ciphertext> Y;
        //     io->recv_vec_Ciphertexts(context, Y);
        // } break;
        case func::SOFTMAX: {
            vector<double> input = { -0.4, -0.3, -0.2, -0.1, 0.1, 0.2, 0.3, 0.4 };
            Plaintext plain_input;
            Ciphertext cipher_input;
            Ciphertext cipher_output;
            vector<double> output;
            ckks->encoder->encode(input, pow(2.0, 40.0), plain_input);
            ckks->encryptor->encrypt(plain_input, cipher_input);
            auto start = high_resolution_clock::now();
            SoftmaxEvaluator softmax_evaluator(*ckks);

            int size = 8;
            softmax_evaluator.softmax(cipher_input, cipher_output, size);
            auto end = high_resolution_clock::now();
            cout << ckks->N / 4 << " times softmax() takes: " << duration_cast<milliseconds>(end - start).count() / 1.0
                 << " milliseconds " << endl;
            std::cout << (ckks->comm_recv + ckks->comm_send) / 1024.0 / 1024.0 << " MB" << std::endl;
        }
        }
    }

    void listen()
    {
        while (true) {
            zmq::message_t request;

            // 等待客户端消息
            auto _ = io->socket.recv(request);
            std::string recv_msg(static_cast<char *>(request.data()), request.size());
            std::cout << "Received: " << recv_msg << std::endl;

            // 在这里添加处理接收到的消息的逻辑
        }
    }

private:
    SEALContext context;
    Channel *io;
};
