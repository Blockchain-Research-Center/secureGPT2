#include <SEAL-4.1/seal/ckks.h>
#include <SEAL-4.1/seal/evaluator.h>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <seal/encryptor.h>
#include <seal/relinkeys.h>
#include <seal/seal.h>
#include <seal/valcheck.h>
#include <utility>
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
    CKKSEvaluator *ckks = nullptr;
    Server(EncryptionParameters parms, Channel *channel) : context(parms), io(channel)
    {}

    void recvParams()
    {
        double scale = pow(2.0, 40.0);
        // SecretKey secret_key = keygen.secret_key();
        // PublicKey public_key;
        // keygen.create_public_key(public_key);

        // Encryptor encryptor(context, public_key);
        Evaluator *evaluator = new Evaluator(context);
        // Decryptor decryptor(context, secret_key);
        CKKSEncoder *encoder = new CKKSEncoder(context);
        // RelinKeys relin_keys;
        // keygen.create_relin_keys(relin_keys);
        GaloisKeys galois_keys;

        // std::vector<std::uint32_t> rots;
        // for (int i = 0; i < 12; i++) {
        //     rots.push_back((poly_modulus_degree + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
        // }
        // keygen.create_galois_keys(rots, galois_keys);
        zmq::message_t request;
        auto _ = io->socket.recv(request);
        // byte *ptr = request.data<byte>();
        // PublicKey public_key;
        // public_key.unsafe_load(context, ptr, request.size());
        // Encryptor encryptor(context, public_key);

        MySealKeys key(context);
        key.deserialize(std::string(static_cast<char *>(request.data()), request.size()));
        auto publicKey = key.pk();
        RelinKeys *relin_keys = new RelinKeys(key.rk());

        Encryptor *encryptor = new Encryptor(context, publicKey);

        printf("Server: Received public key\n");
        // _ = socket.recv(request);
        // ptr = request.data<byte>();
        // RelinKeys relin_keys;
        // relin_keys.unsafe_load(context, ptr, request.size());
        Plaintext pt;
        Ciphertext ct;
        encoder->encode(1.23456789, scale, pt);
        encryptor->encrypt(pt, ct);
        io->sendCiphertext(ct);

        CKKSEvaluator *ckks_evaluator =
            new CKKSEvaluator(&context, encryptor, encoder, evaluator, scale, relin_keys, &galois_keys, io);

        this->ckks = ckks_evaluator;
    }

    void func()
    {
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
