#include <cstddef>
#include <cstdio>
#include <iostream>
#include <seal/decryptor.h>
#include <seal/galoiskeys.h>
#include <seal/util/defines.h>
#include <seal/valcheck.h>
#include <string>
#include <sys/types.h>
#include <vector>
#include <zmq.hpp>
#include "channel.h"
#include "ckks_evaluator.h"
#include "util.h"

class Client {
public:
    CKKSEvaluator *ckks = nullptr;

    Client(EncryptionParameters parms, Channel *channel) : context(parms), io(channel)
    {}

    void sendMessage(const std::string &message)
    {
        zmq::message_t zmq_message(message.begin(), message.end());
        io->socket.send(zmq_message, zmq::send_flags::none);
        std::cout << "Sent: " << message << std::endl;
    }

    void sendParams()
    {
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        double scale = pow(2.0, 40.0);

        Encryptor *encryptor = new Encryptor(context, public_key);
        Evaluator *evaluator = new Evaluator(context);
        Decryptor *decryptor = new Decryptor(context, secret_key);
        CKKSEncoder *encoder = new CKKSEncoder(context);
        RelinKeys *relin_keys = new RelinKeys();
        keygen.create_relin_keys(*relin_keys);

        GaloisKeys *galois_keys = new GaloisKeys();

        {
            vector<int> step;
            for (auto i = 0; i < 12; i++) {
                step.push_back(1 << i);
            }
            step.push_back(-8);

            keygen.create_galois_keys(step, *galois_keys);
        }
        // {
        //     std::vector<std::uint32_t> rots;
        //     for (int i = 0; i < 12; i++) {
        //         rots.push_back(
        //             (context.key_context_data()->parms().poly_modulus_degree() + exponentiate_uint(2, i)) /
        //             exponentiate_uint(2, i));
        //     }
        //     keygen.create_galois_keys(rots, *galois_keys);
        // }

        MySealKeys key(context);

        key.setKeys(public_key, *relin_keys, *galois_keys);

        auto key_string = key.serialize();
        cout << "keygen: " << key_string.size() / 1024.0 / 1024.0 << endl;
        auto zmq_message = zmq::message_t(key_string.begin(), key_string.end());

        io->socket.send(zmq_message, zmq::send_flags::none);

        CKKSEvaluator *ckks_evaluator =
            new CKKSEvaluator(&context, encryptor, decryptor, encoder, evaluator, scale, relin_keys, galois_keys);

        this->ckks = ckks_evaluator;

        Ciphertext ct;
        Plaintext pt;
        io->recvCiphertext(context, ct);
        decryptor->decrypt(ct, pt);
        vector<double> res;
        encoder->decode(pt, res);
        printf("Client: Received ciphertext %.10lf\n", res[0]);
    }

    void reEncrypt()
    {
        while (true) {
            Ciphertext ct;
            io->recvCiphertext(context, ct);
            Plaintext temp;
            vector<double> v;
            ckks->decryptor->decrypt(ct, temp);
            ckks->encoder->decode(temp, v);
            ckks->encoder->encode(v, ckks->scale, temp);
            ckks->encryptor->encrypt(temp, ct);
            io->sendCiphertext(ct);
            printf("Client: reEncrypt ciphertext\n");
        }
    }

private:
    SEALContext context;
    Channel *io;
};
