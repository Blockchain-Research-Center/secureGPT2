#include <chrono>
#include <future>
#include <iostream>
#include <math.h>
#include <random>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <seal/seal.h>
#include <string>
#include <vector>
#include "argmax.h"
#include "gelu.h"
#include "layer_norm.h"
#include "matrix_mul.h"
#include "softmax.h"
#include "thread_pool_mgr.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace std::chrono;

void MM_test();

int main()
{
    EncryptionParameters parms(scheme_type::ckks);
    long logN = 16;
    size_t poly_modulus_degree = 1 << logN;
    double scale = pow(2.0, 40);
    int depth = 35;

    // cout << "Chose N=" << poly_modulus_degree << " so max bit count is " <<
    // CoeffModulus::MaxBitCount(poly_modulus_degree) << endl; cout << "Will attempt to use " << 60 + log2(scale) *
    // depth + 60 << " bits (depth = " << depth << ")" << endl;
    vector<int> moduli_bits(depth + 2, log2(scale));
    moduli_bits[0] = 60;
    moduli_bits[moduli_bits.size() - 1] = 60;

    parms.set_poly_modulus_degree(poly_modulus_degree);

    auto moduli = CoeffModulus::Create(poly_modulus_degree, moduli_bits);
    parms.set_coeff_modulus(moduli); // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, moduli_bits));
    SEALContext context(parms, true, sec_level_type::none);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;

    std::vector<int> rots;
    for (int i = 0; i < 12; i++) {
        rots.push_back(1 << i);
    }
    // rots.push_back(-8);
    keygen.create_galois_keys(rots, galois_keys);
    // keygen.create_galois_keys(galois_keys);

    CKKSEvaluator ckks_evaluator(context, encryptor, decryptor, encoder, evaluator, scale, relin_keys, galois_keys);
    GeLUEvaluator gelu_evaluator(ckks_evaluator);
    LNEvaluator ln_evaluator(ckks_evaluator);
    SoftmaxEvaluator softmax_evaluator(ckks_evaluator);
    ArgmaxEvaluator argmax_evaluator(ckks_evaluator);

    std::cout << "Initilization done" << std::endl;
    // double bound = 1.0 / (1 << 16);
    // vector<double> input = {-0.4, -0.3, -0.2, -0.1, 0.1, 0.2, 0.3, 0.4};
    vector<double> input = { 0.4, 0.3, 0.2, 0.1, 0.7, 0.8, 0.2, 0.4 };
    Plaintext plain_input;
    Ciphertext cipher_input;
    Ciphertext cipher_output;
    vector<double> output;
    ckks_evaluator.encoder->encode(input, scale, plain_input);
    ckks_evaluator.encryptor->encrypt(plain_input, cipher_input);

    vector<Ciphertext> cipher_inputs;
    vector<Ciphertext> cipher_outputs;

    for (auto i = 0; i < 32; i++) {
        Ciphertext ct;
        ckks_evaluator.encryptor->encrypt(plain_input, ct);
        cipher_inputs.push_back(ct);
    }

    for (auto i = 0; i < 32; i++) {
        Ciphertext out;
        cipher_outputs.push_back(out);
    }

    ThreadPoolMgr tpm;

    tpm.SetThreadCount(32);

    // auto start = high_resolution_clock::now();

    // // gelu_evaluator.gelu(cipher_input, cipher_output);

    // vector<future<void>> futures;
    // for (auto i = 0; i < 32; i++) {
    //     futures.push_back(
    //         tpm.thread_pool().enqueue([&, i]() { gelu_evaluator.gelu(cipher_inputs[i], cipher_outputs[i]); }));
    // }

    // for (auto &f : futures) {
    //     f.get();
    // }

    // auto end = high_resolution_clock::now();
    // cout << poly_modulus_degree / 2 << " times gelu() takes: " << duration_cast<milliseconds>(end - start).count()
    // / 2.0
    //      << " milliseconds" << endl;

    auto start = high_resolution_clock::now();
    // int size = input.size();

    vector<future<void>> futures;
    for (auto i = 0; i < 1; i++) {
        // futures.push_back(tpm.thread_pool().enqueue([&, i]() {
        //     softmax_evaluator.softmax2(cipher_inputs[i], cipher_outputs[i], 8);
        // }));
        // softmax_evaluator.softmax2(cipher_inputs[i], cipher_outputs[i], 8);
    }

    for (auto &f : futures) {
        // f.get();
    }

    auto rotk = *softmax_evaluator.ckks->galois_keys;
    std::cout << rotk.save_size() << endl;

    auto end = high_resolution_clock::now();
    cout << poly_modulus_degree / 4 << " times LN() takes: " << duration_cast<milliseconds>(end - start).count() / 2.0
         << " milliseconds" << endl;

    // auto start = high_resolution_clock::now();
    // int size = input.size();
    // // cipher_output = ckks_evaluator.inverse(cipher_input);
    // softmax_evaluator.softmax2(cipher_input, cipher_output, size);
    // auto end = high_resolution_clock::now();
    // cout << poly_modulus_degree / 4
    //      << " times softmax() takes: " << duration_cast<milliseconds>(end - start).count() / 1.0 << " milliseconds"
    //      << endl;

    // auto start = high_resolution_clock::now();
    // int size = input.size();
    // argmax_evaluator.argmax(cipher_input, cipher_output, size);
    // auto end = high_resolution_clock::now();
    // cout << poly_modulus_degree / 4 << " times Argmax() takes: " << duration_cast<seconds>(end - start).count() / 2.0
    //      << " seconds" << endl;

    // cout << "Input: ";
    // for (int i = 0; i < input.size(); i++) {
    //     printf("%.1f ", input[i]);
    //     ;
    // }
    // cout << "\n";
    // cout << "Output: ";
    // ckks_evaluator.print_decrypted_ct(cipher_output, 8);
    // cout << "communication cost: " << ckks_evaluator.comm << " bytes" << endl;
    // cout << "communication round: " << ckks_evaluator.round << endl;
    // MM_test();
}

void MM_test()
{
    EncryptionParameters parms(scheme_type::ckks);
    long logN = 13;
    size_t poly_modulus_degree = 1 << logN;
    double scale = pow(2.0, 40);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 60 }));
    SEALContext context(parms, true, sec_level_type::none);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;

    std::vector<std::uint32_t> rots;
    for (int i = 0; i < logN; i++) {
        rots.push_back((poly_modulus_degree + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }
    keygen.create_galois_keys(rots, galois_keys);

    CKKSEvaluator ckks_evaluator(context, encryptor, decryptor, encoder, evaluator, scale, relin_keys, galois_keys);

    MMEvaluator mme(ckks_evaluator);

    vector<vector<double>> X(768);
    vector<vector<double>> Y(72, vector<double>(poly_modulus_degree, 0.0));
    for (auto i = 0; i < 768; i++) {
        vector<double> val(poly_modulus_degree / 2);
        for (auto j = 0; j < poly_modulus_degree / 2; j++) {
            val[j] = 10.0 * 2.0 * (1.0 * rand() / RAND_MAX - 0.5);
        }
        X[i] = val;
    }
    vector<Ciphertext> res;

    mme.matrix_mul(X, Y, res);

    // for (auto i = 0; i < 10; i++) {
    //     printf("%+.10lf\n", -3.5153774 * X[0][i]);
    // }

    Plaintext res_pt;
    vector<double> mm_res;
    ckks_evaluator.decryptor->decrypt(res[0], res_pt);
    ckks_evaluator.encoder->decode(res_pt, mm_res);
    for (auto i = 0; i < 10; i++) {
        printf("%+.10lf\n", mm_res[i]);
    }
}