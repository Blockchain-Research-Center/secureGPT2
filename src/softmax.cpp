#include "softmax.h"

using namespace std;
using namespace seal;


void SoftmaxEvaluator::softmax(Ciphertext &x, Ciphertext &res, int len) {
    Ciphertext tmp, exp_x;
    int log_step = log2(len);
    ckks->evaluator->rotate_vector(x, -len, *ckks->galois_keys, tmp);
    ckks->evaluator->add_inplace(x, tmp);
    exp_x = ckks->exp(x);
    tmp = exp_x;
    for (int i = 0; i < log_step; ++i) {
        ckks->evaluator->rotate_vector(tmp, pow(2, i), *ckks->galois_keys, res);
        ckks->evaluator->add_inplace(res, tmp);
        tmp = res;
    }
    ckks->re_encrypt(res);
    res = ckks->inverse(res);
    ckks->evaluator->mod_switch_to_inplace(exp_x, res.parms_id());
    ckks->evaluator->multiply(res, exp_x, res);
    ckks->evaluator->relinearize_inplace(res, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(res);
}

void SoftmaxEvaluator::softmax2(Ciphertext &x, Ciphertext &res, int len) {
    Ciphertext tmp, a, b, sign, a_plus_b, a_minus_b, exp_x;
    Plaintext zero_point_five, one, inverse_64;
    int log_step = log2(len);
    ckks->evaluator->rotate_vector(x, -len, *ckks->galois_keys, tmp);
    ckks->evaluator->add_inplace(x, tmp);
    a = x;
    for (int i = 0; i < log_step; ++i) {
        ckks->evaluator->rotate_vector(a, pow(2, i), *ckks->galois_keys, b);
        ckks->evaluator->add(a, b, a_plus_b);
        ckks->evaluator->sub(a, b, a_minus_b);
        sign = ckks->sgn_eval2(a_minus_b, 2, 2);
        ckks->encoder->encode(0.5, a.parms_id(), a.scale(), zero_point_five);
        ckks->evaluator->multiply_plain_inplace(a_plus_b, zero_point_five);
        ckks->evaluator->rescale_to_next_inplace(a_plus_b);
        ckks->evaluator->mod_switch_to_inplace(a_minus_b, sign.parms_id());
        ckks->evaluator->multiply_inplace(a_minus_b, sign);
        ckks->evaluator->relinearize_inplace(a_minus_b, *ckks->relin_keys);
        ckks->evaluator->rescale_to_next_inplace(a_minus_b);
        a_plus_b.scale() = ckks->scale;
        a_minus_b.scale() = ckks->scale;
        ckks->evaluator->mod_switch_to_inplace(a_plus_b, a_minus_b.parms_id());
        ckks->evaluator->add(a_plus_b, a_minus_b, a);
        ckks->re_encrypt(a);
    }
    a.scale() = ckks->scale;
    ckks->evaluator->mod_switch_to_inplace(x, a.parms_id());
    ckks->evaluator->sub_inplace(x, a);
    ckks->encoder->encode(0.015625, x.parms_id(), x.scale(), inverse_64);
    ckks->evaluator->multiply_plain_inplace(x, inverse_64);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->encoder->encode(1.0, x.parms_id(), x.scale(), one);
    ckks->evaluator->add_plain_inplace(x, one);
    //x^64
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->square(x, x);
    ckks->evaluator->relinearize_inplace(x, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(x);

    vector<double> mask = ckks->init_mask(ckks->N/2, len);
    Plaintext mask_pt;
    exp_x = x;
    ckks->encoder->encode(mask, x.parms_id(), x.scale(), mask_pt);
    ckks->evaluator->multiply_plain_inplace(x, mask_pt);
    ckks->evaluator->rescale_to_next_inplace(x);
    ckks->evaluator->rotate_vector(x, -len, *ckks->galois_keys, tmp);
    ckks->evaluator->add_inplace(x, tmp);
    tmp = x;
    for (int i = 0; i < log_step; ++i) {
        ckks->evaluator->rotate_vector(tmp, pow(2, i), *ckks->galois_keys, res);
        ckks->evaluator->add_inplace(res, tmp);
        tmp = res;
    }
    //ckks->re_encrypt(res);
    Plaintext len_pt;
    ckks->encoder->encode(1.0/len, res.parms_id(), res.scale(), len_pt);
    ckks->evaluator->multiply_plain_inplace(res, len_pt);
    ckks->evaluator->rescale_to_next_inplace(res);
    res = ckks->inverse(res);
    ckks->encoder->encode(1.0/len, res.parms_id(), res.scale(), len_pt);
    ckks->evaluator->multiply_plain_inplace(res, len_pt);
    ckks->evaluator->rescale_to_next_inplace(res);
    ckks->evaluator->mod_switch_to_inplace(exp_x, res.parms_id());
    ckks->evaluator->multiply_inplace(res, exp_x);
    ckks->evaluator->relinearize_inplace(res, *ckks->relin_keys);
    ckks->evaluator->rescale_to_next_inplace(res);
    
}