#include "seal/seal.h"
using namespace seal;

class SealParameters {
public:
    static seal::EncryptionParameters GetParameters1()
    {
        EncryptionParameters parms(scheme_type::ckks);
        long logN = 14;
        size_t poly_modulus_degree = 1 << logN;
        double scale = pow(2.0, 40);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 58, 40, 40, 40, 40, 40, 40, 40, 40, 58 }));
        return parms;
    }

    static seal::EncryptionParameters GetParameters2()
    {
        EncryptionParameters parms(scheme_type::ckks);
        long logN = 12;
        size_t poly_modulus_degree = 1 << logN;
        double scale = pow(2.0, 30);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 36, 36, 37 }));
        return parms;
    }
};
