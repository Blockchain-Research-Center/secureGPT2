#include <cstddef>
#include <iostream>
#include <seal/relinkeys.h>
#include <sstream>
#include "seal/seal.h"

class MySealKeys {
public:
    MySealKeys(const seal::SEALContext &context) : context(context)
    {}

    void setKeys(const seal::PublicKey &publicKey, const seal::RelinKeys &relinKeys, const seal::GaloisKeys &rotKeys)
    {
        this->publicKey = publicKey;
        this->relinKeys = relinKeys;
        this->rotKeys = rotKeys;
    }

    std::string serialize() const
    {
        std::stringstream ss;
        publicKey.save(ss);
        relinKeys.save(ss);
        rotKeys.save(ss);
        return ss.str();
    }

    void deserialize(const std::string &data)
    {
        std::stringstream ss(data);
        publicKey.load(context, ss);
        relinKeys.load(context, ss);
        rotKeys.load(context, ss);
    }

    seal::PublicKey publicKey;
    seal::RelinKeys relinKeys;
    seal::GaloisKeys rotKeys;
    seal::SEALContext context;
};
