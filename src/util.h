#include <cstddef>
#include <iostream>
#include <seal/relinkeys.h>
#include <sstream>
#include "seal/seal.h"

class MySealKeys {
public:
    MySealKeys(const seal::SEALContext &context) : context(context)
    {}

    void setKeys(const seal::PublicKey &publicKey, const seal::RelinKeys &relinKeys)
    {
        this->publicKey = publicKey;
        this->relinKeys = relinKeys;
    }

    std::string serialize() const
    {
        std::stringstream ss;
        publicKey.save(ss);
        relinKeys.save(ss);
        return ss.str();
    }

    void deserialize(const std::string &data)
    {
        std::stringstream ss(data);
        publicKey.load(context, ss);
        relinKeys.load(context, ss);
    }

    seal::PublicKey pk()
    {
        return publicKey;
    }

    seal::RelinKeys rk()
    {
        return relinKeys;
    }

private:
    seal::PublicKey publicKey;
    seal::RelinKeys relinKeys;
    seal::SEALContext context;
};
