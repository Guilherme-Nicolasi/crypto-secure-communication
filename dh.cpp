#include "dh.h"

DH::DH(unsigned long long prime, unsigned long long primitiveRoot, unsigned long long privateKey) {
    p = prime;
    g = primitiveRoot;
    x = privateKey;
}

unsigned long long DH::PublicKey() {
    return static_cast<unsigned long long>(std::pow(g, x)) % p;
}

void DH::SharedKey(unsigned long long destPublicKey) {
    sharedKey = static_cast<unsigned long long>(std::pow(destPublicKey, x)) % p;
}
