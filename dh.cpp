#include "dh.h"

DH::DH(int prime, int primitiveRoot, int privateKey) {
    p = prime;
    g = primitiveRoot;
    x = privateKey;
}

int DH::PublicKey() {
    return static_cast<int>(std::pow(g, x)) % p;
}

int DH::SharedKey(int destPublicKey) {
    sharedKey = static_cast<int>(std::pow(destPublicKey, x)) % p;
    return sharedKey;
}
