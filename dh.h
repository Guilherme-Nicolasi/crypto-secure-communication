#ifndef DH_H
#define DH_H

#include <iostream>
#include <cstring>
#include <cmath>

class DH {
    private:
        unsigned long long p; // Prime number
        unsigned long long g; // Primitive Root
        unsigned long long x; // Private Key
        unsigned long long sharedKey; // Shared Key

        unsigned long long PublicKey();

    public:
        DH(unsigned long long prime, unsigned long long generator, unsigned long long privateKey);
        unsigned long long SharedKey(unsigned long long destPublicKey);
};

#endif // DH_H
