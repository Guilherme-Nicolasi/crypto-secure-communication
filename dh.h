#ifndef DH_H
#define DH_H

#include <iostream>
#include <cstring>
#include <cmath>

class DH {
    private:
        int p; // Prime number
        int g; // Primitive Root
        int x; // Private Key
        int sharedKey; // Shared Key

    public:
        int PublicKey();
        int SharedKey(int destPublicKey);
        DH(int prime, int primitiveRoot, int privateKey);
};

#endif // DH_H
