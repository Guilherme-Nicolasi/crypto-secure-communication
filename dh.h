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
        void set_DH(int prime, int generator, int privateKey);
        int PublicKey();
        int SharedKey(int destPublicKey);
        DH(int prime, int primitiveRoot, int privateKey);
};

#endif // DH_H
