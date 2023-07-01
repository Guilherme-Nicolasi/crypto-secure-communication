#ifndef RC4_H
#define RC4_H

#include <iostream>
#include <cstring>

class RC4 {
    private:
        unsigned char subkeys[256];
        unsigned char S[256];
        unsigned char key[256];

        void KSA();
        void PRGA(unsigned char* data);

    public:
        std::string encode(const std::string& data);
        void update(const std::string& inputKey);
};

#endif // RC4_H
