#include "rc4.h"

void RC4::KSA() {
    size_t i, j = 0;

    for(i = 0; i < 256; i++) {
        S[i] = i;
        subkeys[i] = key[(i % std::strlen((const char*)key))];
    }

    for(i = 0; i < 256; i++) {
        j = ((j + S[i] + subkeys[i]) % 256);
        std::swap(S[i], S[j]);
    }
}

void RC4::PRGA(unsigned char *data) {
    size_t i = 0, j = 0, index;
    unsigned char t, k;

    for(index = 0; index < std::strlen((const char*)data); index++) {
        i = ((i + 1) % 256);
        j = ((j + S[i]) % 256);
        std::swap(S[i], S[j]);
        t = ((S[i] + S[j]) % 256);
        k = S[t];
        data[index] = (data[index] ^ k);
    }
}

std::string RC4::encode(const std::string& data) {
    KSA();
    unsigned char formated_data[(data.size() + 1)];

    size_t i;
    for(i = 0; i < data.size(); i++)
        formated_data[i] = (unsigned char)data[i];
    formated_data[data.size()] = '\0';

    PRGA(formated_data);
    return std::string((char*)formated_data);
}

void RC4::update(const std::string& inputKey){
    std::memcpy(key, inputKey.c_str(), 256);
}
