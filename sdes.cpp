#include <iostream>
#include <string>

#include "sdes.h"

#define merge(upper, lower, upper_len) ((upper) << (upper_len)) | lower

int S_DES::permutation(int in, int in_size, int map[], int map_size) {
    int out = 0;
    int bit;
    int end = 1 << (in_size - 1);

    for(int i = 0; i < map_size; i++) {
        bit = 0 != (in & end >> map[i]);
        out = out | bit << (map_size - 1 - i);
    }

    return out;
}

int* S_DES::divide(int in, int size) {
    int half = (size / 2);
    int mask = ((1 << half) - 1);
    int* out = (int*)malloc(sizeof(int) * 2);

    out[0] = (in & mask);
    out[1] = ((in & (~mask)) >> half);
    return out;
}

int S_DES::shift(int in, int size, int iterations) {
    iterations %= size;
    int right = (in << iterations);
    int left = (in >> (size - iterations));
    int clip = ((1 << (size)) - 1);
    return ((right | left) & clip);
}

int S_DES::reduce(int in, int map[4][4]) {
    int bits[4];
    for(int i = 0; i < 4; i++)
        bits[i] = ((in & 1 << i) >> i);

    int outer = (bits[3] << 1 | bits[0]);
    int inner = (bits[2] << 1 | bits[1]);
    return map[outer][inner];
}

int S_DES::complex_function(int in, int subkey) {
    int* halves = divide(in, 8);
    int out = halves[0];
    int upper = halves[1];
    int lower = halves[0];

    out = permutation(lower, 4, MAP_EXPANDER, 8);
    out = (out ^ subkey);

    int* lower_halves = divide(out, 8);
    lower_halves[1] = reduce(lower_halves[1], MAP_REDUCE);
    lower_halves[0] = reduce(lower_halves[0], MAP_REDUCE_1);

    out = merge(lower_halves[1], lower_halves[0], 2);
    out = permutation(out, 4, MAP_4, 4);
    out = (out ^ upper);

    free(halves);
    free(lower_halves);
    return merge(out, lower, 4);
}

int S_DES::encode_integer(int in, int key_1, int key_2) {
    int rounds = 2;

    in = permutation(in, 8, MAP_IP, 8);
    int* halves;

    for(int i = 0; i < (rounds - 1); i++) {
        in = complex_function(in, ((i % 2) == 0) ? key_1 : key_2);
        halves = divide(in, 8);
        in = merge(halves[0], halves[1], 4);
        free(halves);
    }

    in = complex_function(in, (((rounds - 1) % 2) == 0) ? key_1 : key_2);
    return permutation(in, 8, MAP_REVERSE_IP, 8);
}

std::string S_DES::encode(const std::string& data, S_DES::mode m) {
    std::string cipher;

    switch(m) {
        case ECB:
            for(char plain : data)
                cipher += (char)encode_integer((int)plain, subkeys[0], subkeys[1]);
            return cipher;
        break;
        case CBC:
            int feedback = FEEDBACK;
            for(char plain : data) {
                char value = (char)encode_integer((int)(plain ^ feedback), subkeys[0], subkeys[1]);
                feedback = value;
                cipher += value;
            }
            return cipher;
        break;
    }
    return "";
}

std::string S_DES::decode(const std::string& data, S_DES::mode m) {
    std::string plain = "";

    switch(m) {
        case ECB:
            for(unsigned int cipher : data)
                plain += (char)encode_integer(cipher, subkeys[1], subkeys[0]);
            return plain;
        break;
        case CBC:
            int feedback = FEEDBACK;
            for(unsigned int cipher : data) {
                char value = (char)encode_integer(cipher, subkeys[1], subkeys[0]);
                plain += (value ^ feedback);
                feedback = cipher;
            }
            return plain;
        break;
    }
    return "";
}

void S_DES::update(int key) {
    key = permutation(key, 10, MAP_10, 10);

    int* key_halves = divide(key, 10);
    key_halves[0] = shift(key_halves[0], 5, 1);
    key_halves[1] = shift(key_halves[1], 5, 1);

    int subk_1 = merge(key_halves[1], key_halves[0], 5);
    subk_1 = permutation(subk_1, 10, MAP_8, 8);

    key_halves[0] = shift(key_halves[0], 5, 2);
    key_halves[1] = shift(key_halves[1], 5, 2);

    int subk_2 = merge(key_halves[1], key_halves[0], 5);
    subk_2 = permutation(subk_2, 10, MAP_8, 8);

    free(key_halves);
    subkeys[0] = subk_1;
    subkeys[1] = subk_2;
}
