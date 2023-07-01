#ifndef SDES_H
#define SDES_H

#include <iostream>
#include <string>

class S_DES {
    private:
        char subkeys[2];
        int MAP_4[4] = {1,3,2,0};
        int MAP_8[8] = {5, 2, 6, 3, 7, 4, 9, 8};
        int MAP_10[10] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
        int MAP_EXPANDER[8] = {3, 0, 1, 2, 1, 2, 3, 0};
        int MAP_IP[8] = {1,5,2,0,3,7,4,6};
        int MAP_REVERSE_IP[8] = {3,0,2,4,6,1,7,5};
        int MAP_REDUCE[4][4] = {{1, 0, 3, 2},
                                {3, 2, 1, 0},
                                {0, 2, 1, 3},
                                {3, 1, 3, 2}};
        int MAP_REDUCE_1[4][4] = {{1, 1, 2, 3},
                                  {3, 2, 1, 0},
                                  {0, 2, 1, 3},
                                  {2, 1, 0, 3}};
        static const int FEEDBACK = 127;

        int permutation(int in, int in_size, int map[], int map_size);
        int* divide(int in, int size);
        int shift(int in, int size, int iterations);
        int reduce(int in, int map[4][4]);
        int complex_function(int in, int subkey);
        int encode_integer(int in, int key_1, int key_2);

    public:
        enum mode {
            ECB,
            CBC
        };
        std::string encode(const std::string& data, mode m);
        std::string decode(const std::string& data, mode m);
        void update(int key);
};

#endif // SDES_H
