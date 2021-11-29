#include <iostream>
#include <bitset>
#include "constants.h"
#include "operators.h"
#include <string.h>
#include <vector>

// std::vector<std::bitset<8>> convertToHex(std::string str)
// {
//     std::bitset<8> b;
//     std::vector<std::bitset<8>> vec;
//     for (char c : str)
//     {
//         auto dec = (int) c;
//         // std::cout << std::hex << dec;
//         auto b = std::bitset<8>(c);
//         vec.push_back(b);
//         std::cout << b;
//     }
//     return vec;
// }

class SHA512
{
    protected:
        const unsigned int DIGEST_SIZE = 0x80; // 128
        const unsigned int BLOCK_SIZE = 1024; // in bits

    public:
        SHA512(std::string msg)
        {
            // length is represented by a 64 bit unsigned integer
            uint64_t len = msg.length()*8;
            
            std::bitset<8> binary;
            std::vector<std::bitset<8>> Word;
            for (char c : msg)
            {
                binary = std::bitset<8>(c);
            }
            // padding of zeros
            uint64_t padding = (BLOCK_SIZE - len+1 - 128) % 1024;
            std::string pad(padding, '0');
            std::bitset<1> _1 = std::bitset<1>('1');
            auto paddedBits = binary, _1,pad;//std::bitset<padding>(0);
            std::cout << "padding of sha512 message: " << padding
                      << "\nlength of message: " << len << std::endl
                      << "padded bits: " << paddedBits;
        }
};

int main()
{
    std::string msg;
    std::cout << "input message:\t";
    getline(std::cin, msg);
    SHA512 hash(msg);
    return 0;
}
