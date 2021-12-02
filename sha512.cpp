#include <iostream>
#include <bitset>
#include "constants.h"
#include "operators.h"
#include <string.h>
#include <vector>

//  97, 115 = 24947 // convert string to binary then to decimal to use bitwise operations
// a + s = 24947

class SHA512
{
    protected:
        const unsigned int DIGEST_SIZE = 0x80; // 128
        const unsigned int BLOCK_SIZE = 1024; // in bits

    public:
        SHA512(std::string msg)
        {
            // length is represented by a 128 bit unsigned integer
            __uint128_t len = msg.length()*8;

            std::bitset<8> binary;
            std::vector<std::bitset<8>> Word;
            for (char c : msg)
            {
                binary = std::bitset<8>(c);
            }
            
            // padding of zeros
            const __uint128_t padding = (BLOCK_SIZE - len+1 - 128) % 1024;
            std::printf(padding);
            for (int c=0;c<msg.length();c++)
            {
                std::bitset<8> paddedBits = std::bitset<8>(msg[c]);
            }
            // std::cout << "padding of sha512 message: " << (std::string)padding
            //           << "\nlength of message: " << len << std::endl
            //           << "padded bits: " << paddedBits;
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
