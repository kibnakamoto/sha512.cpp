#include <iostream>
#include "constants.h"
#include "operators.h"
#include <string>
#include <vector>

//  97, 115 = 24947 // convert string to binary then to decimal to use bitwise operators
// a + s = 24947

class SHA512
{
    protected:
        typedef unsigned char* ucharptr;
        typedef unsigned long long uint64;
        const uint64 DIGEST_SIZE = 0x80/8; // 128 bytes
        const uint64 BLOCK_SIZE = 1024/8; // in bytes
        std::vector<ucharptr> Word;

    public:
        SHA512(std::string msg)
        {
            ucharptr message = (ucharptr)msg.c_str();
            
            // length is represented by a 128 bit unsigned integer
            __uint128_t len = msg.length();

            // padding
            const __uint128_t padding = (BLOCK_SIZE - (len+1) - 128) % 1024;
            ucharptr add1AndPad = message + '1' + '0'*padding + len;
            Word.push_back(add1AndPad);

            for (int i=0;i<Word.size();i++)
            {
                std::cout << Word[i];
            }
        }
        
};

int main()
{
    std::string msg;
    std::cout << "input:\t";
    getline(std::cin, msg);
    SHA512 hash(msg);
    return 0;
}
