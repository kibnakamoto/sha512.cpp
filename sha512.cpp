#include <iostream>
#include <bitset>
#include "constants.h"
#include "operators.h"
#include <string.h>

using byte = unsigned char;

std::string convertToHex(std::string str)
{
    for (char c : str)
    {
        auto dec = (int) c;
        std::cout << std::hex << dec;
    }
    return str;
}

class SHA512
{
    protected:
        const unsigned int DIGEST_SIZE = 0x80; // 128
    
    public:
        SHA512(std::string msg)
        {
            auto Bytes = convertToHex(msg);

            // length is represented by a 64 bit unsigned integer
            uint64_t len = msg.length()*8;
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
