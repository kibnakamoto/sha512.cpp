#include <iostream>
#include <string>
#include "SHA512.h"

int main()
{
    // this algorithm only works for 1 block
    std::string msg;
    msg = "abc";
    std::cout << sha512(msg);
    return 0;
}
