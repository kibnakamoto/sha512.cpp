#include <iostream>
#include <string>
#include "SHA512.h"

int main()
{
    std::string msg;
    msg = "abc";
    std::cout << sha512(msg);
    return 0;
}
