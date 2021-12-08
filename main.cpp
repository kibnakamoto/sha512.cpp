#include <iostream>
#include <string>
#include "SHA512.h"

int main()
{
    std::string msg;
    std::cout << "input:\t";
    getline(std::cin, msg);
    SHA512 hash(msg);
    return 0;
}
