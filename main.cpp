#include <iostream>
#include <string>
#include "SHA512.h"

int main()
{
    std::string msg;
    msg = "abc";
    // std::cout << "input:\t";
    // getline(std::cin, msg);
    SHA512 hash(msg);
    std::cout << std::endl
          << "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9ee"
          <<"ee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d442364"
          << "3ce80e2a9ac94fa54ca49f\n\t\t\t\t\t\t\t^ correct value ^";
    return 0;
}
