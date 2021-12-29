# sha512.cpp
sha512 in c++. project just started

Made By: TC (Kibnakamoto)

Start Date: dec 5, 2021

Finalized in: N/A

I made this code at 15.

_


length of message is represented by a 128 bit unsigned int

operators are defined by macros.

first problem is to separate the padded word into 16 part 64 bit blocks. (16x64=1024 message size in bits = 1024) using unsigned char pointer

official NIST documentations used in the implementation of this algorithm(SHA512).

