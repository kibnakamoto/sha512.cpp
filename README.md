# sha512.cpp
sha512 in c++. project just started

length of message is represented by a 128 bit unsigned int

operators are mostly defined by macros but some might use inline functions

first problem is to separate the padded word into 16 part 64 bit blocks. (16x64=1024 message size in bits = 1024) using unsigned char pointer

official NIST documentations used in the implementation of this algorithm(SHA512).
