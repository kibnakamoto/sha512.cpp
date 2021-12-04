// choice
#define Ch(x,y,z) (x bitand y)xor(~x bitand z)

// majority
#define Maj(x,y,z) (x & y)^(x & z)^(y & z)

inline __uint128_t maj(__uint128_t x, __uint128_t y, __uint128_t z) 
{
    return (x bitand y)xor(x bitand z)xor(y bitand z);
};
