/*
 *  github: kibnakamoto
 *   Created on: Dec. 5, 2021
 *      Author: kibarekmek(TC)
 */

#ifndef SHA512_H_
#define SHA512_H_

#include <iostream>
#include <string>
#include <cstring>
#include <stdint.h>

const uint64_t K[80] =
{
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// choice = (x ∧ y) ⊕ (¯x ∧ z)

#define Ch(x,y,z) ((x bitand y)xor(~x bitand z))
// majority = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)

#define Maj(x,y,z) ((x & y)^(x & z)^(y & z))

// binary operators
#define Shr(x,n) (x >> n)
#define Rotr(x,n) ((x >> n)|(x << (sizeof(x)<<3)-n))

// convert to big endian
inline __uint8_t* BE128(__uint8_t* y, __uint128_t len)
{ 
    // len = bitlen in this function
    // for (int c=120+1;c>=0;c--)
    // {
    //     if (c%8==0)
    //     {
    //         *y++=(uint8_t)((x>>c)&0xff);
    //     }
    //     else if (c==0)
    //     {
    //         *y++=(uint8_t)((x>>c)&0xff);
    //     }
    // }
    *y++=(uint8_t)((len>>120)&0xff);
    *y++=(uint8_t)((len>>112)&0xff);
    *y++=(uint8_t)((len>>104)&0xff);
    *y++=(uint8_t)((len>>96)&0xff);
    *y++=(uint8_t)((len>>88)&0xff);
    *y++=(uint8_t)((len>>80)&0xff);
    *y++=(uint8_t)((len>>72)&0xff);
    *y++=(uint8_t)((len>>64)&0xff);
    *y++=(uint8_t)((len>>56)&0xff);
    *y++=(uint8_t)((len>>48)&0xff);
    *y++=(uint8_t)((len>>40)&0xff);
    *y++=(uint8_t)((len>>32)&0xff);
    *y++=(uint8_t)((len>>24)&0xff);
    *y++=(uint8_t)((len>>16)&0xff);
    *y++=(uint8_t)((len>>8)&0xff);
    *y=(uint8_t)(len&0xff);
    return y;
};

class SHA512
{
    protected:
        typedef uint8_t* ucharptr;
        static const unsigned int DIGEST_SIZE = 0x80; // 128 bits
        static const unsigned int BLOCK_SIZE = 1024; // in bits
        uint64_t W[80];
        uint64_t H[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb42bd6bULL, 0x5be0cd19137e2179ULL
        };
        
    public:
        /* default class constructor */
        SHA512(std::string msg)
        {
        	// length in bytes.
            __uint128_t len = msg.length();
            
            // length is represented by a 128 bit unsigned integer
            __uint128_t bitlen = len << 3;
            
            // padding with zeros
            unsigned int padding = ((BLOCK_SIZE - (bitlen+1) - 128) % BLOCK_SIZE)-7;
            padding /= 8; // in bytes.
            
            // required b/c that adds random value to the end of WordArray
            int n_pad = len < 128 ? n_pad = padding+len+16 : n_pad = padding+len+17;
            uint8_t WordArray[n_pad];
            memset(WordArray, (uint8_t)'0', padding+len+17);
            for (int c=0;c<len;c++)
            {
                WordArray[c] = ((ucharptr)msg.c_str())[c];
            }
            WordArray[len] = (uint8_t)(1<<7); // append 10000000.

            for (int c=padding+len+17;c>padding+len+1;c--)
            {
                // WordArray[c] = BE128((uint8_t*)bitlen, bitlen)[c];
            }
            
            /* ====================== (WORD-ARRAY NOT DONE) ====================== */
            
            std::cout << WordArray;
            // std::cout << std::endl << "128B128B128B128B128B"
            //           << "8B128B128B128B128B128B128B128B128B128B128B128B128B128B"
            //           << "128B128B128B128B128B128B128B128B128B128B128B128B128B12"
            //           << std::endl;
            std::cout << std::endl;
            // convert WordArray uint8 to uint64_t // THIS PART ISNT DONE
            
            // pad W with zeros
            memset(W, (uint64_t)'0', 80);
            
            // WRONG. need to convert WArray to 64 bit array without more padding
            for (int c=0;c<(padding+len+17)/8;c++)
            {
                W[c] = WordArray[c]; // adds them as 8 bit instead of 64.
            } // right now its adding only 16 of the message bytes in uint8_t
             // format. There is 128 message bytes.

            /* ======================= (WORD NOT DONE) ======================== */
            
            // create message schedule
            for (int c=16;c<80;c++)
            {
                // σ0 = (w[c−15] ≫≫ 1) ⊕ (w[c−15] ≫ ≫8) ⊕ (w[c−15] ≫ 7)
                
                uint64_t s0 = Rotr(W[c-15],1) xor Rotr(W[c-15],8) xor Shr(W[c-15],7);
                
                // σ1 = (w[c−2]  ≫ ≫ 19) ⊕ (w[c−2]  ≫ ≫ 61) ⊕ (w[c−2]  ≫  6)
                
                uint64_t s1 = Rotr(W[c-2],19) xor Rotr(W[c-2],61) xor Shr(W[c-2],6);
                
                // uint64_t does binary addition 2^64.
                // w[c] = w[c−16] [+] σ0,c [+] w[c−7] [+] σ1,c
                W[c] = (W[c-16] + s0 + W[c-7] + s1);
            }
            
            uint64_t V[8]; // initialize non-constant hash values
            for(int c=0;c<8;c++)
            {
                V[c] = H[c];
            }
            
            // transform blocks
            for (int c=0;c<80;c++)
            {
                // Σ0 = (ac ≫≫ 28) ⊕ (ac ≫≫ 34) ⊕ (ac ≫≫ 39)
                
                uint64_t S0 = Rotr(V[c], 28) xor Rotr(V[c], 34) xor Rotr(V[c], 22);
                
                // t2 = Σ0,[c] + Maj[c]
                uint64_t temp2 = S0 + Maj(V[0], V[1], V[2]);
                
                // Σ1 = (e ≫≫ 14) ⊕ (e ≫≫ 18) ⊕ (e ≫≫ 41)
                
                uint64_t S1 = Rotr(V[4], 14) xor Rotr(V[4], 18) xor Rotr(V[4], 41);
                
                // t1 = h + Σ1 + Ch[e,f,g] + K[c] + W[c]
                uint64_t temp1 = V[7] + S1 + Ch(V[4], V[5], V[6]) + K[c] + W[c];
                
                // modify hash values
                V[7] = V[6];
                V[6] = V[5];
                V[5] = V[4];
                V[4] = V[3] + temp1;
                V[3] = V[2];
                V[2] = V[1];
                V[0] = temp1 + temp2;
            }
            
            // final values
            for (int c=0;c<8;c++)
            {
                H[c] += V[c];
                std::cout << std::hex << H[c];
                // hash length = wrong.
            }
            std::cout << "\n\n" << "cf83e1357eefb8bdf1542850d66d8007d620e4050b57"
                      << "15dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63"
                      << "b931bd47417a81a538327af927da3e" << std::endl
                      << "\t\t\t\t\t\t^ empty string hash value ^";
        }
        // return value
        std::string sha512()
        {
            return NULL;
        }
};

#endif /* SHA512_H_ */
