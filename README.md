# sha512.cpp
sha512 in c++

Made By: Taha Canturk(Kibnakamoto)

Start Date: Dec. 5, 2021

Finalized in: Jan. 5, 2022

Email: taha.ez.ca@gmail.com

I made this code when I was 15.

This algorithm took me exactly a month to make (I didn't work on it everday btw). 


This algorithm only works for single block message until further updates

Warnings and need to know before using code:
____________________________________________________________________________________________________________________________________________________________
I used linux compilers to code this algorithm.

Warning: This code was made in c++ 20 and c++ compilers before c++17 might give warning: SHA512.h:122:18: warning: structured bindings only available with ‘-std=c++17’ or ‘-std=gnu++17’. But still works correctly for one block of data(1024 bits) which doesn't have anything to do with the compiler version since this code only works for single block computation of sha512. if you use an older compiler. Compare values to see if your version is working correctly.

I compiled it in c++ 14 with the warning provided in line 17 of this file but still worked same as c++17 or c++20.
tested without warning or error with c++17 and c++20 in linux. 

For Windows: stdint.h doesn't exist so, you can to download stdint.h from gntp-send/stdint.h at master for it to compile on Windows.

mac compilers should work as far as I can tell.
____________________________________________________________________________________________________________________________________________________________
_


length of message is represented by a 128 bit unsigned int that is converted into to 64 bit integers which are appended into the W-array.

operators are defined by macros.

equations: 

Σ0,i = (ai ≫ 28) ⊕ (ai ≫ 34) ⊕ (ai ≫ 39)

Maj i = (ai ∧ bi) ⊕ (ai ∧ ci) ⊕ (bi ∧ ci)

t2,i = Σ0,i [+] Maj i

Σ1,i = (ei ≫ 14) ⊕ (ei ≫ 18) ⊕ (ei ≫ 41)

Chi = (ei ∧ fi) ⊕ (¯ei ∧ gi)

t1,i = hi [+] Σ1,i [+] Chi [+] ki [+] wi

(hi+1, gi+1, fi+1, ei+1) = (gi, fi, ei, di [+] t1,i)

(di+1, ci+1, bi+1, ai+1) = (ci, bi, ai, t1,i [+] t2,i)

NOTE: [+] denotes binary addition. (x+y) mod 2^64.

constants:
```
        const uint64_t K[80] =
        {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
            0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
            0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
            0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 
            0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
            0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
            0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
            0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
            0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
            0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
            0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
            0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
            0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
            0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
        uint64_t H[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb42bd6bULL, 0x5be0cd19137e2179ULL};
```

for the a,b,c,d,e,f,g,h values. I used V array. defined as:
```
uint64_t V[8]; // initialize hash values
memcpy(V, H, sizeof(uint64_t)*8);
```

My code for sha512 in c++ has the smallest number of lines which is good because it shows that my implementation is one of the most efficient for this algorithm.
