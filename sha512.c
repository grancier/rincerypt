/* sha512.c */
/* ====================================================================
 *  * Copyright (c) 2004 The OpenSSL Project.  All rights reserved
 *  * according to the OpenSSL license [found in ../../LICENSE].
 *  * ====================================================================
 *  */

/*
 *  * IMPLEMENTATION NOTES.
 *  *
 *  * As you might have noticed 32-bit hash algorithms:
 *  *
 *  * - permit SHA_LONG to be wider than 32-bit (case on CRAY);
 *  * - optimized versions implement two transform functions: one operating
 *  *   on [aligned] data in host byte order and one - on data in input
 *  *   stream byte order;
 *  * - share common byte-order neutral collector and padding function
 *  *   implementations, ../md32_common.h;
 *  *
 *  * Neither of the above applies to this SHA-512 implementations. Reasons
 *  * [in reverse order] are:
 *  *
 *  * - it's the only 64-bit hash algorithm for the moment of this writing,
 *  *   there is no need for common collector/padding implementation [yet];
 *  * - by supporting only one transform function [which operates on
 *  *   *aligned* data in input stream byte order, big-endian in this case]
 *  *   we minimize burden of maintenance in two ways: a) collector/padding
 *  *   function is simpler; b) only one transform function to stare at;
 *  * - SHA_LONG64 is required to be exactly 64-bit in order to be able to
 *  *   apply a number of optimizations to mitigate potential performance
 *  *   penalties caused by previous design decision;
 *  *
 *  * Caveat lector.
 *  *
 *  * Implementation relies on the fact that "long long" is 64-bit on
 *  * both 32- and 64-bit platforms. If some compiler vendor comes up
 *  * with 128-bit long long, adjustment to sha.h would be required.
 *  * As this implementation relies on 64-bit integer type, it's totally
 *  * inappropriate for platforms which don't support it, most notably
 *  * 16-bit platforms.
 *  *                                      <appro@fy.chalmers.se>
 *  */

/* 
 * 08/20/2008 Simplified by Gary Rancier through gcc -E for use as standalone 
 * procedures, without using the full OpenSSL API. 
 *
 */

#include <stdlib.h>
#include <string.h>
#include "sha512.h"

unsigned char cleanse_ctr = 0;

void OPENSSL_cleanse(void *ptr, size_t len)
{
    unsigned char *p = ptr;
    size_t loop = len, ctr = cleanse_ctr;
    while (loop--) {
        *(p++) = (unsigned char) ctr;
        ctr += (17 + ((size_t) p & 0xF));
    }

    p = memchr(ptr, (unsigned char) ctr, len);

    if (p)
        ctr += (63 + (size_t) p);
    cleanse_ctr = (unsigned char) ctr;
}

int SHA384_Init(SHA512_CTX *c)
{
    c->h[0] = 0xcbbb9d5dc1059ed8ULL;
    c->h[1] = 0x629a292a367cd507ULL;
    c->h[2] = 0x9159015a3070dd17ULL;
    c->h[3] = 0x152fecd8f70e5939ULL;
    c->h[4] = 0x67332667ffc00b31ULL;
    c->h[5] = 0x8eb44a8768581511ULL;
    c->h[6] = 0xdb0c2e0d64f98fa7ULL;
    c->h[7] = 0x47b5481dbefa4fa4ULL;
    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = 48;
    return 1;
}

int SHA512_Init(SHA512_CTX *c)
{
    c->h[0] = 0x6a09e667f3bcc908ULL;
    c->h[1] = 0xbb67ae8584caa73bULL;
    c->h[2] = 0x3c6ef372fe94f82bULL;
    c->h[3] = 0xa54ff53a5f1d36f1ULL;
    c->h[4] = 0x510e527fade682d1ULL;
    c->h[5] = 0x9b05688c2b3e6c1fULL;
    c->h[6] = 0x1f83d9abfb41bd6bULL;
    c->h[7] = 0x5be0cd19137e2179ULL;
    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = 64;
    return 1;
}

int SHA512_Final(unsigned char *md, SHA512_CTX *c)
{
    unsigned char *p = (unsigned char *) c->u.p;
    size_t n = c->num;

    p[n] = 0x80;
    n++;
    if (n > (sizeof (c->u) - 16))
        memset(p + n, 0, sizeof (c->u) - n), n = 0,
            sha512_block_data_order(c, p, 1);

    memset(p + n, 0, sizeof (c->u) - 16 - n);

    p[sizeof (c->u) - 1] = (unsigned char) (c->Nl);
    p[sizeof (c->u) - 2] = (unsigned char) (c->Nl >> 8);
    p[sizeof (c->u) - 3] = (unsigned char) (c->Nl >> 16);
    p[sizeof (c->u) - 4] = (unsigned char) (c->Nl >> 24);
    p[sizeof (c->u) - 5] = (unsigned char) (c->Nl >> 32);
    p[sizeof (c->u) - 6] = (unsigned char) (c->Nl >> 40);
    p[sizeof (c->u) - 7] = (unsigned char) (c->Nl >> 48);
    p[sizeof (c->u) - 8] = (unsigned char) (c->Nl >> 56);
    p[sizeof (c->u) - 9] = (unsigned char) (c->Nh);
    p[sizeof (c->u) - 10] = (unsigned char) (c->Nh >> 8);
    p[sizeof (c->u) - 11] = (unsigned char) (c->Nh >> 16);
    p[sizeof (c->u) - 12] = (unsigned char) (c->Nh >> 24);
    p[sizeof (c->u) - 13] = (unsigned char) (c->Nh >> 32);
    p[sizeof (c->u) - 14] = (unsigned char) (c->Nh >> 40);
    p[sizeof (c->u) - 15] = (unsigned char) (c->Nh >> 48);
    p[sizeof (c->u) - 16] = (unsigned char) (c->Nh >> 56);


    sha512_block_data_order(c, p, 1);

    if (md == 0) return 0;

    switch (c->md_len)
    {

        case 48:
            for (n = 0; n < 48 / 8; n++) {
                unsigned long long t = c->h[n];

                *(md++) = (unsigned char) (t >> 56);
                *(md++) = (unsigned char) (t >> 48);
                *(md++) = (unsigned char) (t >> 40);
                *(md++) = (unsigned char) (t >> 32);
                *(md++) = (unsigned char) (t >> 24);
                *(md++) = (unsigned char) (t >> 16);
                *(md++) = (unsigned char) (t >> 8);
                *(md++) = (unsigned char) (t);
            }
            break;
        case 64:
            for (n = 0; n < 64 / 8; n++) {
                unsigned long long t = c->h[n];

                *(md++) = (unsigned char) (t >> 56);
                *(md++) = (unsigned char) (t >> 48);
                *(md++) = (unsigned char) (t >> 40);
                *(md++) = (unsigned char) (t >> 32);
                *(md++) = (unsigned char) (t >> 24);
                *(md++) = (unsigned char) (t >> 16);
                *(md++) = (unsigned char) (t >> 8);
                *(md++) = (unsigned char) (t);
            }
            break;

        default: return 0;
    }

    return 1;
}

int SHA384_Final(unsigned char *md, SHA512_CTX *c)
{
    return SHA512_Final(md, c);
}

int SHA512_Update(SHA512_CTX *c, const void *_data, size_t len)
{
    unsigned long long l;
    unsigned char *p = c->u.p;
    const unsigned char *data = (const unsigned char *) _data;

    if (len == 0) return 1;

    l = (c->Nl + (((unsigned long long) len) << 3))&0xffffffffffffffffULL;
    if (l < c->Nl) c->Nh++;
    if (sizeof (len) >= 8) c->Nh += (((unsigned long long) len) >> 61);
    c->Nl = l;

    if (c->num != 0) {
        size_t n = sizeof (c->u) - c->num;

        if (len < n) {
            memcpy(p + c->num, data, len), c->num += len;
            return 1;
        } else {
            memcpy(p + c->num, data, n), c->num = 0;
            len -= n, data += n;
            sha512_block_data_order(c, p, 1);
        }
    }

    if (len >= sizeof (c->u)) {
        sha512_block_data_order(c, data, len / sizeof (c->u)),
                data += len,
                len %= sizeof (c->u),
                data -= len;
    }

    if (len != 0) memcpy(p, data, len), c->num = (int) len;

    return 1;
}

int SHA384_Update(SHA512_CTX *c, const void *data, size_t len)
{
    return SHA512_Update(c, data, len);
}

void SHA512_Transform(SHA512_CTX *c, const unsigned char *data)
{
    sha512_block_data_order(c, data, 1);
}

unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA512_CTX c;
    static unsigned char m[48];

    if (md == ((void *) 0)) md = m;
    SHA384_Init(&c);
    SHA512_Update(&c, d, n);
    SHA512_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof (c));
    return (md);
}

unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA512_CTX c;
    static unsigned char m[64];

    if (md == ((void *) 0)) md = m;
    SHA512_Init(&c);
    SHA512_Update(&c, d, n);
    SHA512_Final(md, &c);
    OPENSSL_cleanse(&c, sizeof (c));
    return (md);
}
