/*
---------------------------------------------------------------------------
Copyright (c) 2002, Dr Brian Gladman <brg@gladman.me.uk>, Worcester, UK.
All rights reserved.

LICENSE TERMS

The free distribution and use of this software in both source and binary
form is allowed (with or without changes) provided that:

1. distributions of this source code include the above copyright
notice, this list of conditions and the following disclaimer;

2. distributions in binary form include the above copyright
notice, this list of conditions and the following disclaimer
in the documentation and/or other associated materials;

3. the copyright holder's name is not used to endorse products
built using this software without specific written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product
may be distributed under the terms of the GNU General Public License (GPL),
in which case the provisions of the GPL apply INSTEAD OF those given above.

DISCLAIMER

This software is provided 'as is' with no explicit or implied warranties
in respect of its properties, including, but not limited to, correctness
and/or fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 24/01/2003

This is an implementation of HMAC, the FIPS standard keyed hash function
*/

#include <memory.h>
#include <string.h>
#include "hmac.h"


#if defined(__cplusplus)
extern "C"
{
#endif

/* initialise the HMAC context to zero */
void hmac_sha512_init(hmac512_ctx cx[1])
{
	memset(cx, 0, sizeof(hmac512_ctx));
}

/* input the HMAC key (can be called multiple times)    */
int hmac_sha512_key(const unsigned char key[], unsigned long key_len, hmac512_ctx cx[1])
{
	if(cx->klen == HMAC_IN_DATA)                /* error if further key input   */
		return HMAC_BAD_MODE;                   /* is attempted in data mode    */

	if(cx->klen + key_len > SHA512_BLOCK_SIZE)    /* if the key has to be hashed  */
	{
		if(cx->klen <= SHA512_BLOCK_SIZE)         /* if the hash has not yet been */
		{                                       /* started, initialise it and   */
			SHA512_Init(cx->ctx);                /* hash stored key characters   */
			SHA512_Update(cx->ctx, cx->key, cx->klen);
		}

		SHA512_Update(cx->ctx, key, key_len);       /* hash long key data into hash */
	}
	else                                        /* otherwise store key data     */
		memcpy(cx->key + cx->klen, key, key_len);

	cx->klen += key_len;                        /* update the key length count  */
	return HMAC_OK;
}

/* input the HMAC data (can be called multiple times) - */
/* note that this call terminates the key input phase   */
void hmac_sha512_data(const unsigned char data[], unsigned long data_len, hmac512_ctx cx[1])
{
	unsigned int i;

	if(cx->klen != HMAC_IN_DATA)                /* if not yet in data phase */
	{
		if(cx->klen > SHA512_BLOCK_SIZE)          /* if key is being hashed   */
		{                                       /* complete the hash and    */
			SHA512_Final(cx->key, cx->ctx);         /* store the result as the  */
			cx->klen = SHA512_DIGEST_SIZE;        /* key and set new length   */
		}

		/* pad the key if necessary */
		memset(cx->key + cx->klen, 0, SHA512_BLOCK_SIZE - cx->klen);

		/* xor ipad into key value  */
		for(i = 0; i < (SHA512_BLOCK_SIZE >> 2); ++i)
			((unsigned long*)cx->key)[i] ^= 0x36363636;

		/* and start hash operation */
		SHA512_Init(cx->ctx);
		SHA512_Update(cx->ctx, cx->key, SHA512_BLOCK_SIZE);

		/* mark as now in data mode */
		cx->klen = HMAC_IN_DATA;
	}

	/* hash the data (if any)       */
	if(data_len)
		SHA512_Update(cx->ctx, data, data_len);
}

/* compute and output the MAC value */
void hmac_sha512_final(unsigned char mac[], unsigned long mac_len, hmac512_ctx cx[1])
{
	unsigned char dig[SHA512_DIGEST_SIZE];
	unsigned int i;

	/* if no data has been entered perform a null data phase        */
	if(cx->klen != HMAC_IN_DATA)
		hmac_sha512_data((const unsigned char*)0, 0, cx);

	SHA512_Final(dig, cx->ctx);         /* complete the inner hash      */

	/* set outer key value using opad and removing ipad */
	for(i = 0; i < (SHA512_BLOCK_SIZE >> 2); ++i)
		((unsigned long*)cx->key)[i] ^= 0x36363636 ^ 0x5c5c5c5c;

	/* perform the outer hash operation */
	SHA512_Init(cx->ctx);
	SHA512_Update(cx->ctx, cx->key, SHA512_BLOCK_SIZE);
	SHA512_Update(cx->ctx, dig, SHA512_DIGEST_SIZE);
	SHA512_Final(dig, cx->ctx);

	/* output the hash value            */
	for(i = 0; i < mac_len; ++i)
		mac[i] = dig[i];
}

/* 'do it all in one go' subroutine     */
void hmac_sha512(const unsigned char key[], unsigned int key_len,
		const unsigned char data[], unsigned int data_len,
		unsigned char mac[], unsigned int mac_len)
{
	hmac512_ctx    cx[1];

	hmac_sha512_init(cx);
	hmac_sha512_key(key, key_len, cx);
	hmac_sha512_data(data, data_len, cx);
	hmac_sha512_final(mac, mac_len, cx);
}

//based on PKCS5V2
void derive_key_sha512(const unsigned char pwd[],  /* the PASSWORD     */
               unsigned int pwd_len,        /* and its length   */
               unsigned char salt[],  /* the SALT and its */
               unsigned int salt_len,       /* length           */
               unsigned int iter,   /* the number of iterations */
               unsigned char key[], /* space for the output key */
               unsigned int key_len)/* and its required length  */
{
    unsigned int    i, j, k, n_blk;
    unsigned char uu[SHA512_DIGEST_SIZE], ux[SHA512_DIGEST_SIZE];
    hmac512_ctx c1[1], c2[1], c3[1];

    /* set HMAC context (c1) for password               */
    hmac_sha512_init(c1);
    hmac_sha512_key(pwd, pwd_len, c1);

    /* set HMAC context (c2) for password and salt      */
    memcpy(c2, c1, sizeof(hmac512_ctx));
    hmac_sha512_data(salt, salt_len, c2);

    /* find the number of SHA blocks in the key         */
    n_blk = 1 + (key_len - 1) / SHA512_DIGEST_SIZE;

    for(i = 0; i < n_blk; ++i) /* for each block in key */
    {
        /* ux[] holds the running xor value             */
        memset(ux, 0, SHA512_DIGEST_SIZE);

        /* set HMAC context (c3) for password and salt  */
        memcpy(c3, c2, sizeof(hmac512_ctx));

        /* enter additional data for 1st block into uu  */
        uu[0] = (unsigned char)((i + 1) >> 24);
        uu[1] = (unsigned char)((i + 1) >> 16);
        uu[2] = (unsigned char)((i + 1) >> 8);
        uu[3] = (unsigned char)(i + 1);

        /* this is the key mixing iteration         */
        for(j = 0, k = 4; j < iter; ++j)
        {
            /* add previous round data to HMAC      */
            hmac_sha512_data(uu, k, c3);

            /* obtain HMAC for uu[]                 */
            hmac_sha512_final(uu, SHA512_DIGEST_SIZE, c3);

            /* xor into the running xor block       */
            for(k = 0; k < SHA512_DIGEST_SIZE; ++k)
                ux[k] ^= uu[k];

            /* set HMAC context (c3) for password   */
            memcpy(c3, c1, sizeof(hmac512_ctx));
        }

        /* compile key blocks into the key output   */
        j = 0; k = i * SHA512_DIGEST_SIZE;
        while(j < SHA512_DIGEST_SIZE && k < key_len)
            key[k++] = ux[j++];
    }
}


#if defined(__cplusplus)
}
#endif
