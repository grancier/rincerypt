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
 Issue Date: 26/08/2003

 This is an implementation of HMAC, the FIPS standard keyed hash function
*/

#ifndef _HMAC_H
#define _HMAC_H

#include <memory.h>
#include "sha512.h"

#if defined(__cplusplus)
extern "C"
{
#endif


#define HMAC_OK                0
#define HMAC_BAD_MODE         -1
#define HMAC_IN_DATA  0xffffffff
#define IN_BLOCK_LENGTH     SHA512_BLOCK_SIZE
#define OUT_BLOCK_LENGTH    SHA512_BLOCK_SIZE


typedef struct
{   unsigned char   key[SHA512_BLOCK_SIZE];
    SHA512_CTX         ctx[1];
    unsigned long   klen;
} hmac512_ctx;

/*
typedef struct
{   unsigned char   key[SHA256_BLOCK_SIZE];
    sha256_ctx         ctx[1];
    unsigned long   klen;
} hmac_ctx;
*/

#if defined(__cplusplus)
}
#endif

#endif
