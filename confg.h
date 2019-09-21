/*
*  confg.h defines config options for rinecrypt
*
*  Copyright (C) 2020 Gary Rancier <lodyssee@gmail.com>
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef CONFG_H
#define CONFG_H

/*  BLOCK_SIZE is in BYTES: 16, 24, 32 or undefined for aes.c and 16, 20,
    24, 28, 32 or undefined for aespp.c.  When left undefined a slower
    version that provides variable block length is compiled.
*/

#define DIR_ENCRYPT  7
#define DIR_DECRYPT 11
#define BAD_KEY_DIR -2
#define NORMAL_EXIT  0
#define ERROR_EXIT  -3
#define READ_ERROR  -4
#define WRITE_ERROR -5
#define ERR_NOT_HEX  -6
#define ERR_BAD_SIZE -7
#define ERR_NO_MEM   -8
#define OK 0

#define BLOCK_LEN   16
#define HASH_SIZE   32
#define SALT_SIZE   32
#define MAC_LEN     32
#define FID_LEN	    16
#define AES_KEY_LEN 32
#define DEC_STR_LEN 70
#define VER_LEN 2
#define EXT_LEN 4
#define TIMECODE 6
#define HEADER_SIZE (FID_LEN + VER_LEN + EXT_LEN + TIMECODE)

#define DO_CMP "100000ABAB000001"
#define FILE_EXT "RAES"
#define VER 998
#define KEY_DER_ITERS 72347
#define HMAC_ITERS 93191
#define INPUT_SIZE   128

#define strcmp_sha1(x, y) cmp_crypt_usr_string(x, y, DO_CMP)

#endif //CONFG_H

