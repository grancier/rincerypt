/*
*  rinecrypt.h AES encryptor/decryptor defines.
*
*  Copyright (C) 2002, 2003 Gary Rancier <mephis5@softhome.net>
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

#ifndef _RINECRYPT_H
#define _RINECRYPT_H

#include <stdio.h>
#include "aes.h"
#include "confg.h"

typedef unsigned int u32;
typedef unsigned char byte;

//struct for file manipulation
typedef struct{
	FILE *fin; //infile
	FILE *fout; //outfile
	char *ifn; //infile name
	char *ofn; //outfile name
}file_ctx;


//hash key with a salt for purposes of password compare/verification
unsigned char *sha1_crypt(unsigned char *key, unsigned char *salt);

//process user entered strings
void get_user_string(const char *prn_msg, unsigned char *user_string);

//generate authentication measures for ciphertxt and encrypt plaintxt
void enc_n_auth_file(file_ctx f_ctx);

//get authentication measures for ciphertxt and decrypt ciphertxt
void dec_n_auth_file(file_ctx f_ctx);

//check if user entered string was twice correctly inputted
int cmp_crypt_usr_string(unsigned char *usr_ent_str, unsigned char *usr_ent_str_cmp, const char *prn_msg);

//make a 32 byte key from a base-secret
void derive_key_sha512(const unsigned char pwd[],  /* the PASSWORD     */
               unsigned int pwd_len,        /* and its length   */
               unsigned char salt[],  /* the SALT and its */
               unsigned int salt_len,       /* length           */
               unsigned int iter,   /* the number of iterations */
               unsigned char key[], /* space for the output key */
               unsigned int key_len);/* and its required length  */

//make a 64 byte key from a base-secret
void derive_key_sha256(const unsigned char pwd[],  /* the PASSWORD     */
               unsigned int pwd_len,        /* and its length   */
               unsigned char salt[],  /* the SALT and its */
               unsigned int salt_len,       /* length           */
               unsigned int iter,   /* the number of iterations */
               unsigned char key[], /* space for the output key */
               unsigned int key_len);/* and its required length  */


//remove the character directly before the '\0' from a user entered string
void rm_last_char(unsigned char *a_string);

//create a string of raw unsigned chars from a user enetered HEX key
unsigned char *hex2bin(unsigned char *hex, int len);

//remove any spaces located before the '/0' from a user entered hex string
unsigned char *rm_space(unsigned char *has_space, int len);

//produce file MAC
void hmac_sha512_file (FILE *data, unsigned char *k, int lk, unsigned char *digest);

//improvised key derivation function
void super_der_key(const unsigned char *key, unsigned char *salt,
		unsigned char *digest, unsigned char *mac_key);

void secrand(unsigned char *buf, unsigned long nbytes);

#endif //_RINECRYPT_H
