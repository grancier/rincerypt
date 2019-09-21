/*
*  dencrypt.c rinecrypt encrypt/decrypt engine
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

/*  CT STEALING
*
*  CT stealing modifies the encryption of the last two CBC
*  blocks. It can be applied invariably to the last two plaintext
*  blocks or only applied when the last block is a partial one. In
*  this code it is only applied if there is a partial block.  For
*  a plaintext consisting of N blocks, with the last block possibly
*  a partial one, CT stealing works as shown below (note the
*  reversal of the last two CT blocks).  During decryption
*  the part of the C:N-1 block that is not transmitted (X) can be
*  obtained from the decryption of the penultimate CT block
*  since the bytes in X are xored with the zero padding appended to
*  the last plaintext block.
*
*  This is a picture of the processing of the last
*  plaintext blocks during encryption:
*
*    +---------+   +---------+   +---------+   +-------+-+
*    |  P:N-4  |   |  P:N-3  |   |  P:N-2  |   | P:N-1 |0|
*    +---------+   +---------+   +---------+   +-------+-+
*         |             |             |             |
*         v             v             v             v
*  +----->x      +----->x      +----->x      +----->x   x = xor
*  |      |      |      |      |      |      |      |
*  |      v      |      v      |      v      |      v
*  |    +---+    |    +---+    |    +---+    |    +---+
*  |    | E |    |    | E |    |    | E |    |    | E |
*  |    +---+    |    +---+    |    +---+    |    +---+
*  |      |      |      |      |      |      |      |
*  |      |      |      |      |      v      |  +---+
*  |      |      |      |      | +-------+-+ |  |
*  |      |      |      |      | | C:N-1 |X| |  |
*  |      |      |      |      | +-------+-+ ^  |
*  |      |      |      |      |     ||      |  |
*  |      |      |      |      |     |+------+  |
*  |      |      |      |      |     +----------|--+
*  |      |      |      |      |                |  |
*  |      |      |      |      |      +---------+  |
*  |      |      |      |      |      |            |
*  |      v      |      v      |      v            v
*  | +---------+ | +---------+ | +---------+   +-------+
* -+ |  C:N-4  |-+ |  C:N-3  |-+ |  C:N-2  |   | C:N-1 |
*    +---------+   +---------+   +---------+   +-------+
*
*  And this is a picture of the processing of the last
*  CT blocks during decryption:
*
*    +---------+   +---------+   +---------+   +-------+
* -+ |  C:N-4  |-+ |  C:N-3  |-+ |  C:N-2  |   | C:N-1 |
*  | +---------+ | +---------+ | +---------+   +-------+
*  |      |      |      |      |      |            |
*  |      v      |      v      |      v   +--------|----+
*  |    +---+    |    +---+    |    +---+ |  +--<--+    |
*  |    | D |    |    | D |    |    | D | |  |     |    |
*  |    +---+    |    +---+    |    +---+ |  |     v    v
*  |      |      |      |      |      |   ^  | +-------+-+
*  |      v      |      v      |      v   |  | | C:N-1 |X|
*  +----->x      +----->x      | +-------+-+ | +-------+-+
*         |             |      | |       |X| |      |
*         |             |      | +-------+-+ |      v
*         |             |      |     |       |    +---+
*         |             |      |     |       v    | D |
*         |             |      |     +------>x    +---+
*         |             |      |             |      |
*         |             |      +----->x<-----|------+   x = xor
*         |             |             |      +-----+
*         |             |             |            |
*         v             v             v            v
*    +---------+   +---------+   +---------+   +-------+
*    |  P:N-4  |   |  P:N-3  |   |  P:N-2  |   | P:N-1 |
*    +---------+   +---------+   +---------+   +-------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "rinecrypt.h"
#include "memory.h"
//patina


int encfile(file_ctx f_ctx, aes_context ctx[1])
{   
	byte *dbuf = (byte *)xmalloc_secure(5 * BLOCK_LEN);
    	unsigned long i, len, wlen = BLOCK_LEN, infile_size, rlen;
	int count = 0;

	// When ciphertext stealing is used, we have three ciphertext blocks so
	// we use a buffer that is three times the block length.  The buffer
	// pointers b1, b2 and b3 point to the buffer positions of three
	// ciphertext blocks, b3 being the most recent and b1 being the
	// oldest. We start with the IV in b1 and the block to be decrypted
	// in b2.
	
	// set a random IV
	
	secrand((byte *)dbuf, BLOCK_LEN * sizeof(byte));
	
	//get the size of the plaintext
	fseek(f_ctx.fin, 0, SEEK_END);
	rlen = infile_size = ftell(f_ctx.fin);
	rewind(f_ctx.fin);

	//seek the CT to after the header
	//everything that's written after is the CT
	fseek(f_ctx.fout, HEADER_SIZE, SEEK_SET);

	fprintf(stdout, "\nEncrypting.\n");

	// read the first file block
	len = (unsigned long) fread((char*)dbuf + BLOCK_LEN, 1, BLOCK_LEN, f_ctx.fin);
	
	if(len < BLOCK_LEN)
	{   // if the file length is less than one block
	
		// xor the file bytes with the IV bytes
		for(i = 0; i < len; ++i)
		dbuf[i + BLOCK_LEN] ^= dbuf[i];
	
		// encrypt the top 16 bytes of the buffer
		aes_encrypt(ctx, dbuf + len, dbuf + len);
	
		len += BLOCK_LEN;
		// write the IV and the encrypted file bytes
		if(fwrite((char*)dbuf, 1, len, f_ctx.fout) != len)
		return WRITE_ERROR;
	
		return OK;
	}
	else    // if the file length is more 16 bytes
	{   unsigned char *b1 = dbuf, *b2 = b1 + BLOCK_LEN, *b3 = b2 + BLOCK_LEN, *bt;
	
		// write the IV
		if(fwrite((char*)dbuf, 1, BLOCK_LEN, f_ctx.fout) != BLOCK_LEN)
		return WRITE_ERROR;
	
		for( ; ; )
		{
			// read the next block to see if ciphertext stealing is needed
			len = (unsigned long)fread((char*)b3, 1, BLOCK_LEN, f_ctx.fin);
		
			// do CBC chaining prior to encryption for current block (in b2)
			for(i = 0; i < BLOCK_LEN; ++i)
				b1[i] ^= b2[i];
		
			// encrypt the block (now in b1)
			aes_encrypt(ctx, b1, b1);
		
			if(len != 0 && len != BLOCK_LEN)    // use ciphertext stealing
			{
				// set the length of the last block
				wlen = len;
		
				// xor ciphertext into last block
				for(i = 0; i < len; ++i)
				b3[i] ^= b1[i];
		
				// move 'stolen' ciphertext into last block
				for(i = len; i < BLOCK_LEN; ++i)
				b3[i] = b1[i];
		
				// encrypt this block
				aes_encrypt(ctx, b3, b3);
		
				// and write it as the second to last encrypted block
				if(fwrite((char*)b3, 1, BLOCK_LEN, f_ctx.fout) != BLOCK_LEN)
				return WRITE_ERROR;
			}
		
			// write the encrypted block
			if(fwrite((char*)b1, 1, wlen, f_ctx.fout) != wlen)
				return WRITE_ERROR;
		
			if(len != BLOCK_LEN)
				return OK;
		
			// advance the buffer pointers
			bt = b3, b3 = b2, b2 = b1, b1 = bt;
			
			if (((infile_size - rlen) / (float)infile_size) * 100.0f > count)
				fprintf(stderr, " Blocks completed:  %3.0i%%\t\r", count++);

  			rlen -= len;
		}
	}
	
	fprintf(stdout, "\n");
	wipememory(dbuf, 3 * BLOCK_LEN);
	xfree(dbuf);
	return OK;
}

int decfile(file_ctx f_ctx, aes_context ctx[1])
{   
	unsigned char dbuf[3 * BLOCK_LEN], buf[BLOCK_LEN];
	unsigned long i, len, wlen = BLOCK_LEN,  infile_size, rlen;
	int count = 0;
	
	// When ciphertext stealing is used, we three ciphertext blocks so
	// we use a buffer that is three times the block length.  The buffer
	// pointers b1, b2 and b3 point to the buffer positions of three
	// ciphertext blocks, b3 being the most recent and b1 being the
	// oldest. We start with the IV in b1 and the block to be decrypted
	// in b2.
	
	// find the file length
	fseek(f_ctx.fin, HEADER_SIZE, SEEK_END);
	infile_size = rlen = ftell(f_ctx.fin);
	fseek(f_ctx.fin, HEADER_SIZE, SEEK_SET);

	fprintf(stdout, "\nDecrypting.\n");

	len = (unsigned long)fread((char*)dbuf, 1, 2 * BLOCK_LEN, f_ctx.fin);
	
	if(len < 2 * BLOCK_LEN) // the original file is less than one block in length
	{
		len -= BLOCK_LEN;
		// decrypt from position len to position len + BLOCK_LEN
		aes_decrypt(ctx, dbuf + len, dbuf + len);
	
		// undo the CBC chaining
		for(i = 0; i < len; ++i)
		dbuf[i] ^= dbuf[i + BLOCK_LEN];
	
		// output the decrypted bytes
		if(fwrite((char*)dbuf, 1, len, f_ctx.fout) != len)
		return WRITE_ERROR;
	
		return OK;
	}
	else
	{   
		unsigned char *b1 = dbuf, *b2 = b1 + BLOCK_LEN, *b3 = b2 + BLOCK_LEN, *bt;
	
		for( ; ; )  // while some ciphertext remains, prepare to decrypt block b2
		{
			// read in the next block to see if ciphertext stealing is needed
			len = fread((char*)b3, 1, BLOCK_LEN, f_ctx.fin);
		
			// decrypt the b2 block
			aes_decrypt(ctx, b2, buf);
		
			if(len == 0 || len == BLOCK_LEN)    // no ciphertext stealing
			{
				// unchain CBC using the previous ciphertext block in b1
				for(i = 0; i < BLOCK_LEN; ++i)
				buf[i] ^= b1[i];
			}
			else    // partial last block - use ciphertext stealing
			{
				wlen = len;
		
				// produce last 'len' bytes of plaintext by xoring with
				// the lowest 'len' bytes of next block b3 - C[N-1]
				for(i = 0; i < len; ++i)
				buf[i] ^= b3[i];
		
				// reconstruct the C[N-1] block in b3 by adding in the
				// last (BLOCK_LEN - len) bytes of C[N-2] in b2
				for(i = len; i < BLOCK_LEN; ++i)
				b3[i] = buf[i];
		
				// decrypt the C[N-1] block in b3
				aes_decrypt(ctx, b3, b3);
		
				// produce the last but one plaintext block by xoring with
				// the last but two ciphertext block
				for(i = 0; i < BLOCK_LEN; ++i)
				b3[i] ^= b1[i];
		
				// write decrypted plaintext blocks
				if(fwrite((char*)b3, 1, BLOCK_LEN, f_ctx.fout) != BLOCK_LEN)
				return WRITE_ERROR;
			}
		
			// write the decrypted plaintext block
			if(fwrite((char*)buf, 1, wlen, f_ctx.fout) != wlen)
				return WRITE_ERROR;
		
			if(len != BLOCK_LEN)
				return OK;
		
			// advance the buffer pointers
			bt = b1, b1 = b2, b2 = b3, b3 = bt;
		
			if (((infile_size - rlen) / (float)infile_size) * 100.0f > count)
				fprintf(stderr, " Blocks completed:  %3.0i%%\t\r", count++);

  			rlen -= len;
		}
	}
	fprintf(stdout, "\n\n");
	return OK;
}

void enc_n_auth_file(file_ctx f_ctx)
{
	aes_context *a_ctx = (aes_context *)xmalloc_secure(sizeof(aes_context));
	byte *usr_pwd = (unsigned char *)xmalloc_secure(64 + 1); //usr entered string
	byte *hmac_bytes  = (byte *)xmalloc_secure(64 + 1); //holds MAC
	byte *cipher_key  = (byte *)xmalloc_secure(AES_KEY_LEN + 1); //holds derived key
	byte *salt    = (byte *)xmalloc_secure(SALT_SIZE + 1); //random salt for ker derivation
	byte *mac_key = (byte *)xmalloc_secure(AES_KEY_LEN + 1); //key for hmac
	byte *prn_out = (byte *)xmalloc_secure(DEC_STR_LEN + 6); //strings to be printed to user
	byte *timestr = (byte *)xmalloc_secure(7);
	byte hdr_buf[HEADER_SIZE + 1] = {0}; //holds the header ( extension + version + file id)
	byte ct_id[FID_LEN + 1]; //ciphertext id
	byte ver_bytes[VER_LEN+1]; //implicit cast of version
	byte timeout[6] = {0};
	time_t timenow = time(NULL);
	byte *ptr = 0;
	int err, i, j, f;
	FILE *crypfile = f_ctx.fout;

/*generate CT header*/

	//append the CT extension to the header
	strcat((char *)hdr_buf, FILE_EXT);

	//cast ct_id implicitly into bytes
	for (i = (2 - 1); i >= 0; i--)
		ver_bytes[i] = VER >> (8 * (i & 15));

	//append the version bytes to the header
	for (i = EXT_LEN, j = 0; i < VER_LEN + EXT_LEN; i++)
  		hdr_buf[i] = ver_bytes[j++];

	//get a random ciphertext id
	secrand(ct_id, FID_LEN * sizeof(byte));

	//append the ciphertext id to the header
	for (i = (VER_LEN + EXT_LEN), j = 0; i < HEADER_SIZE; i++)
		hdr_buf[i] = ct_id[j++];

	for (f = 0; f < 5; f++)
		timeout[f] |= timenow >> (f * 8);

	for (i = (VER_LEN + EXT_LEN + FID_LEN), j = 0; i < HEADER_SIZE; i++)
		hdr_buf[i] = timeout[j++];

	//write the header to the ciphertext
	fwrite(hdr_buf, sizeof(byte), HEADER_SIZE, crypfile);

/* get usr passwd + generate keys + encrypt */

	//get the user supplied password
	printf("\n");
	get_user_string("Password", usr_pwd);

	//generate a random SALT_SIZE salt
	secrand(salt, SALT_SIZE * sizeof(byte));

	//get a 32 byte AES key, and a 32 byte MAC key
	//from the user-entered string, and the random salt
	
	derive_key_sha512(usr_pwd,  /* the PASSWORD     */
               strlen((const char *)usr_pwd),        /* and its length   */
               salt,  /* the SALT and its */
               SALT_SIZE,       /* length           */
               HMAC_ITERS,   /* the number of iterations */
               cipher_key, /* space for the output key */
               AES_KEY_LEN);/* and its required length  */

	//make the AES key from the derived key
	aes_set_key(a_ctx, cipher_key, 256, 1);

	//encrypt infile
	err = encfile(f_ctx, a_ctx);

	if (err == READ_ERROR)
	{
		fprintf(stderr, "ERROR could not read from %s\n", f_ctx.ifn);
		exit(ERROR_EXIT);
	}
	if (err == WRITE_ERROR)
	{
		fprintf(stderr, "ERROR could not write to %s\n", f_ctx.ofn);
		exit(ERROR_EXIT);
	}

	//get the ciphertext MAC, and write it to 'hmac_bytes'
	hmac_sha512_file(crypfile, mac_key, MAC_LEN, hmac_bytes);

/* print auth info for CT */

	// ?write function to print meta-info in a standard way?

	//print ciphertxt ID as a hex code
	ptr = prn_out;
	for (i = 0; i < FID_LEN; i++)
	{
		if ((i < 4 && (i % 2) == 0) || ((i > 7) && (i % 3) ==0))
			*ptr++ = ' ';

		sprintf((char *)ptr, "%02X", ct_id[i]);
		ptr += 2;
	}
	
	sprintf((char *)timestr, "%s", (const char *)asctime(localtime(&timenow)));	
	
	prn_out[FID_LEN + 18] = ' ';
	for (f = 0;f< 24; f++)
		prn_out[f + FID_LEN + 19] = timestr[f];
	
	fprintf(stdout, "\n\n%90s", prn_out);
	fprintf(stdout, "\rCT ID: \n");

	memset(prn_out, 0, DEC_STR_LEN);

	//print the salt used for key derivation as a hex code
	ptr = prn_out;
	for (i = 0; i < SALT_SIZE; i++)
	{
		if (i == 1 || i == 2 || i == 3 || i == 5 || i == 7 || i == 11 || i == 13)
			*ptr++ = ' ';

		sprintf((char *)ptr, "%02X", salt[i]);
		ptr += 2;
	}
	fprintf(stdout, "%90s", prn_out);
	fprintf(stdout, "\rSalt: \n");

	memset(prn_out, 0, DEC_STR_LEN);

	//print ciphertxt MAC as a hex code
	ptr = prn_out;
	for (i = 0; i < HASH_SIZE; i++)
	{
		if (i % 4 == 0)
			*ptr++ = ' ';

		sprintf((char *)ptr, "%02X", hmac_bytes[i]);
		ptr += 2;
	}
	fprintf(stdout, "%90s", prn_out);
	fprintf(stdout, "\rCT MAC: \n\n");

/*clear and free vars*/

	wipememory(hmac_bytes, 20);
	wipememory(prn_out, DEC_STR_LEN);
	wipememory(salt, SALT_SIZE);
	wipememory(cipher_key, AES_KEY_LEN);
	wipememory(a_ctx, sizeof(aes_context));
	wipememory(usr_pwd, strlen((const char *)usr_pwd));
	wipememory(usr_pwd, AES_KEY_LEN);

	xfree(hmac_bytes);
	xfree(prn_out);
	xfree(salt);
	xfree(cipher_key);
	xfree(a_ctx);
	xfree(usr_pwd);
	xfree(mac_key);
}


int dec_n_auth_file(file_ctx f_ctx)
{
	aes_context *a_dec_ctx = (aes_context *)xmalloc_secure(sizeof(aes_context));
	byte *hmac_bytes  = (byte *)xmalloc_secure(128 + 1);
	byte *cipher_key  = (byte *)xmalloc_secure(64 + 1);
	unsigned char *usr_pwd = (unsigned char *)xmalloc_secure(64 + 1);
	byte *salt    = (byte *)xmalloc_secure(64 + 1);
	byte *mac_key = (byte *)xmalloc_secure(64 + 1);
	unsigned char *prn_out = (byte *)xmalloc_secure(128 + 2);
	byte *timestr = (byte *)xmalloc_secure(7);

	byte hdr_buf[HEADER_SIZE + 1];
	byte d2[HASH_SIZE + 1];
	char ver_str[5];
	int err, j, i;

	FILE *crypfile = f_ctx.fin;
	byte *ptr = 0;
	byte *salt_ptr;
	short ver_short = 0;
	time_t timethen = 0;


/*get CT header + print ver + print CT I.D.*/

	//get the ciphertext header
	rewind(f_ctx.fin);
	if (fread(hdr_buf, sizeof(byte), HEADER_SIZE, f_ctx.fin) != HEADER_SIZE)
		return -1;

	//cast version bytes from ciphertext from byte to  short
	for (i = EXT_LEN, j = 0; i < VER_LEN + EXT_LEN; ++i, ++j)
		ver_short ^= (short)hdr_buf[i] << (8 * (j & 15));

	//convert version number to a string
	sprintf(ver_str, "%d", ver_short);

	//print version of the ciphertext (version of rinecrypt with which CT was encrypted)
	if (ver_short < 1000)
		printf("\nCT ver: 0.%c.%c\n", ver_str[0], ver_str[1]);
	else
		printf("\nCT ver: %c.%c.%c\n", ver_str[0], ver_str[1], ver_str[2]);

	//print the ciphertext ID
	ptr = prn_out;
	for (i = (VER_LEN + EXT_LEN),j = 0; i < (HEADER_SIZE - TIMECODE - 1); i++,j++)
	{
		
		if ((j < 4 && (j % 2) == 0) || ((j > 7) && (j % 3) ==0))
			*ptr++ = ' ';

		sprintf((char *)ptr, "%02X", hdr_buf[i]);
		ptr += 2;
	}


	for (i = (VER_LEN + EXT_LEN + FID_LEN), j = 0; i < HEADER_SIZE; ++i, ++j)
      			 timethen |= (time_t)(hdr_buf[i]) << (j * 8);
	
	sprintf((char *)timestr, "%s", (const char *)asctime(localtime(&timethen)));	

	//printf(" %s  %i\n", timestr, strlen(timestr));
	prn_out[FID_LEN + 18] = ' ';
	for (j = 0; j < 24; j++)
		prn_out[j + FID_LEN + 19] = timestr[j];

	fprintf(stdout, "\n%90s", prn_out);
	fprintf(stdout, "\rCT ID: \n\n");
	
/* get usr passwd, salt + generate keys */

	//prompt for password
	get_user_string("Password", usr_pwd);

	//prompt for the ciphertext salt
	printf("\n");
	get_user_string("Salt", salt);

	//remove any spaces that might be in the salt
	salt_ptr = rm_space(salt, strlen((const char *)salt));

	//convert entered salt from hex to raw bytes
	ptr = hex2bin(salt_ptr, strlen((const char *)salt_ptr));
	while(!ptr)
	{
		printf("Salt not hex.\n");
		get_user_string("Salt", salt);
		salt_ptr = rm_space(salt, strlen((const char *)salt));
		ptr = hex2bin(salt_ptr, strlen((const char *)salt_ptr));
	}
	wipememory(salt_ptr, strlen((const char *)salt_ptr));
	xfree(salt_ptr);

	derive_key_sha512(usr_pwd,  /* the PASSWORD     */
               strlen((const char *)usr_pwd),        /* and its length   */
               ptr,  /* the SALT and its */
               SALT_SIZE,       /* length           */
               HMAC_ITERS,   /* the number of iterations */
               cipher_key, /* space for the output key */
               AES_KEY_LEN);/* and its required length  */

	wipememory(ptr, strlen((const char *)ptr));
	xfree(ptr);

/* authenticate CT */

	//calculate ciphertxt MAC
	hmac_sha512_file (crypfile, mac_key, MAC_LEN, hmac_bytes);

	//trim the mac to HASH_SIZE
	for (i = 0 ; i < HASH_SIZE; i++)
		d2[i] = hmac_bytes[i];

	printf("\n\n");
	//prompt user to enter the mac received along with decryption key
	get_user_string("CT MAC", usr_pwd);

	//rm any spaces in the MAC
	salt_ptr = rm_space(usr_pwd, strlen((const char *)usr_pwd));

 	//convert user-entered hex MAC to raw bytes
	ptr = hex2bin(salt_ptr, strlen((const char *)salt_ptr));
	while(!ptr)
	{
		printf("CT MAC not hex.\n");
		get_user_string("CT MAC", usr_pwd);
		salt_ptr = rm_space(usr_pwd, strlen((const char *)usr_pwd));
		ptr = hex2bin(salt_ptr, strlen((const char *)salt_ptr));
	}

	//compare the raw user-entered MAC with the one produced from user-entered (password + salt)
	//this comparison uses sha1 because stdc strncmp compares unly until byte 0x00, which can
	//occur anywhere in a raw byte sequence

	if (strcmp_sha1(ptr, d2))
	{
		//if the MACs don't match, alert user as such
		fprintf(stderr, "\nCT Not Authentic.\n");
		exit(ERROR_EXIT);
	}
	else
	{ //decrypt

		fprintf(stdout, "\nCT Authenticated.\n");

		//if they match create an AES key from the derived key
		aes_set_key(a_dec_ctx, cipher_key, 256, 0);

		//decryption in Cipher Block Chaining mode
		err = decfile(f_ctx, a_dec_ctx);

		if (err == READ_ERROR)
		{
			fprintf(stderr, "ERROR could not read from %s\n", f_ctx.ifn);
			exit(ERROR_EXIT);
		}
		if (err == WRITE_ERROR)
		{
			fprintf(stderr, "ERROR could not write to %s\n", f_ctx.ofn);
			exit(ERROR_EXIT);
		}
	}
	printf("\n");

	//clear the variables
	wipememory(d2, HASH_SIZE);
	wipememory(salt_ptr, SALT_SIZE);
	wipememory(ptr, SALT_SIZE);
	wipememory(cipher_key, AES_KEY_LEN);
	wipememory(hmac_bytes, 20);
	wipememory(a_dec_ctx, sizeof(aes_context));
	wipememory(usr_pwd, strlen((const char *)usr_pwd));
	wipememory(salt, SALT_SIZE);
	wipememory(mac_key, MAC_LEN);
	wipememory(prn_out, DEC_STR_LEN);

	xfree(salt_ptr);
	xfree(ptr);
	xfree(cipher_key);
	xfree(hmac_bytes);
	xfree(a_dec_ctx);
	xfree(usr_pwd);
	xfree(salt);
	xfree(mac_key);
	xfree(prn_out);

	return 0;
}
