/*
*  librinecrypt.c password handling routines.
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
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <stdlib.h>
#include <termios.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "rinecrypt.h"
#include "sha512.h"
#include "memory.h"


//this function is used solely to compare strings
byte *sha512_crypt(byte *key, const char *salt)
{
	SHA512_CTX context;
	byte *digest = (byte*)xmalloc_secure(64 * sizeof(byte));

	SHA512_Init(&context);
	SHA512_Update(&context, key, HASH_SIZE);
	SHA512_Update(&context, salt, HASH_SIZE);
	SHA512_Final(digest, &context);

	wipememory(&context, sizeof(SHA512_CTX));
	return digest;
}

//compare user entered strings to see if they match each other
int cmp_crypt_usr_string(byte *usr_ent_str, byte *usr_ent_str_cmp, const char *prn_msg)
{
	//get the hashes for the password and the comparison password
	byte *crypted_pw1, *crypted_pw2;

	//if 'prn_msg' is DO_CMP, only compare strings.
	//do not prompt for string re-entry if they don't match
	if (!strncmp(prn_msg, DO_CMP, 16))
	{
		crypted_pw1 = sha512_crypt(usr_ent_str,     "0000000000000000");
		crypted_pw2 = sha512_crypt(usr_ent_str_cmp, "0000000000000000");
		if (!strncmp((const char *)crypted_pw1, (const char *)crypted_pw2, SHA512_DIGEST_SIZE))
		{
			//wipe and free the pointer because they will be allocated
			// again when sha512_crypt is called. helps with memory
			wipememory(crypted_pw1, strlen((const char *)crypted_pw1));
			wipememory(crypted_pw2, strlen((const char *)crypted_pw2));
			xfree(crypted_pw1);
			xfree(crypted_pw2);
			return 0;
		}
		else
		{
			wipememory(crypted_pw1, strlen((const char *)crypted_pw1));
			wipememory(crypted_pw2, strlen((const char *)crypted_pw2));
			xfree(crypted_pw1);
			xfree(crypted_pw2);
			return -1;
		}
	}
	else
	{
		crypted_pw1 = sha512_crypt(usr_ent_str,     "0000000000000000");
		crypted_pw2 = sha512_crypt(usr_ent_str_cmp, "0000000000000000");

		//if the strings entered do not match, keep getting them
		// until they do
		while (strncmp((const char *)crypted_pw1, (const char *)crypted_pw2, SHA512_DIGEST_SIZE))
		{
			//wipe and free the pointer because they will be allocated
			// again when sha512_crypt is called. helps with memory
			wipememory(usr_ent_str_cmp, strlen((const char *)usr_ent_str_cmp));
			wipememory(usr_ent_str, strlen((const char *)usr_ent_str));
			wipememory(crypted_pw1, strlen((const char *)crypted_pw1));
			wipememory(crypted_pw2, strlen((const char *)crypted_pw2));
			xfree(crypted_pw1);
			xfree(crypted_pw2);

			//prompt user to enter string
			printf("\n%ss did not match!\n\n", prn_msg);
			printf("Enter %s:", prn_msg);
			fgets((char *)usr_ent_str, 64, stdin);
			rm_last_char(usr_ent_str);
			printf("\n");

			//string length is always more than 10 bytes long
			//the only things the user enters on promp are
			//the password and the header MAC when decrypting
			//both these things are > 10 bytes
			while (strlen((const char *)usr_ent_str) < 10)
			{
				printf("\n%s too short!\n\n", prn_msg);
				printf("Enter %s:", prn_msg);
				fgets((char *)usr_ent_str, 64, stdin);
				rm_last_char(usr_ent_str);
				printf("\n");
			}

			printf("Re-Enter %s:", prn_msg);
			fgets((char *)usr_ent_str_cmp, 64, stdin);
			rm_last_char(usr_ent_str_cmp);
			printf("\n");

			//re-compare entered strings and reallocate more memory
			crypted_pw1 = sha512_crypt(usr_ent_str,     "0000000000000000");
			crypted_pw2 = sha512_crypt(usr_ent_str_cmp, "0000000000000000");
		}
	}
	//clear and free allocated variables
	wipememory(crypted_pw1, strlen((const char *)crypted_pw1));
	wipememory(crypted_pw2, strlen((const char *)crypted_pw1));
	xfree(crypted_pw1);
	xfree(crypted_pw2);

	return 0;
}

//get a user-entered string and blank terminal
void get_user_string(const char *prn_msg, byte *usr_ent_str)
{
	struct termios tios;
	unsigned char *usr_ent_str_cmp = (unsigned char *)xmalloc_secure(INPUT_SIZE + 1);

	//check terminal attributes
	if (tcgetattr(0, &tios) < 0)
	{
		printf("Could not get terminal attributes\n");
		exit(ERROR_EXIT);
	}

	//turn off echoing of keyboard input
	tios.c_lflag ^= ECHO;           /* echo off */
	tcsetattr(0, TCSAFLUSH, &tios);

	//get the string from the user
	printf("Enter %s:", prn_msg);
	fgets((char *)usr_ent_str, INPUT_SIZE, stdin);
	//strip LF from string entered by the user
	rm_last_char(usr_ent_str);
	printf("\n");

	//make sure that the password is greater than 10 charaters.
	//this is done to assure some level of security
	while (strlen((const char *)usr_ent_str) < 10)
	{
	   printf("%s too short!\n", prn_msg);
	   printf("Enter %s:", prn_msg);
	   fgets((char *)usr_ent_str, INPUT_SIZE, stdin);
	   rm_last_char(usr_ent_str);
	   printf("\n");
	}

	//get comparison password from the user.
	//should match the one entered above
	printf("Re-Enter %s:", prn_msg);
	fgets((char *)usr_ent_str_cmp, INPUT_SIZE, stdin);
	rm_last_char(usr_ent_str_cmp);
	printf("\n");

	//make sure that entered strings match
	cmp_crypt_usr_string(usr_ent_str, usr_ent_str_cmp, prn_msg);

	//Reset the property and reset the terminal line.
	tios.c_lflag ^= ECHO;           /* echo on */
	tcsetattr(0, TCSAFLUSH, &tios);

	wipememory(usr_ent_str_cmp, INPUT_SIZE);
	xfree(usr_ent_str_cmp);
}


//FIPS-198a Keyed-Hash Message Authentication Code implemenation
void hmac_sha512_file (FILE *data, unsigned char *k, int lk, unsigned char *digest)
{
	SHA512_CTX ictx, octx;
	unsigned char    isha[SHA512_DIGEST_SIZE];
	unsigned char    key[SHA512_DIGEST_SIZE] ;
	unsigned char    buf[SHA512_BLOCK_SIZE] ;
	unsigned char 	 fbuf[SHA512_BLOCK_SIZE];
	int     i, count = 0;
	unsigned long bytesread, infile_size, rlen = 0;

	if (lk > SHA512_BLOCK_SIZE) {

		SHA512_CTX         tctx ;

		SHA512_Init(&tctx) ;
		SHA512_Update(&tctx, k, lk) ;
		SHA512_Final(key, &tctx) ;

		k = key ;
		lk = SHA512_DIGEST_SIZE ;
	}


	/**** Inner Digest ****/
	fprintf(stdout, "\nCalculating MAC\n");
	SHA512_Init(&ictx) ;

	/* Pad the key for inner digest */
	for (i = 0 ; i < lk ; ++i) buf[i] = k[i] ^ 0x36 ;
	for (i = lk ; i < SHA512_BLOCK_SIZE ; ++i) buf[i] = 0x36 ;

	SHA512_Update(&ictx, buf, SHA512_BLOCK_SIZE) ;

	rewind(data);
	fseek(data, 0, SEEK_END);
	infile_size = rlen = ftell(data);
	rewind(data);

	//get file digest
	while (rlen > 0 && !feof(data))
	{
		bytesread = fread(fbuf, 1, SHA512_BLOCK_SIZE, data);
		SHA512_Update(&ictx, fbuf, bytesread);

		if (((infile_size - rlen) / (float)infile_size) * 100.0f > count)
			fprintf(stderr, " Blocks completed:  %3.0i%%\t\r", count++);

		rlen -= bytesread;
	}
	
	SHA512_Final(isha, &ictx);

	/**** Outter Digest ****/

	SHA512_Init(&octx) ;

	/* Pad the key for outter digest */

	for (i = 0 ; i < lk ; ++i) buf[i] = k[i] ^ 0x5C ;
	for (i = lk ; i < SHA512_BLOCK_SIZE ; ++i) buf[i] = 0x5C ;

	SHA512_Update(&octx, buf, SHA512_BLOCK_SIZE) ;
	SHA512_Update(&octx, isha, SHA512_DIGEST_SIZE) ;

	SHA512_Final(digest, &octx);
}


int is_hex(unsigned char *given_chain, int len)
{
	int i;
	for (i = 0; i < len; i++)
		if (isxdigit(given_chain[i]) == 0)
			return 0;
	return 1;
}

//replace last char of a string with '\0' if it is '\n'
void rm_last_char(unsigned char *a_string)
{
	//pointer to the last char in a line
	char *ptr = strchr((const char *)a_string, '\n');

	//overwrite that char if it is a '\n'
	if (ptr != NULL && ptr[0] == '\n')
		ptr[0] = '\0';

	if (ptr != NULL && ptr[0] == '\0')
		ptr[0] = ' ';
}

//remove any spaces in a 'len' long string
byte *rm_space(byte *has_space, int len)
{
	int i, j;
	byte *out_str = (byte *)xmalloc_secure(64 * sizeof(byte));

	for (i = 0, j = 0; i < len; i++)
		if (!isspace(has_space[i]))
			out_str[j++] = has_space[i];
	out_str[j] = '\0';
	return out_str;
}

unsigned char *hex2bin(unsigned char *hex, int len)
{
	char ch ;
	unsigned char val;
	unsigned char *tmpchain ;
	int nbytes = 0, i = 0, upper = 1 ;

	/* The chain should have 2*n characters */
	if (!is_hex(hex, len) || len % 2)
		return NULL ;

	tmpchain = xmalloc_secure((len / 2) + 1);

	for(; nbytes<len; hex++)
	{
		ch = *hex;
		if(ch == ' ') continue;
		if(islower(ch)) ch = (char)toupper(ch);

		if(isdigit(ch))
			val = (unsigned char) (ch - '0');
		else
		{
			if(ch>='A' && ch<='F')
				val = (unsigned char)(ch - 'A' + 10);
			/* End of hex digits--time to bail out. */
			else
				return (upper ? tmpchain : 0);
		}


	/* If this is an upper digit, set the top 4 bits of the destination
	* byte with this value, else -OR- in the value.
	*/
		if(upper)
		{
			tmpchain[i] = (unsigned char) (val << 4);
			upper = 0;
		}
		else
		{
			tmpchain[i++] |= val;
			upper = 1;
		}
	}

	tmpchain[(len / 2)] = '\0' ;
	return(tmpchain);
}
