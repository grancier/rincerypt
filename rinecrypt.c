/*
 *  rinecrypt.c AES file encryptor/decryptor
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "rinecrypt.h"
#include "memory.h"

//print current version and date
static void printver()
{
	char ver[5];

	sprintf(ver, "%d", VER);

	if (VER < 1000)
		printf("rinecrypt-0.%c.%c, %s\n", ver[0], ver[1], __DATE__);
	else
		printf("rinecrypt-%c.%c.%c, %s\n", ver[0], ver[1], ver[2], __DATE__);
}

static void usage()
{
	//print usage. include version and date of compilation
	printf("\n\trinecrypt, a file encryptor/decryptor\n");
	printf("\t   using the 256 bit AES algorithm in CBC mode.\n");
	printf("\t   ");
	printf("\n");
	printf("\tusage: rinecrypt [-e|-d] -i <infile> -o <outfile>\n");
	printf("\n");
}


static void help()
{
	//standard help
	usage();
	printf("\n");
	printf(  "   -d, --decrypt	decrypt infile to outfile\n");
	printf(  "   -e, --encrypt	encrypt infile to outfile\n");
	printf(  "   -h, --help		print this message\n");
	printf(  "   -i  <infile>,  --infile  <infile>  file which contains input\n");
	printf(  "   -o  <outfile>, --outfile <outfile> file to contain output\n");
	printf(  "   -v, --version	print rinecrypt version\n");
	printf("\n");
}


//parse command line args
static byte parse_args(int argc, char **argv, char *infile_name[], char *outfile_name[])
{
	int c;
	extern char *optarg;
	extern int optind;
	int eflg = 0;
	int dflg = 0;
	int errflg = 0;
	byte direction = -1;

	if (argc != 6 && argc != 2)
		errflg++;

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
			{"encrypt", 0, 0, 'e'},
			{"decrypt", 0, 0, 'd'},
			{"version", 0, 0, 'v'},
			{"help",    0, 0, 'h'},
			{"infile",  1, 0, 'i'},
			{"outfile", 1, 0, 'o'},
			{0, 0, 0, 0}
		};

		c = getopt_long_only(argc, argv, "",
			long_options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'd':
			if (eflg)
				errflg++;
			else
			{
				if (argc != 6)
					errflg++;

				dflg++;
				direction = DIR_DECRYPT;
			}
			break;

		case 'e':
			if (dflg)
				errflg++;
			else
			{
				if (argc != 6)
					errflg++;

				eflg++;
				direction = DIR_ENCRYPT;
			}
			break;

		case 'h':
			help();
			exit(NORMAL_EXIT);
			break;

		case 'i':
			*infile_name = optarg;
			if (strlen(*infile_name) > 128)
			{
				   printf("Infile name exceeds 128 characters!\n");
				   exit(ERROR_EXIT);
			}
			break;

		case 'o':
			*outfile_name = optarg;
			if (strlen(*outfile_name) > 128)
			{
				   printf("Outfile name exceeds 128 characters!\n");
				   exit(ERROR_EXIT);
			}
			break;

		case 'v':
			printf("\n");
			exit(NORMAL_EXIT);
			break;

		case '?':
			errflg++;
			direction = BAD_KEY_DIR;
			break;

		default:
			break;
		}
	}

	if (optind < argc)
		errflg++;

	if (errflg)
	{
		usage();
		exit(ERROR_EXIT);
	}

	return direction;
}


int main(int argc, char *argv[])
{
	byte direction;
	file_ctx f_ctx;
	f_ctx.fin = stdin;
	f_ctx.fout = stdout;
   
	char usr_ent_str[5];


	printver();

	//initialize secure memory
	//taking directly from gnupg 1.2.1
	secmem_set_flags(secmem_get_flags() | 2);
	secmem_init(9792 * 2); //allocate this many secure bytes;

	//parse command line options and determine whether to decrypt or encrypt
	direction = parse_args(argc, argv, &f_ctx.ifn, &f_ctx.ofn);

	if (!(f_ctx.fin = fopen(f_ctx.ifn, "r")))   // try to open the input file
	{
		fprintf(stderr, "ERROR: The input file: %s could not be opened.\n", f_ctx.ifn);
		exit(ERROR_EXIT);
	}

	//don't clobber if outfile exists
	if ((f_ctx.fout = fopen (f_ctx.ofn, "r")))
	{
		fclose (f_ctx.fout);

		//permission to overwrite
		fprintf (stderr, "The output file: %s exists\nOverwrite? [n]: ", f_ctx.ofn);
		if (fgets(usr_ent_str, 4, stdin) == NULL)
			 return -1;

		//if yes overwrite existing outfile
		if ((usr_ent_str[0] = toupper(usr_ent_str[0])) == 'Y')
		{
			if (!(f_ctx.fout = fopen (f_ctx.ofn, "w+")))
			{
				fprintf (stderr, "ERROR: The output file: %s could not be opened.\n", f_ctx.ofn);
				exit(ERROR_EXIT);
			}
		}
		else
			exit(ERROR_EXIT);

	}
	//open outfile read/write so that we can read from the outfile
	else if (!(f_ctx.fout = fopen (f_ctx.ofn, "w+")))
	{
		fprintf (stderr, "ERROR: The output file: %s could not be opened.\n", f_ctx.ofn);
		exit(ERROR_EXIT);
	}

	if (direction == DIR_ENCRYPT)   // encryption in Cipher Block Chaining mode
		enc_n_auth_file(f_ctx);

	else if (direction == DIR_DECRYPT)
	{
		//read the file extension of ciphertext, first 4 bytes
		//fread(ext_cmp, sizeof(byte), EXT_LEN, f_ctx.fin);

		//if extension is not RAES
		/*if (strcmp(FILE_EXT, (const char *)ext_cmp))
		{	//infile is not valid for rinecrypt to decrypt
			fprintf(stderr, "ERROR: Invalid Ciphertext!\n");
			exit(ERROR_EXIT);
		}
		else*/
			dec_n_auth_file(f_ctx);
	}
	else
		fprintf(stderr, "ERROR: an error occurred parsing args\n");

	//clear the variables
	wipememory(f_ctx.ifn, strlen(f_ctx.ifn));
	wipememory(f_ctx.ofn, strlen(f_ctx.ofn));
	fclose(f_ctx.fout);
	fclose(f_ctx.fin);

	secmem_set_flags(secmem_get_flags() & ~2);
	secmem_term();

	return NORMAL_EXIT;
}
