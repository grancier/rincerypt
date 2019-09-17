#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "rinecrypt.h"

#define ONE_K 1024

static int devrand_fd           = -1,
           devrand_fd_noblock =   -1,
           devurand_fd          = -1;

void make_fd_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);  /* Get flags associated with the descriptor. */
	if (flags == -1)
	{
		perror("make_fd_nonblocking failed on F_GETFL");
		exit(-1);
	}
	flags |= O_NONBLOCK;

	/* Now the flags will be the same as before, except with O_NONBLOCK set.
	*/
	if (fcntl(fd, F_SETFL, flags) == -1)
	{
		perror("make_fd_nonblocking failed on F_SETFL");
		exit(-1);
	}
}


void rand_init(void)
{
	devrand_fd         = open("/dev/random",  O_RDONLY);
	devrand_fd_noblock = open("/dev/random",  O_RDONLY);
	devurand_fd        = open("/dev/urandom", O_RDONLY);

	if (devrand_fd == -1 || devrand_fd_noblock == -1)
	{
		perror("rand_init failed to open /dev/random");
		exit(-1);
	}
	if (devurand_fd == -1)
	{
		perror("rand_init failed to open /dev/urandom");
		exit(-1);
	}
	make_fd_nonblocking(devrand_fd_noblock);
}

unsigned char *dev_rand(void *buf, unsigned long nbytes)
{
	unsigned long       r;
	unsigned char *where = buf;

	if (devrand_fd == -1 && devrand_fd_noblock == -1 && devurand_fd == -1)
		rand_init();
	while (nbytes)
	{
		if ((r = read(devurand_fd, where, nbytes)) == -1)
		{
			if (errno == EINTR)
				continue;
			perror("dev_rand could not read from /dev/urandom");
			exit(-1);
		}
		where  += r;
		nbytes -= r;
	}
	return buf;
}

unsigned char *keygen(unsigned char *buf, unsigned long nbytes)
{
	unsigned long       r;
	unsigned char *where = buf;

	if (devrand_fd == -1 && devrand_fd_noblock == -1 && devurand_fd == -1)
		rand_init();

	while (nbytes)
	{
		if ((r = read(devrand_fd_noblock, where, nbytes)) == -1)
		{
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				 break;
			perror("dev_rand could not read from /dev/random");
			exit(-1);
		}
		where  += r;
		nbytes -= r;
	}
	dev_rand(where, nbytes);
	return buf;
}

unsigned char *entropy(unsigned char *buf, unsigned long nbytes)
{
 	unsigned long       r;
	unsigned char *where = buf;

	if (devrand_fd == -1 && devrand_fd_noblock == -1 && devurand_fd == -1)
		rand_init();
	while (nbytes)
	{
		if ((r = read(devrand_fd, (void *)where, nbytes)) == -1)
		{
			if (errno == EINTR)
				continue;
			perror("dev_rand could not read from /dev/random");
			exit(-1);
		}
		where  += r;
		nbytes -= r;
	}
	return buf;
}

void secrand(unsigned char *buf, unsigned long nbytes)
{
	unsigned char sec_buf[2 * nbytes];
	unsigned char salt[nbytes];
	unsigned long int rnd_n[1] = {0};

	dev_rand(sec_buf, 2 * nbytes);
	dev_rand(salt, nbytes);
	dev_rand(rnd_n, 4);

	derive_key_sha512(sec_buf, 2 * nbytes, salt,  nbytes,
		(rnd_n[0] % ONE_K) + ONE_K,  buf, nbytes);
}

