#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

#define DEFAULT_POOLSIZE 16384

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

/* It seems that Slackware 7.1 does not know about EPERM */
#if !defined(EPERM) && defined(ENOMEM)
#define EPERM  ENOMEM
#endif

#define wipememory2(_ptr,_set,_len) do { volatile char *_vptr=(volatile char *)(_ptr); size_t _vlen=(_len); while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)


typedef union {
    	int a;
    	short b;
    	char c[1];
    	long d;
	unsigned long e;
    	float f;
    	double g;
} PROPERLY_ALIGNED_TYPE;


typedef struct memblock_struct MEMBLOCK;

struct memblock_struct {
    unsigned size;
    union {
 MEMBLOCK *next;
 PROPERLY_ALIGNED_TYPE aligned;
    } u;
};

