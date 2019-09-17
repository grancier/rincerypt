#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "secmem.h"

#define OUT_OF_CORE 0xfc

void *xmalloc_secure (size_t n);
void xfree( void *a );
void *secmem_malloc( size_t size );
void *secmexrealloc( void *p, size_t newsize );
int m_is_secure (const void *p);
void secmem_free (void *a);
unsigned secmem_get_flags(void);
void secmem_set_flags( unsigned flags );
int secmem_init( size_t n );
void secmem_term();





