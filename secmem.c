
#include "secmem.h"



static void *pool;
static volatile int pool_okay;
static volatile int pool_is_mmapped;
static size_t poolsize;
static size_t poollen;
static MEMBLOCK *unused_blocks;
static unsigned max_alloced;
static unsigned cur_alloced;
static unsigned max_blocks;
static unsigned cur_blocks;
static int disable_secmem;
static int show_warning;
static int no_warning;
static int suspend_warning;


static void print_warn(void)
{
	if (!no_warning)
	printf ("WARNING: using insecure memory!\n");
         
}


static void lock_pool( void *p, size_t n )
{

	uid_t uid;
    	int err;

    	uid = getuid();
    	err = mlock( p, n );
    
	if (err && (*__errno_location ()))
 		err = (*__errno_location ());


    	if (uid && !geteuid()) 
	
		if( setuid( uid ) || getuid() != geteuid() || !setuid(0) )
     			printf("failed to reset uid: %s\n", strerror((*__errno_location ())));
    
	if( err ) 
	{
		if( (*__errno_location ()) != EPERM
     		&& (*__errno_location ()) != EAGAIN
     		&& (*__errno_location ()) != ENOSYS
            	&& (*__errno_location ()) != ENOMEM)

     			printf("can't lock memory: %s\n", strerror(err));
 		
		show_warning = 1;
	}

}


static void init_pool (size_t n)
{
	size_t pgsize;

    	poolsize = n;

    	if( disable_secmem )
 		printf("secure memory is disabled");

    	pgsize = getpagesize();
    	poolsize = (poolsize + pgsize -1 ) & ~(pgsize-1);

       	pool = mmap( 0, poolsize, PROT_READ|PROT_WRITE,
				 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    	if (pool == (void*)-1)
 		printf("can't mmap pool of %u bytes: %s - using malloc\n",
       		(unsigned)poolsize, strerror((*__errno_location ())));
    	else 
	{
 		pool_is_mmapped = 1;
 		pool_okay = 1;
    	}


    	if( !pool_okay ) 
	{
 		pool = malloc( poolsize );
 
		if (!pool)
     			printf("can't allocate memory pool of %u bytes\n",
             		(unsigned)poolsize);
 		else
     			pool_okay = 1;
    	}
    	
	lock_pool( pool, poolsize );
    	poollen = 0;
}


void secmem_set_flags( unsigned flags )
{
    	int was_susp = suspend_warning;

    	no_warning = flags & 1;
    	suspend_warning = flags & 2;

    	if (was_susp && !suspend_warning && show_warning ) 
	{
 		show_warning = 0;
 		print_warn();
    	}
}

unsigned secmem_get_flags(void)
{
    	unsigned flags;

    	flags = no_warning ? 1:0;
    	flags |= suspend_warning ? 2:0;
    	return flags;
}


int secmem_init( size_t n )
{
	if (!n) 
	{
 		uid_t uid;

 		disable_secmem=1;
 		uid = getuid();
 
		if (uid != geteuid()) 
			if( setuid (uid) || getuid() != geteuid() || !setuid(0) )
  				printf("failed to drop setuid\n" );
    	}
    	else 
	{
 		if (n < DEFAULT_POOLSIZE)
     			n = DEFAULT_POOLSIZE;
 
		if (!pool_okay)
     			init_pool(n);
 		else
     			printf("Oops, secure memory pool already initialized\n");
    	}

    	return !show_warning;
}


void *secmem_malloc( size_t size )
{
    	MEMBLOCK *mb, *mb2;
    	
    	if (!pool_okay) 
	{
 		printf("operation is not possible without initialized secure memory\n");
 		printf("(you may have used the wrong program for this task)\n");
 		exit(2);
    	}

    	if (show_warning && !suspend_warning ) 
	{
 		show_warning = 0;
 		print_warn();
    	}

    	size += sizeof(MEMBLOCK);
    	size = ((size + 31) / 32) * 32;

 
	for (mb = unused_blocks, mb2=((void *)0); mb; mb2=mb, mb = mb->u.next)
 		if( mb->size >= size ) 
		{
     			if (mb2)
  				mb2->u.next = mb->u.next;
     			else
			{
  				unused_blocks = mb->u.next;
     				cur_alloced += mb->size;
    				cur_blocks++;
    				
				if (cur_alloced > max_alloced)
 					max_alloced = cur_alloced;
    				if( cur_blocks > max_blocks )
	 				max_blocks = cur_blocks;

    				return &mb->u.aligned.c;
			}
 		}

	if ((poollen + size <= poolsize)) 
	{
 		mb = (void*)((char*)pool + poollen);
 		poollen += size;
 		mb->size = size;
    	}
	else
 		return ((void *)0);

    	cur_alloced += mb->size;
    	cur_blocks++;
    
	if (cur_alloced > max_alloced)
 		max_alloced = cur_alloced;
    	if (cur_blocks > max_blocks)
 		max_blocks = cur_blocks;
	
	return &mb->u.aligned.c;
}


void secmem_free (void *a)
{
    	MEMBLOCK *mb;
    	size_t size;

    	if (!a)
 		return;

    	mb = (MEMBLOCK*)((char*)a - ((size_t) &((MEMBLOCK*)0)->u.aligned.c));
    	size = mb->size;

    	wipememory2(mb, 0xff, size );
    	wipememory2(mb, 0xaa, size );
    	wipememory2(mb, 0x55, size );
    	wipememory2(mb, 0x00, size );
    	mb->size = size;
    	mb->u.next = unused_blocks;
    	unused_blocks = mb;
    	cur_blocks--;
    	cur_alloced -= size;
}

void *secmexrealloc( void *p, size_t newsize )
{
    	MEMBLOCK *mb;
    	size_t size;
    	void *a;

    	mb = (MEMBLOCK*)((char*)p - ((size_t) &((MEMBLOCK*)0)->u.aligned.c));
    	size = mb->size;
    
	if (size < sizeof(MEMBLOCK))
      		printf ("secure memory corrupted at block %p\n", (void *)mb);
    
	size -= ((size_t) &((MEMBLOCK*)0)->u.aligned.c);

    	if (newsize <= size)
 		return p;
    
	a = secmem_malloc( newsize );
    	
	if (a) 
	{
        	memcpy(a, p, size);
        	memset((char*)a+size, 0, newsize-size);
        	secmem_free(p);
    	}
    
	return a;
}

int m_is_secure (const void *p)
{
    return p >= pool && p < (void*)((char*)pool+poolsize);
}

void secmem_term()
{
	if( !pool_okay )
 		return;

    	wipememory2( pool, 0xff, poolsize);
    	wipememory2( pool, 0xaa, poolsize);
    	wipememory2( pool, 0x55, poolsize);
    	wipememory2( pool, 0x00, poolsize);

    	if (pool_is_mmapped)
 		munmap( pool, poolsize );

   	pool = ((void *)0);
    	pool_okay = 0;
    	poolsize=0;
    	poollen=0;
    	unused_blocks=((void *)0);
}


void secmem_dump_stats()
{
    	if (disable_secmem)
 		return;
    
	fprintf(stderr,
  		"secmem usage: %u/%u bytes in %u/%u blocks of pool %lu/%lu\n",
  		cur_alloced, max_alloced, cur_blocks, max_blocks,
  		(ulong)poollen, (ulong)poolsize );
}
