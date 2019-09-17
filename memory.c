
#include "memory.h"

void *xmalloc (size_t n)
{
	char *p;

    	if (!n)
		n = 1;
    	
	if (!(p = malloc (n)))
 		exit (OUT_OF_CORE); //print errror
    	
	return p;
}


void *xmalloc_secure (size_t n)
{
	char *p;

    	if (!n)
      		n = 1;
    	
	if (!(p = secmem_malloc (n)))
 		exit (OUT_OF_CORE); //print error
    
	return p;

}

void *xmalloc_clear( size_t n )
{
    	void *p;
    	p = xmalloc( n );
    	memset(p, 0, n );
    	return p;
}

void *xmalloc_secure_clear (size_t n)
{
    	void *p;
   	p = xmalloc_secure( n );
    	memset(p, 0, n );
    	return p;
}

void *xrealloc( void *a, size_t n )
{
	void *b;

    	if (m_is_secure(a)) 
	{
 		if (!(b = secmexrealloc(a, n)))
    			exit (OUT_OF_CORE);//print errror
    	}
    	else if (!(b = realloc(a, n)))
     		exit (OUT_OF_CORE); //print errror
    
    	return b;
}


void xfree( void *a )
{
    	unsigned char *p = a;

    	if (!p)
 		return;

    	if (m_is_secure(a))
 		secmem_free(p);
    	else
 		free(p);

}

char *xstrdup( const char *a )
{
    	size_t n = strlen(a);
   	 char *p = xmalloc(n+1 );
    	strcpy(p, a);
    	return p;
}


void *xcalloc (size_t n, size_t m)
{
	size_t nbytes;

  	nbytes = n * m;
  
	if (m && nbytes / m != n)
  		exit (OUT_OF_CORE); //print errror
  
	return xmalloc_clear (nbytes);
}

void *xcalloc_secure (size_t n, size_t m)
{
  	size_t nbytes;

  	nbytes = n * m;
  	
	if (m && nbytes / m != n)
    		exit (OUT_OF_CORE); //print errror
  
	return xmalloc_secure_clear (nbytes);
}
