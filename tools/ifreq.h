#ifndef _IFREQ_H_
	#define _IFREQ_H_

#include <stdlib.h>

/*
 *	Take a bunch of values and return it sorted by their number 
 *  of appeareance. Rely on qsort for actual sorting.
 *
 *.  Returns the number of unique values 
 */
size_t ifreq(int *values, unsigned int *counts, size_t len);


#endif /* _IFREQ_H_ */