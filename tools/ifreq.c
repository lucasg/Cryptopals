#include "ifreq.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* 
 * Temp structure used to keep track of the indexes.
 */
struct ifreq_counts {
  int value;
  int counts;
  int index;
};

/*
 *  Comparaison function, from most to last frequent 
 */
int ifreq_cmp (const void * a, const void * b)
{
   return ( ((struct ifreq_counts*)b) -> counts - ((struct ifreq_counts*)a ) -> counts );
}

/*
 *	Take a bunch of values and return it sorted by their number 
 *  of appeareance. Rely on isort for sorting. 
 */
size_t ifreq(int *values, unsigned int *counts, size_t len)
{
	struct ifreq_counts *tmp;
	size_t i, j, alloc_tmp;

	tmp = malloc(len*sizeof(struct ifreq_counts));
	if (NULL == tmp)
		return 0;
	
	memset(tmp, 0, len*sizeof(struct ifreq_counts));

	alloc_tmp = 0;
	for (j=0;j<len;j++)
	{
		i=0;
		while(i< alloc_tmp && tmp[i].value != values[j])
			i++;

		// element already in array
		if (tmp[i].value == values[j])
			tmp[i].counts++;
		// insertion new elem
		else
		{
			tmp[i].value = values[j];
			tmp[i].counts = 1;
			alloc_tmp++;
		}
	}

	for (j=0; j < alloc_tmp; j++)
		tmp[j].index = j;

	qsort((void*) tmp, alloc_tmp, sizeof(struct ifreq_counts), ifreq_cmp);


	for (j=0; j < alloc_tmp; j++)
	{
		values[j] =  tmp[j].value;
		
		if (NULL != counts)
			counts[j] =  tmp[j].counts;
	}
		
	memset(values + alloc_tmp, 0, (len-alloc_tmp)*sizeof(int));
	if (NULL != counts)
		memset(counts + alloc_tmp, 0, (len-alloc_tmp)*sizeof(int));

	free(tmp);

	return alloc_tmp;
}