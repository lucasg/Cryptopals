#include <stdlib.h>
#include <string.h>
#include "hamdist.h"

/* 
 * Compute the hamming distance between two ints
 */
unsigned int hamdist_uint(unsigned int x, unsigned int y)
{
  unsigned dist = 0, val = x ^ y;

  while(val)
  {
    ++dist; 
    val &= val - 1;
  }
 
  return dist;
}

/* 
 *  Compute the hamming distance between two strings
 */
unsigned int hamdist_str(const char *str1, const  char *str2,unsigned int len)
{
	unsigned int ham_dist = 0,i = 0;
	while(i < len)
	{
		ham_dist += hamdist_uint(*str2 , *str1);

		str1++;
		str2++;
		i++;
	}

	return ham_dist;
}

/* 
 *  Compute the hamming distance of a text, using a given key length
 */
float hamdist_keyscore(const char *txtdat, unsigned int txtsize, unsigned int keysize)
{
	unsigned int keyblk_idx, score = 0;
	char *curblk, *prevblk;

	curblk = malloc(keysize+1);
	if( NULL == curblk)
		return -1;
	curblk[keysize] = 0;

	prevblk = malloc(keysize+1);
	if( NULL == prevblk)
		return -1;
	prevblk[keysize] = 0;


	memcpy(curblk, txtdat, keysize);
	for (keyblk_idx = keysize; keyblk_idx < txtsize; keyblk_idx+=keysize)
	{
		
		memcpy(prevblk, curblk, keysize);
		memcpy(curblk, txtdat + keysize, keysize);
		score += hamdist_str(prevblk, curblk, keysize);
	}
	

	free(curblk);
	free(prevblk);

	return score/((float) keysize);
}

/*
 * Simple Unit Test
 */
unsigned int hamming_distance_test()
{
	return 37 == hamdist_str("this is a test\0", "wokka wokka!!!\0", 16);
}
