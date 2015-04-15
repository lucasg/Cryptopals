#ifndef _HAMDIST_H_
	#define _HAMDIST_H_


/* 
 * Compute the hamming distance between two ints
 */
unsigned int hamdist_uint(unsigned int x, unsigned int y);

/* 
 *  Compute the hamming distance between two strings
 */
unsigned int hamdist_str(const char *str1, const  char *str2, unsigned int len);

/* 
 *  Compute the hamming distance of a text, using a given key length
 */
float hamdist_keyscore(const char *txtdat, unsigned int txtsize, unsigned int keysize);



#ifdef TEST
	/*
	 * Simple Unit Test
	 */
	unsigned int hamming_distance_test()
#endif /* TEST */


#endif /* _HAMDIST_H_ */