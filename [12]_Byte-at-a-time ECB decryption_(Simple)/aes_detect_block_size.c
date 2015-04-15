#include "aes_detect_block_size.h"
#include "../tools/ifreq.h"

/* 
 *  Biggest common dividor using Euclide's Algorithm
 */ 
unsigned int pgcd (unsigned int a, unsigned int b)
{
	unsigned int tmp;

	while (b)
	{
		tmp = a;
		a = b,
		b = tmp % b;
	}

	return a;
}

/* 
 *  Block size detection using ciphertext lengths
 */
int aes_detect_block_size(aes_detect_block_size_encrypt encryption_method)
{	
	size_t i, clen, uclen_count;
	unsigned int clengths[32], clen_oc[32];
	unsigned char *ctext;
	unsigned char  ptext[64] = {0};


	for (i=0; i<32; i++)
	{
		ptext[i] = 'A';
		clen = encryption_method(&ctext, ptext, 1 + i);
		clengths[i] = clen;


		free(ctext);
	}

	// Sort cipher lengths by number of appearance
	uclen_count = ifreq((int*) clengths, clen_oc, 32);

	

	// return pgcd of at most the three most recurrent lengths
	switch (uclen_count)
	{
	case 0:
		return 0;
	case 1:
		return clengths[0];
	case 2:
		return pgcd(clengths[0], clengths[1]);
	default:
	case 3:
		return pgcd(pgcd(clengths[0], clengths[1]), clengths[2]) ;	
	}
}