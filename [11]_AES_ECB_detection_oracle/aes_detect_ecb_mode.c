#include "../tools/hamdist.h"


int aes_detect_ecb_mode(const unsigned char *ciphertext, unsigned int cipherlength)
{
	unsigned int l, min_l = 0;
	float kscore, min_kscore = 0;

	for (l = 1; l < cipherlength/4; l++ )
	{
		kscore = hamdist_keyscore((char*) ciphertext, cipherlength, l) + 
				 hamdist_keyscore((char*) ciphertext, cipherlength, 2*l);

		// Special case : textbook example of ECB encryption
		// return perfect kscore (i.e. 0) for multiples of 16
		if(0==kscore)
		{
			min_l = l;
			break;
		}

		// Local min
		if (min_kscore < 1/kscore)
		{
			min_kscore = 1/kscore;
			min_l = l;
		}

		//printf("Keyscore for #%d : %lf\n", l, kscore);
	}

	return (min_l != 0) && !(min_l % 16);
}