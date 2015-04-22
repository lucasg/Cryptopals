#include "aes_detect_ecb_mode.h"
#include "../tools/hamdist.h"

#include <string.h>
#include <stdlib.h>
//#include <stdio.h>

int aes_ecb_detection_oracle(aes_encrypt encryption_method, unsigned int block_size)
{
	unsigned char randkey[16] = {0};
	unsigned char *ciphertext,
				  chosen_block[16] = "0123456789ABCDEF",
				  chosen_plaintext[16*15 + 1];
	unsigned int i;

	// Random key
	for (i=0; i<4; i++)
		((int*) randkey)[i] = rand();

	// chosen plaintext
    for (i=0; i<15; i++)
    	memcpy( chosen_plaintext + 16*i, chosen_block, sizeof(chosen_block));
    chosen_plaintext[16*15] = 0x00;

   	// encrypt (iv is same as key)
    encryption_method(&ciphertext, chosen_plaintext, strlen((char*)chosen_plaintext), randkey, 16, randkey );

	unsigned int ret_ecb = aes_detect_ecb_mode(ciphertext, strlen((char*)chosen_plaintext), 16);

	free(ciphertext);

	return ret_ecb;
}

int aes_detect_ecb_mode(const unsigned char *ciphertext, unsigned int cipherlength, unsigned int block_size)
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

	return (min_l != 0) && !(min_l % block_size);
}