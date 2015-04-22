#include "../tools/aes_128/aes_128.h"
#include "../tools/xor.h"
#include "aes_detect_ecb_mode.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>



unsigned int generate_random_aes_mode(unsigned char * cipher, const unsigned char * msg)
{

	unsigned char random_key[16], iv[16] = {0};
	unsigned int i;

	// Generate random key
	for (i=0; i<4; i++)
		((int*) random_key)[i] = rand();

	// the ciphertext buffer should be long enough
	int prefix_len = (int)5 + (rand() / (double)RAND_MAX * (5 - 1));
	int suffix_len = (int)5 + (rand() / (double)RAND_MAX * (5 - 1));

	
	// encrypt accord to selected mode
	unsigned int ecb_mode = rand() >= RAND_MAX / 2;
	if (ecb_mode)
		aes_128_encrypt_msg(cipher + prefix_len,msg, strlen((char*)msg),random_key, ECB, NULL);
	else
		aes_128_encrypt_msg(cipher + prefix_len,msg, strlen((char*)msg),random_key, CBC, (const union aes_128_init *) iv);

	
	// pre/append some garbage values
	for (i=0; i<prefix_len;i++)
		cipher[i] = (char)(rand() / (double)RAND_MAX * (255 - 1));
	for (i= 0; i<suffix_len;i++)
		cipher[prefix_len + strlen((char*)msg) + i] = (char)(rand() / (double)RAND_MAX * (255 - 1));

	return ecb_mode;
}

unsigned int ecb_detection_oracle()
{
	unsigned char ciphertext[16*15+30],
				  chosen_block[16] = "0123456789ABCDEF",
				  chosen_plaintext[16*15 + 1];
	unsigned int i;

    for (i=0; i<15; i++)
    	memcpy( chosen_plaintext + 16*i, chosen_block, sizeof(chosen_block));
    chosen_plaintext[16*15] = 0x00;

	int gen_mode = generate_random_aes_mode(ciphertext,chosen_plaintext);
	//printf("Mode used : %s\n", gen_mode ? "ECB": "CBC" );

	int ret_mode = aes_detect_ecb_mode(ciphertext, strlen((char*)chosen_plaintext));
	//printf("Mode detected : %s\n", ret_mode ? "ECB": "CBC" );

	return 2*ret_mode + gen_mode;
}

int main (int argc, char *argv[])
{
	srand (time (NULL));
	unsigned int i, r, results[4] = {0};


	for (i=0; i<1000; i++)
	{
		r = ecb_detection_oracle();
		results[r % 4]++;
	}

	printf("Results :\n");
	printf("ret\\gen      cbc, ecb\n");
	printf("cbc	%lf, %lf\n", results[0]/((float)results[0]+results[2]), results[1]/((float)results[1]+results[3]));
	printf("ecb	%lf, %lf\n", results[2]/((float)results[0]+results[2]), results[3]/((float)results[1]+results[3]));


	return 0x00;
}