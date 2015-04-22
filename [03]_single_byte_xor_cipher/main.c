#include "../tools/ifreq.h"
#include "../tools/xor.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>


/*
 *	Decode a text encrypted by a fixed character
 */
void decode_cipher(unsigned char* cipher,unsigned char*  decoded_cipher, unsigned int len, unsigned char ekey)
{
	caesar_decode(decoded_cipher, cipher, len, ekey);
}


/*
 *   Detect the key in a continous string (without 0xa) by simply counting letters
 *   and returning the most frequent one
 */
unsigned char detect_key_single_line(unsigned char *lencdata, size_t llen)
{
	size_t i;
	int *tmp;
	unsigned char most_freq_char;

	tmp = malloc(llen*sizeof(unsigned int));
	if (NULL == tmp)
		return 0x00;

	for (i = 0; i < llen; i++)
		tmp[i] = (int) lencdata[i];

	ifreq(tmp, NULL, llen);

	most_freq_char = (unsigned char) tmp[0];	

	free(tmp);
	return most_freq_char;
}


// Usage :  decode.EXEC cipher_text > result.
int main (int argc, char *argv[])
{
	unsigned char 	cipher_buf[34] = {0},
				decoded_cipher[34] = {0};	
	
	if (argc < 2)
		return 0x1;

	/*
	 * 	 Init
	 */
	FILE  *cipher = fopen(argv[1], "rb");
	if ( NULL == cipher)
		return 0x1;

	if (!fread(&cipher_buf, 34 , sizeof(char), cipher))
	{
		fclose(cipher);
		return 1;
	}


	/* 
	 *  Hypothesiss:  " " is the most frequent char in the ciphertext
	 */
	unsigned char sp_img = detect_key_single_line(cipher_buf, sizeof(cipher_buf)/sizeof(cipher_buf[0]));
	decode_cipher(cipher_buf, decoded_cipher, sizeof(cipher_buf)/sizeof(cipher_buf[0]), ' ' ^ sp_img);
	write(1, decoded_cipher, sizeof(decoded_cipher)/sizeof(decoded_cipher[0]));
	printf("\n");

	/*
	 * 	 Exit
	 */
	fclose(cipher);

	return 0;
}