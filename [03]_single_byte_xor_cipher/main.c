#include "ifreq.h"
#include "xor.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * The input file's line length is defined here : it's easier that way than 
 * to open the file, detect the return char in order to compute the line lengths.
 */
#define INPUT_FILE_LINE_LENGTH (34)


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


/*
 *  Usage :  decode.EXEC cipher_text > result.
 */
int main (int argc, char *argv[])
{
	FILE  *cipher;
	unsigned char sp_img;
	unsigned char 	cipher_buf[INPUT_FILE_LINE_LENGTH] = {0},
				decoded_cipher[INPUT_FILE_LINE_LENGTH] = {0};	
	

	if (argc < 2)
		return 0x1;

	/*
	 * 	 Init
	 */
	cipher = fopen(argv[1], "rb");
	if (NULL == cipher)
	{
		printf("Error when calling fopen(%s) : %s\n", argv[1], strerror(errno));
		return errno;
	}

	if (INPUT_FILE_LINE_LENGTH != fread(&cipher_buf, 1, INPUT_FILE_LINE_LENGTH, cipher))
	{
		fclose(cipher);
		return errno;
	}


	/* 
	 *  Hypothesiss:  " " is the most frequent char in the ciphertext
	 */
	sp_img = detect_key_single_line(cipher_buf, INPUT_FILE_LINE_LENGTH);
	decode_cipher(cipher_buf, decoded_cipher, INPUT_FILE_LINE_LENGTH, ' ' ^ sp_img);
	write(STDOUT_FILENO, decoded_cipher, INPUT_FILE_LINE_LENGTH);
	printf("\n");

	/*
	 * 	 Exit
	 */
	fclose(cipher);

	return 0;
}