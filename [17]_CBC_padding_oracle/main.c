#include "target.h"
#include "../tools/aes_128/aes_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>




/*
 *  Decode a secret byte by bitfliping the (block-1) corresponding byte in order to create a valid padding.
 *  From the padding length of byte value, we then can deduce the secret byte value.
 *
 *  Any return value over 255 is an error (no match found).
 */
short decode_byte(unsigned char *decoded, unsigned  char *previous_block, int byte_idx, char prev_start_point)
{
	unsigned int byte, i;
	unsigned int reverse_byte_idx; 

	/*
	 *  Mask the already known bytes in order to create a (byte_idx) long padding : "\xbyte_idx\xbyte_idx\...\xbyte_idx"
	 */
	for (i=0; i < byte_idx; i++)
	{
		reverse_byte_idx = aes_128_block_len - i - 1;
		previous_block[reverse_byte_idx] ^= decoded[reverse_byte_idx]  ^ (byte_idx + 1);
	}

	/*
	 *	
	 */
	reverse_byte_idx = aes_128_block_len - byte_idx - 1;
	unsigned char t = previous_block[reverse_byte_idx];
	for( byte = prev_start_point; byte < 256; byte++)
	{
		previous_block[reverse_byte_idx] = byte ^ t ^ (byte_idx + 1);

		if (decrypt(previous_block, 32))
		{
			decoded[reverse_byte_idx] = byte;
			break;
		}
	}
	previous_block[reverse_byte_idx] = t;


	/*
	 * Revert the bytes to their original values
	 */
	for (i=0; i < byte_idx; i++)
	{
		reverse_byte_idx = aes_128_block_len - i - 1;
		previous_block[reverse_byte_idx] ^= decoded[reverse_byte_idx]  ^ (byte_idx + 1);
	}


	return byte;
}

/*
 * Decode a whole 16-byte block of secret data.
 * The padding oracle attack works by decoding every byte from right to left, so the 
 * convention here is to enumerate from (aes_128_block_len to 0).
 */
void decode_block(unsigned char *decoded, unsigned  char *iv_cipher, int block_idx)
{
	size_t i;
	short previous_secret_byte, secret_byte;

	previous_secret_byte = 0;
	for (i = 0; i < aes_128_block_len; i++)
	{

		secret_byte = decode_byte(decoded + block_idx*aes_128_block_len, iv_cipher, i, 0);

		/*
		 * There is a slight probability that we stumble upon the wrong padding.
		 * e.g for if a block finish in "\0x08\0x02\0x03" :
		 *		-> 0x01 is a valid padding
		 *      -> 0x02\0x02 is also a valid one, although not the one we want.
		 * so we can find several bytes leading to a valid padding. From time to
		 * time, if we don't find a match for the i-th byte, we need to traceback
		 * and look for another valid (i-1)-th byte.
		 */ 
		while (secret_byte > 255)
		{
			
			previous_secret_byte = decode_byte(decoded + block_idx*aes_128_block_len, iv_cipher, i - 1, previous_secret_byte + 1);

			if (256 <= previous_secret_byte)
				printf("Well, you're out of luck : you've stroke the (1/256)^3 chance where we have to traceback twice in a row\n");

			secret_byte  = decode_byte(decoded + block_idx*aes_128_block_len, iv_cipher, i, 0);


		}

		previous_secret_byte = secret_byte;
	}

}


int main (int argc, char *argv[])
{
	size_t clen,i,j;
	unsigned char *cipher, *secret, *tmp_buf;


	clen = encrypt(&cipher);
	if (NULL == cipher || 0 == clen)
		return 0x01;

	secret = malloc((clen - aes_128_block_len + 1)*sizeof(char));
	if (NULL == secret)
	{
		free(cipher);
		return 0x01;
	}

	tmp_buf = malloc((2*aes_128_block_len)*sizeof(char));
	if (NULL == tmp_buf)
	{
		free(cipher);
		free(secret);
		return 0x01;
	}

	memset(secret, 0,  (clen - aes_128_block_len + 1)*sizeof(char));
	memset(tmp_buf, 0, (2*aes_128_block_len)*sizeof(char));

	printf("Cipher Buf len : %d \n",  (clen + aes_128_block_len)*sizeof(char));
	for (i = 0;  i*aes_128_block_len < (clen - aes_128_block_len); i++)
	{
		memcpy(tmp_buf, cipher + i*aes_128_block_len, 2*aes_128_block_len*sizeof(char));

		decode_block(secret, tmp_buf, i);
	}

	
	secret[clen - aes_128_block_len] = 0x00;
	printf("Secret : %s \n\t", secret);
	for (j = 0; j < clen - aes_128_block_len + 1; j++)
		 printf(" %02x", secret[j]);
	printf("\n");

	printf("Is it the real secret ? %s", (0 != is_right_answer((char*)secret)) ? "yes" : "no");


	free(tmp_buf);
	free(secret);
	free(cipher);
	return 0x00;
}