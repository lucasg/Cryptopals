#include "aes_detect_block_size.h"
#include "aes_detect_ecb_mode.h"
#include "target.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


static unsigned char *plain;
static unsigned char *cipher;
static unsigned char *candidate;


/* 
 * Get (padded) secret len
 */
size_t get_secret_len()
{
	unsigned char *ctext;
	size_t secretlen = encrypt(&ctext, NULL, 0);
	free(ctext);

	return secretlen;
}

unsigned char detect_byte(unsigned char *partial_decoding, unsigned int byte_idx, unsigned int  block_idx, unsigned int  block_size)
{
	unsigned char i, byte;

	/* 
	 * Encrypt AA..AAYYYYX plaintext with X the first
	 * unknown byte of the secret plaintext data appended.
	 * Y is the already know bytes and A a placeholder in
	 * order to pad the input data to an exact block length
	 */
	for (i = 0; i < block_size - 1 - byte_idx; i++)
		plain[i] = 'A';
	encrypt(&cipher, plain, block_size - byte_idx - 1);

	/*
	 *	If we want to know the i-th byte, we have to provide the
	 *  (i-1)  previously known bytes.
	 */
	for (i = block_size - 1 - byte_idx; i < block_size*(block_idx+1) - 1; i++)
		plain[i] = partial_decoding[i - (block_size - 1 - byte_idx)];


	for (byte  = 0; byte < 255; byte++)
	{
		/*
		 *	Try every last byte possible until we found a match in the resulting ciphertext.
		 */
		plain[block_size*(block_idx+1) - 1] = byte;
		encrypt(&candidate, plain, block_size*(block_idx+1));
		
		// match found 
		if (0==strncmp( (char*) candidate + block_size*block_idx,
						(char*) cipher    + block_size*block_idx, block_size))
		{
			free(candidate);
			break;
		}

		free(candidate);
	}

	free(cipher);

	return byte;
}


void detect_block(unsigned char *decoded_string, unsigned int block_idx, unsigned int block_size)
{
	unsigned int byte_idx;
	size_t secret_padded_len = get_secret_len(); 
	
	memset(plain, 0 , sizeof(unsigned char)*secret_padded_len);
	for (byte_idx = 0; byte_idx < block_size; byte_idx++)
	{
		decoded_string[block_idx*block_size + byte_idx] = detect_byte(decoded_string, byte_idx, block_idx, block_size);
	}
}

int main (int argc, char *argv[])
{
	unsigned int block_size, ecb_mode;
	unsigned char *decoded_string;

	// Block size detection
	block_size = aes_detect_block_size( (aes_detect_block_size_encrypt) &encrypt);
	printf("Block size used : %d \n", block_size );

	// ECB mode detection
	ecb_mode = aes_ecb_detection_oracle( (aes_encrypt) &encrypt, block_size );
	printf("ECB Encryption mode : %s \n", ecb_mode ? "Yes" : "No" );


	// init resulting text buffer
	size_t secret_padded_len =  get_secret_len(); 
	if (secret_padded_len % block_size)
		secret_padded_len +=  block_size - (secret_padded_len % block_size);

	decoded_string = malloc(sizeof(unsigned char)*(secret_padded_len + 1));
	if (NULL == decoded_string)
		return 0x00;

	plain = malloc(sizeof(unsigned char)*secret_padded_len);
	if (NULL == plain)
		return 0x00;

	memset(plain, 0 , sizeof(unsigned char)*secret_padded_len);
	memset(decoded_string, 0, sizeof(unsigned char)*(secret_padded_len + 1));


	// Decryption
	unsigned int block_idx;
	for (block_idx = 0; block_idx*block_size < get_secret_len(); block_idx++)
		detect_block(decoded_string, block_idx, block_size);
	

	printf("Decoded String : %s \n", decoded_string );

	free(decoded_string);
	free(plain);
	
	return 0x00;
}