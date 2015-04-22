#include "target.h"
#include "../tools/b64.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static unsigned int key_init = 0;
static unsigned char randkey[16] = {0};
static const unsigned char b64secret[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24"\
										 "gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdG"\
										 "FuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b"\
										 "3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";


/*
 *	Get the base64'd decoded length.
 */
size_t target_get_secret_len()
{
	return b64_get_ascii_wc(strlen((char*)b64secret));
} 


/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_random_key()
{
	unsigned int i;

	for (i=0; i<4; i++)
		((int*) randkey)[i] = rand();
	
}

/*
 *	encrypt plaintext data, using the randomly generated key.
 *  Append the secret to the plaintext before encryption.
 *  The ciphertext buffer must be at least bigger than datalen + get_secret_len().
 */
size_t encrypt(unsigned char **cipher, const unsigned char* data, size_t datalen)
{
	// AES key random generation (once)
	if (!key_init)
	{
		srand (time (NULL));
		// 
		generate_random_key();
		key_init = 0x1;		
	}


	size_t clen, input_len = (datalen+target_get_secret_len());
	unsigned char *tmp;

	if (input_len % aes_128_block_len)
		input_len += aes_128_block_len - (input_len % aes_128_block_len);

	tmp = malloc(input_len*sizeof(char));
	if (NULL==tmp)
		return 0;

	*cipher = malloc(input_len*sizeof(char));
	if (NULL==*cipher)
	{
		free(tmp);
		return 0;
	}

	memset(*cipher, 0, input_len*sizeof(char));
	memset(tmp    , 0, input_len*sizeof(char));

	memcpy(tmp, data, datalen*sizeof(char));
	b64_decode((char*) tmp+datalen, (const char*) b64secret, strlen((char*) b64secret));
	
	clen = aes_128_encrypt_msg(*cipher, tmp, input_len, randkey, ECB, NULL);

	free(tmp);

	return clen;
}