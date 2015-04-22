#include "b64.h"
#include "aes_128/aes_128.h"
#include "hamdist.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define BLOCK_LEN (16)
static unsigned int  randprefixlen;
static unsigned char randprefix[3*BLOCK_LEN] = {0};
static unsigned char randkey[BLOCK_LEN] = {0};

static const unsigned char b64secret[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
#define SECRET_LEN  (138) // in actual bytes, since there are 184 b64 chars.


/*
 *	Generate a random key to encrypt plaintext data.
 */
int generate_random_prefix()
{
	unsigned int i;

	for (i=0; i<3*4; i++)
		((int*) randprefix)[i] = rand();

	// Return a prefix len between 25 and 45
	return (int) 25 + (rand() / (double)RAND_MAX * (20 - 1));
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
 *  The ciphertext buffer must be at least bigger than datalen + SECRET_LEN.
 */
int encrypt(unsigned char** cipher, const unsigned char* data, unsigned int datalen)
{
	unsigned int clen;
	unsigned char *tmp;

	size_t padded_len = aes_128_get_padded_length(randprefixlen + datalen + SECRET_LEN, ECB);

	tmp = malloc(padded_len*sizeof(unsigned char));
	if (NULL == tmp)
		return 0;

	*cipher = malloc(padded_len*sizeof(unsigned char));
	if (NULL == *cipher)
	{
		free(tmp);
		return 0;
	}

	memset(tmp, 0, padded_len*sizeof(char));
	memcpy(tmp, randprefix, randprefixlen*sizeof(char));
	memcpy(tmp + randprefixlen, data, datalen*sizeof(char));


	b64_decode((char*) tmp + randprefixlen + datalen, (const char*) b64secret, strlen((char*) b64secret));
	clen = aes_128_encrypt_msg(*cipher, tmp, randprefixlen + datalen + SECRET_LEN, randkey, ECB, NULL);

	free(tmp);

	return clen;
}

/*
 *	Encrypt an empty ciphertext and a single character one
 *  in order to detect the first block of data.
 */
unsigned int detect_prefix_block_num(unsigned long block_len)
{
	unsigned char *cipher0, *cipher1;
	unsigned int clen0, clen1, i;


	clen0 = encrypt(&cipher0, NULL, 0);
	if (NULL == cipher0 || 0 == clen0)
		return 0;

	clen1 = encrypt(&cipher1, (unsigned char*) "A", 1);
	if (NULL == cipher1 || 0 == clen1)
	{
		free(cipher0);
		return 0;
	}
	

	i = 0;
	while ( i < clen1 && i < clen0 && cipher0[i] == cipher1[i])
		i++;

	free(cipher0);
	free(cipher1);

	return i / block_len; 
}

/*
 * Estimate the prefix length modulo a block size, by adding a character for encryption until the next block
 * of ciphertext is impacted.
 */
unsigned int detect_prefix_block_pad(unsigned int pref_block_num)
{
	const unsigned char three_blocks_of_a[3*BLOCK_LEN + 1] = "PPPPPPPPPPPPPPPPPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	
	unsigned char *cipher;
	unsigned int i;

	for (i = 1; i < BLOCK_LEN + 1; i++)
	{
		encrypt(&cipher, three_blocks_of_a + (BLOCK_LEN + 1 - i)  , 2*BLOCK_LEN + i);

		if (!strncmp((char*) cipher + (pref_block_num+1)*BLOCK_LEN,(char*)  cipher + (pref_block_num+2)*BLOCK_LEN, BLOCK_LEN))
		{
			free(cipher);
			break;
		}

		free(cipher);
	}


	return (i) ?  BLOCK_LEN - i : 0; 
}

/*
 * Reveal a byte of aes-ecb secret data, by encrypted (block-1) known data and cycling the last character until the resulting ciphertext match the one with the unknown byte.
 * The presence of a random prefix complicate the padding process, but does not change the overall method.
 */
unsigned char detect_byte(unsigned char *partial_decoding,  unsigned int prefix_len, unsigned int byte_idx, unsigned int  block_idx, unsigned int  block_size)
{
	unsigned char *plain, *cipher, *candidate, i, byte;


	
	unsigned int padded_prefix_len = prefix_len;
	if (prefix_len % block_size)
	 	padded_prefix_len = prefix_len + block_size - (prefix_len % block_size);

	unsigned int pad_fill_len = 0;
	if (prefix_len % block_size)
	 	pad_fill_len = block_size - (prefix_len % block_size);

	plain = malloc(sizeof(unsigned char)*((prefix_len % block_size) + block_size*(block_idx + 1)));
	if (NULL == plain)
		return 0x00;

	/* 
	 * Encrypt PPPPPAA..AAYYYYX plaintext with :
	 *  - X the first unknown byte of the secret plaintext data appended.
	 *  - Y is the already know bytes
	 *  - A a placeholder in order to pad the input data to an exact block length
	 *  - P another padding placeholder for the random prefix.
	 */
	for (i = 0; i < pad_fill_len ; i++)
		plain[i] = 'P';

	for (i = 0; i < block_size - 1 - byte_idx; i++)
		plain[(prefix_len % block_size) + i] = 'A';

	encrypt(&cipher, plain, pad_fill_len + block_size - byte_idx - 1);

	/*
	 *	If we want to know the i-th byte, we have to provide the
	 *  (i-1)  previously known bytes.
	 */
	for (i = block_size - 1 - byte_idx; i < block_size*(block_idx+1) - 1; i++)
		plain[pad_fill_len + i] = partial_decoding[i - (block_size - 1 - byte_idx)];


	for (byte  = 0; byte < 255; byte++)
	{
		/*
		 *	Try every last byte possible until we found a match in the resulting ciphertext.
		 */
		plain[pad_fill_len + block_size*(block_idx+1) - 1] = byte;
		encrypt(&candidate, plain, pad_fill_len + block_size*(block_idx+1));
		
		// match found 
		if (0==strncmp((char*) candidate + padded_prefix_len + block_size*block_idx, (char*) cipher + padded_prefix_len + block_size*block_idx, block_size))
		{
			free(candidate);
			break;
		}

		free(candidate);
	}

	free(plain);
	free(cipher);

	return byte;
}

/*
 * Decrypt a whole block of AES-ECB data, one byte at a time.
 */
void detect_block(unsigned char *decoded_string, unsigned int prefix_len, unsigned int block_idx, unsigned int block_size)
{
	unsigned int byte_idx;
	unsigned int block_length = (SECRET_LEN - block_idx*block_size >  block_size) ? block_size : SECRET_LEN - block_idx*block_size;

	for (byte_idx = 0; byte_idx < block_length; byte_idx++)
		decoded_string[block_idx*block_size + byte_idx] = detect_byte(decoded_string, prefix_len, byte_idx, block_idx, block_size);
}

/*
 * Estimate the padded length of the secret string by encryption an empty data plaintext
 * and substracting the estimated prefix.
 */
unsigned int detect_secret_padded_len(unsigned int prefix_len, unsigned int block_size)
{
	unsigned char *cipher0;
	unsigned int clen0 = 0;

	clen0 = encrypt(&cipher0, NULL, 0);
	if (NULL == cipher0 || 0 == clen0)
		return 0;
	free(cipher0);

	return clen0 - ( prefix_len - (prefix_len % block_size));
}


int main (int argc, char *argv[])
{
	unsigned int block_size = 16, pref_block_num, pref_block_pad;
	unsigned char *decoded_string;

	srand (time (NULL));

	// Init target encryption
	generate_random_key();
	randprefixlen = generate_random_prefix();

	// Estimate prefix length
	pref_block_num = detect_prefix_block_num(block_size);
	pref_block_pad = detect_prefix_block_pad(pref_block_num);
	unsigned int prefix_len = pref_block_num*BLOCK_LEN + pref_block_pad;
	printf("Estimated Prefix len : %d*%d + %d = %d \n", pref_block_num, BLOCK_LEN, pref_block_pad, prefix_len );


	// Allocate secret string to be deciphered 
	unsigned int secret_padded_len = detect_secret_padded_len(prefix_len, block_size);
	decoded_string = malloc(sizeof(unsigned char)*(secret_padded_len + 1));
	if (NULL == decoded_string)
		return 0x00;
	memset(decoded_string, 0, sizeof(unsigned char)*(secret_padded_len + 1));


	// Detect a block, each byte at a time
	unsigned int block_idx;
	for (block_idx = 0; block_idx*block_size < SECRET_LEN; block_idx++)
		detect_block(decoded_string, prefix_len, block_idx, block_size);
	

	printf("Decoded String : %s \n", decoded_string );

	return 0x00;
}