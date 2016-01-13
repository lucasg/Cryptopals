#include "xor.h"
#include "mt19937.h"
#include <time.h>
#include <stdlib.h>	
#include <stdio.h>	
#include <string.h>	
#include <unistd.h>

#ifdef WIN32
	#include <windows.h>
	#define sleep(t) Sleep(t*1000) 
#endif

static struct mt19937_t cipher_mt;
static unsigned int token_init = 0x00;
static unsigned int random_prefix_len = 0x00;

/*
 * Equivalent of rand(), using the newly implemented MT19937 prng.
 */
uint32_t get_random_value()
{
	struct mt19937_t mt_single_shot;
	mt19937_init(&mt_single_shot, time(NULL));

	return mt19937_get_value(&mt_single_shot);
}

/*
 *  Reset the prng seed to the current timestamp (aka token reset).
 */
void password_token_reset()
{
	sleep(1 + (get_random_value() % 15));

	mt19937_init(&cipher_mt, time(NULL));
	token_init = 0x01;
	
	sleep(1 +(get_random_value() % 15));
}

/*
 * Encrypt a plaintext message using the mt19937 generator as keystream
 */
size_t encrypt( uint8_t *ctext[], const  uint8_t ptext[], const size_t len)
{
	size_t i;
	uint8_t *keystream;

	if (!random_prefix_len)
		random_prefix_len = 1 + (get_random_value() % 15);

	// Init MT19937 prng to a new seed
	password_token_reset();		
		
	keystream = malloc(len*sizeof(uint8_t));
	if (NULL == keystream)	
		return 0x00;

	*ctext = malloc((random_prefix_len + len)*sizeof(uint8_t));
	if (NULL == *ctext)
	{
		free(keystream);
		return 0x00;
	}	

	for (i = 0; i < random_prefix_len; i++)
		(*ctext)[i] = (uint8_t) get_random_value();

	mt19937_init( &cipher_mt, cipher_mt.seed);
	for (i = 0; i < len; i++)
		keystream[i] = mt19937_get_value(&cipher_mt);

	xor_encode(&((*ctext)[random_prefix_len]), ptext, len, keystream, len);

	free(keystream);

	return random_prefix_len + len;
}

/*
 * Decrypt a ciphertext message using the mt19937 generator as keystream
 */
unsigned int decrypt( uint8_t *ptext[], const  uint8_t ctext[], const size_t len)
{
	size_t i;
	uint8_t *keystream;

	// MT PRNG not init
	if (!token_init)
		return 0x01;

	keystream = malloc(len*sizeof(uint8_t));
	if (NULL == keystream)	
		return 0x01;

	*ptext = malloc((len - random_prefix_len)*sizeof(uint8_t));
	if (NULL == ptext)
	{
		free(keystream);
		return 0x01;
	}

	mt19937_init( &cipher_mt, cipher_mt.seed);
	for (i = 0; i < len; i++)
		keystream[i] = mt19937_get_value(&cipher_mt);

	xor_encode(*ptext , ctext + random_prefix_len, len, keystream, len);

	free(keystream);

	return 0x00;
}