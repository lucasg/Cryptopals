#include "bot.h"
#include "sha1.h"
#include "pkcs7.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

/*
 *	Generate a random iv
 */
void generate_riv(struct bot_t *bot)
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) &(bot -> iv.iv))[i] = rand();

	for (i=0; i<4; i++)
		((int*) &(bot -> iv.iv))[i] = rand();

}

/*
 *  Init the key exchange protocol parameters.
 */
void bot_init(struct bot_t *bot, const mpz_t privkey, const mpz_t p, const mpz_t g )
{
	// DH parameters
	mpz_init_set(bot -> p, p);
	mpz_init_set(bot -> g, g);

	// keys 
	mpz_init_set(bot -> privkey, privkey);
	mpz_init(bot -> pubkey);
	mpz_init(bot -> shared_secret);

	// AES internal buffer
	memset(&(bot -> iv), 0, sizeof(union aes_128_init));
	bot -> msg_buffer = NULL;
	bot -> msg_bufferlen = 0x00;
}

/*
 *  Generate the public key used in DH key exchange protocol, based on modular exponenetiation.
 */
mpz_t* bot_gen_pubkey(struct bot_t *bot)
{
	mpz_powm(bot -> pubkey, bot ->  g, bot ->  privkey, bot ->  p);
	return &(bot -> pubkey);
}

void sha1_utils_print_array(uint8_t* array, size_t array_len, unsigned int swap_endianess)
{
	int i;
	for (i=0; i<array_len; i++) {
		printf("/x%02x", array[i]);
	}
	printf("\n");
}

void sha1_utils_printHash(uint8_t* hash) {
	sha1_utils_print_array(hash, 20, 0x00);
}

/*
 *  Generate the shared secret between two bots, give the other public key
 */
mpz_t* bot_gen_shared_secret(struct bot_t *bot, const mpz_t o_pubkey)
{
	struct sha1nfo hash;
	char *secret_key;

	// shared secret generation
	mpz_powm(bot -> shared_secret, o_pubkey , bot ->  privkey, bot ->  p);

	// Hashing the secret in order to have a usable AES key
	sha1_init(&hash);
	secret_key = mpz_get_str(NULL, 10, bot -> shared_secret);
	sha1_write(&hash, secret_key, strlen(secret_key));
	memcpy(bot -> hashed_skey, sha1_result(&hash), sizeof(bot -> hashed_skey));


	free(secret_key);
	return &(bot -> shared_secret);
}


/*
 *  "Send" a message : in reality encrypt it.
 */
size_t send_msg(struct bot_t *bot, const uint8_t *msg, const size_t msg_len)
{
	size_t padded_len = aes_128_get_padded_length(msg_len, CBC);
	
	if (NULL != bot -> msg_buffer)
		free(bot -> msg_buffer);

	generate_riv(bot);

	bot -> msg_buffer = malloc((AES_128_BLOCK_LEN + padded_len)*sizeof(char));
	if (NULL == bot -> msg_buffer)
		return 0x00;

	memcpy(bot -> msg_buffer,&(bot -> iv.iv), (AES_128_BLOCK_LEN)*sizeof(char));
	aes_128_encrypt_msg(bot -> msg_buffer + AES_128_BLOCK_LEN*sizeof(char), msg, msg_len, bot -> hashed_skey, CBC , &(bot -> iv));
	bot -> msg_bufferlen = AES_128_BLOCK_LEN + padded_len;

	return padded_len;
}

/*
 *  "Receive" a message : in reality decrypt it.
 */
size_t recv_msg(struct bot_t *bot, const uint8_t *cmsg, const size_t cmsg_len)
{
	const uint8_t *cmsg_payload = cmsg + AES_128_BLOCK_LEN;
	const size_t cmsg_payload_len = cmsg_len- AES_128_BLOCK_LEN;

	if (NULL != bot -> msg_buffer)
		free(bot -> msg_buffer);

	bot -> msg_buffer = malloc(( 1 + cmsg_payload_len)*sizeof(char));
	if (NULL == bot -> msg_buffer)
		return 0x00;

	memset(bot -> msg_buffer, 0, sizeof(union aes_128_init));

	aes_128_decrypt_msg(bot -> msg_buffer, cmsg_payload, cmsg_payload_len, bot -> hashed_skey, CBC, (union aes_128_init*) cmsg);
	bot -> msg_bufferlen = pkcs7_strip(bot -> msg_buffer, cmsg_payload_len);
	bot -> msg_buffer[bot -> msg_bufferlen] = 0;


	return bot -> msg_bufferlen;
}


/*
 *  Free any allocated memory
 */
void bot_cleanup(struct bot_t *bot)
{
	if (NULL != bot -> msg_buffer)
		free(bot -> msg_buffer);

	mpz_clear(bot -> privkey);
	mpz_clear(bot -> pubkey);
	mpz_clear(bot -> p);
	mpz_clear(bot -> g);
	mpz_clear(bot -> shared_secret);

	memset(bot, 0, sizeof(struct bot_t));
}