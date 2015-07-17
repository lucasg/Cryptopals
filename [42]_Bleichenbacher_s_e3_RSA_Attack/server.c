#include "server.h"
#include "rsa_utils.h"
#include "pkcs1_v1.5.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct sign_stored_struct{
	unsigned char *h_val;
	size_t h_len;
};

static struct sign_stored_struct store;
static mpz_t pubkey, n;

/*
 * Server initialization using public key and modulo
 */
int server_init(const  mpz_t e, const  mpz_t modulo)
{
	mpz_init_set(pubkey, e);
	mpz_init_set(n, modulo);

	return 0x00;
}

/* 
 * Register a new "user", which only the signature is kept in memory
 */
int server_register_sign(const unsigned char *hash_val, const size_t hash_len)
{
	store.h_len = hash_len;
	store.h_val = malloc(hash_len);
	if (NULL == store.h_val)
		return -1;

	memcpy(store.h_val, hash_val, hash_len);
	return 0x00;
}

/*
 * Test whether the input number is a valid RSA signature .
 */
int server_validate_signature(const mpz_t signature)
{
	char *msg, p_msg[RSA_SIGN_BLOCK_LEN];
	int msg_valid;
	size_t msg_len;


	/* 
	 * RSA "decryption" using the public key. Since the input number is a result of a decryption
	 * we should get the plaintext message;
	 */
	if (rsa_decrypt_msg(&msg, &msg_len, signature, pubkey, n))
		return -1;
	
	if (msg_len > RSA_SIGN_BLOCK_LEN)
		return -1;


	/*
	 * GMP strip any leading 0-value (since it has no meaning as a number repr).
	 * Right-align the input message to retrieve any leading zeroes
	 */
	memset(p_msg, 0, RSA_SIGN_BLOCK_LEN);
	memcpy(p_msg + (RSA_SIGN_BLOCK_LEN - msg_len), msg, msg_len);

	msg_valid = pkcs1_v1_5_insecure_validate(p_msg, RSA_SIGN_BLOCK_LEN, store.h_val, store.h_len);
	free(msg);


	return msg_valid;
}

/*
 * Free any allocated resources
 */
int server_cleanup()
{
	mpz_clear(pubkey);
	mpz_clear(n);

	if (NULL != store.h_val)
	{
		free(store.h_val);
		store.h_val = NULL;
	}

	return 0x00;	
}