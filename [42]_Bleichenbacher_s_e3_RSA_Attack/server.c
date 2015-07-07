#include "server.h"
#include "rsa_utils.h"

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
 * Test whether the input number is a valid RSA signature .
 */
int server_validate_signature(const mpz_t signature)
{
	char *msg;
	int msg_valid;
	size_t msg_len, i;


	/* 
	 * RSA "decryption" using the public key. Since the input number is a result of a decryption
	 * we should get the plaintext message;
	 */
	if (rsa_decrypt_msg(&msg, &msg_len, signature, pubkey, n))
		return -1;

/*	printf("[DEBUG] m : ");
	for (i = 0; i < msg_len; i++ )
		printf("%02x", (unsigned char) msg[i]);
	printf("\n");*/

	msg_valid = pcks1_5_insecure_validate(msg, msg_len);
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

	return 0x00;	
}