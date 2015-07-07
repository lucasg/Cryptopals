#include "server.h"
#include "rsa_utils.h"
#include "hex.h"
#include <stdio.h>

#define BITLEN_MIN (1024)

static mpz_t d, e, n;

/*
 *  Generate key and several constants for RSA communication
 */
int server_init(mpz_t *ext_e, mpz_t *ext_n)
{
	if (rsa_gen_key(&n, &e, &d, BITLEN_MIN))
	{
		printf("Error while generating RSA keys\n");
		return 0x01;
	}

	mpz_init_set(*ext_n, n);
	mpz_init_set(*ext_e, e);

	return 0x00;
}

/*
 * Encrypt a message using the server private key (unkwown to the caller)
 */
int server_encrypt_msg(mpz_t *c, const char *plaintext, const size_t plaintext_len )
{
	if (rsa_encrypt_msg(c, n, e, plaintext, plaintext_len))
	{
		printf("Error while encrypting message \n");
		return 0x01;
	}

	return 0x00;
}

/*
 * Encrypt a message using the server private key (unkwown to the caller)
 */
int server_decrypt_msg(mpz_t *m, const mpz_t c )
{
	return rsa_decrypt(m, c, d, n);
}


/* 
 * Free any allocated memory
 */ 
int server_cleanup()
{
	mpz_clear(e);
	mpz_clear(n);
	mpz_clear(d);

	return 0x00;
}