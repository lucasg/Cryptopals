#ifndef _SERVER_H_
	#define _SERVER_H_

#include "mini-gmp/mini-gmp.h"
#include <stdint.h>

/*
 *  Generate key and several constants for RSA communication
 */
int server_init(mpz_t *e, mpz_t *n);

/*
 * Encrypt a message using the server private key (unkwown to the caller)
 */
int server_encrypt_msg(mpz_t *c, const char *plaintext, const size_t plaintext_len );

/*
 * Encrypt a message using the server private key (unkwown to the caller)
 */
int  server_decrypt_msg(mpz_t *n, const mpz_t c );


/* 
 * Free any allocated memory
 */ 
int server_cleanup();

#endif /* _SERVER_H_ */