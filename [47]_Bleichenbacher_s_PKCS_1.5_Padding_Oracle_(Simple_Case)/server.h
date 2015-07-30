#ifndef _SERVER_H_
	#define _SERVER_H_

#include "mini-gmp/mini-gmp.h"

/*
 * Server initialization using public key and modulo
 */
int server_init(mpz_t e,  mpz_t modulo);


/* 
 *  Encrypt a new message, using pkcs#14 v1.5 padding and the server's secret key.
 */
int server_encrypt_msg(mpz_t *ciphertext, const char *plaintext, const size_t ptext_len);


/*
 * Test whether the input number is a valid RSA signature .
 */
int server_check_padding(const mpz_t ciphertext);


/*
 * Free any allocated resources
 */
int server_cleanup();


#endif /* _SERVER_H_ */