#ifndef _SERVER_H_
	#define _SERVER_H_

#include "mini-gmp/mini-gmp.h"
#include "rsa_sign_constants.h"

/*
 * Server initialization using public key and modulo
 */
int server_init(const mpz_t e, const  mpz_t n);


/* 
 * Register a new "user", which only the signature is kept in memory
 */
int server_register_sign(const unsigned char *hash_val, const size_t hash_len);


/*
 * Test whether the input number is a valid RSA signature .
 */
int server_validate_signature(const mpz_t signature);


/*
 * Free any allocated resources
 */
int server_cleanup();


#endif /* _SERVER_H_ */