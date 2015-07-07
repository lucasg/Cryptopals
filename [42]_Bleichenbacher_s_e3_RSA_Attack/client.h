#ifndef _CLIENT_H_
	#define _CLIENT_H_

#include "mini-gmp/mini-gmp.h"
#include "rsa_sign_constants.h"


/*
 * Initialize the client with the private key used to sign the messages.
 */
int client_init(const  mpz_t private_key, const  mpz_t n);


/* 
 * Sign a mesage using the private key.
 */
int client_sign_msg(mpz_t *signature, const char *msg, const size_t msg_len, const enum rsa_sign_hash_method hash_method );

/*
 * Free any allocated resources
 */
int client_cleanup();

#endif /* _CLIENT_H_ */