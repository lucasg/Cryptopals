#ifndef _RSA_UTILS_H_
	#define _RSA_UTILS_H_

#include "mini-gmp/mini-gmp.h"
#include <stdint.h>


/*
 *  RSA public and private key generation using random primes
 */
int rsa_gen_key(mpz_t *n, mpz_t *e, mpz_t *d, const unsigned int bitlen_min);

/*
 *  RSA encryption (modular arithmetics)
 */
int rsa_encrypt(mpz_t *c, const mpz_t m, const mpz_t n, const mpz_t e);

/*
 *  RSA practical encryption of an input string
 */
int rsa_encrypt_msg(mpz_t *c, const mpz_t n, const mpz_t e,  const char *secret, const size_t secret_len);

/*
 *  RSA decryption (modular arithmetics)
 */
int rsa_decrypt(mpz_t *m, const mpz_t c, const mpz_t d,  const mpz_t n);

/*
 *  RSA practical decryption into a string
 */
int rsa_decrypt_msg(char **secret, size_t *secret_len, const mpz_t c, const mpz_t d, const mpz_t n);



#endif /* _RSA_UTILS_H_ */