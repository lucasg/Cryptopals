#ifndef _SRP_UTILS_H_
	#define _SRP_UTILS_H_

#include "sha256.h"
#include "mini-gmp/mini-gmp.h"
#include <stdint.h>

/*
 *
 */
struct srp_info_t {
	/* Mathematical constants */
	mpz_t N, g, k;

	/* Diffie-Hellman private and public key */
	mpz_t id, pubkey;

};

/*
 *  Free memory allocation within the structure
 */
void srp_info_cleanup(struct srp_info_t *srp);

/*
 * Generate a salt_len bytes long hexadecimal random salt (with memory allocation)
 */
size_t srp_utils_gen_random_salt(char **salt, const size_t salt_len);

/*
 * Generate a random Diffie-Hellman private identifier used for key exchange
 * at least id_len bytes long.
 */ 
void srp_utils_gen_random_dh_id(mpz_t *dh_id ,const size_t id_len);

/*
 * Compute the integer equivalent x of SHA256( salt || password )
 */ 
void srp_utils_gen_x(mpz_t *x, const char *password, const  size_t password_len,
								const char *salt,  const  size_t salt_len);

/*
 * Given a password and salt, generate the password verifier 'v = g^x % N'.
 */
void srp_utils_gen_password_verifier(mpz_t *v, const  mpz_t g, const  mpz_t N,
	   										   const char *password, const  size_t password_len,
										 	   const char *salt,  const  size_t salt_len );


/*
 * 
 */
void srp_utils_gen_server_pubkey(mpz_t *pubkey, const mpz_t k, const mpz_t v, const  mpz_t g, const  mpz_t dh_id, const  mpz_t N);

/*
 * 
 */
void srp_utils_gen_client_pubkey(mpz_t *pubkey, const mpz_t g, const  mpz_t dh_id, const  mpz_t N);

/*
 * 
 */
void srp_utils_gen_shared_hash(mpz_t *u, const mpz_t s_pubkey, const mpz_t c_pubkey);

/*
 * 
 */
void srp_utils_gen_server_shared_secret(mpz_t *S, const mpz_t s_pubkey, const mpz_t g,
												  const mpz_t v, const mpz_t u,
												  const mpz_t dh_id, const mpz_t N);

/*
 * 
 */
void srp_utils_gen_client_shared_secret(mpz_t *S, const mpz_t s_pubkey, const mpz_t g,
												  const mpz_t k, const mpz_t x, const mpz_t u,
												  const mpz_t dh_id, const mpz_t N);

/*
 * 
 */
void srp_utils_gen_shared_key(uint8_t K[SHA256_HASH_SIZE], const mpz_t S);


/*
 * 
 */
unsigned int srp_utils_check_auth(const uint8_t sK[SHA256_HASH_SIZE], const char *salt, const size_t salt_len, const uint8_t c_hmac[SHA256_HASH_SIZE]);

#endif /* _SRP_UTILS_H_ */