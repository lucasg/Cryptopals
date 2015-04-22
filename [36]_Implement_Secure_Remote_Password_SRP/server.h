#ifndef _SERVER_H_
	#define _SERVER_H_

#include "srp_utils.h"
#include "sha256.h"
#include "mini-gmp/mini-gmp.h"
#include "stdint.h"

/*
 *  Entry data structures used to look up the 
 *  authentification is correct.
 */
struct server_entry_t{
	/* plain data (identifier & salt) */
	char   *email, *salt_str;
	size_t  email_len, salt_len;

	/* password verifier (see SRP) */
	mpz_t v;

	/* Shared secret key build using the SRP construction method */
	uint8_t K[SHA256_HASH_SIZE];
};

/*
 * SRP stub server data structure.
 */
struct server_t {
	/* SRP specific variables */
	struct srp_info_t srp;

	/* list of registered "users" */
	struct server_entry_t *entries;
	size_t entries_len, entries_used;
};

/*
 *
 */
unsigned int server_init(struct server_t *s, const mpz_t N, const mpz_t g, const mpz_t k, const size_t entry_cnt);

/*
 *
 */
unsigned int server_add_entry(struct server_t *s, const char* email, const size_t email_len, 
										  const char* password, const size_t password_len);

/*
 *
 */
char* server_init_shared(struct server_t *s, const char *email, const size_t email_len, const mpz_t client_pubkey);

/*
 *
 */
unsigned int server_check_password(struct server_t *s, const char *email, const size_t email_len, const uint8_t password_hmac[SHA256_HASH_SIZE]);

/*
 *
 */
void server_cleanup(struct server_t *s);

#endif /* _SERVER_H_ */