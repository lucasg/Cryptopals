#ifndef _CLIENT_H_
	#define _CLIENT_H_

#include "srp_utils.h"
#include "sha256.h"
#include "mini-gmp/mini-gmp.h"

struct client_t {
	/* SRP specific variables */
	struct srp_info_t srp;

	/* Auth request parameter (salt, key).*/
	char   *salt_str;
	size_t  salt_len;
	uint8_t K[SHA256_HASH_SIZE];
};

/*
 * 
 */
void client_init(struct client_t *c, mpz_t N, mpz_t g, mpz_t k);

/*
 *
 */
void client_init_shared(struct client_t *c, const char *pass, size_t pass_len, mpz_t server_pubkey);

/*
 *
 */
void client_cleanup(struct client_t *c);

#endif /* _CLIENT_H_ */