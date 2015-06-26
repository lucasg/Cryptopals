#include "client.h"
#include "hex.h"
#include "mt19937.h"
#include "mini-gmp/mini-gmp.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>



/*
 * Equivalent of rand(), using the newly implemented MT19937 prng.
 */
uint64_t client_get_random_value()
{
	uint64_t ret = 0x00;
	struct mt19937_t mt_single_shot;

	mt19937_init(&mt_single_shot, time(NULL));
	ret = mt19937_get_value(&mt_single_shot);
	ret <<= 32;
	ret |= mt19937_get_value(&mt_single_shot);

	return  ret;
}


void client_init(struct client_t *c, mpz_t N, mpz_t g, mpz_t k)
{
	memset(c, 0, sizeof(struct client_t));
	mpz_init_set(c -> srp.N, N);
	mpz_init_set(c -> srp.g, g);
	mpz_init_set(c -> srp.k, k);

	mpz_init_set_ui(c -> srp.id, client_get_random_value());

	srp_utils_gen_client_pubkey(&(c -> srp.pubkey), g , c -> srp.id, N);

}

void client_init_shared(struct client_t *c, const char *password, size_t password_len, mpz_t server_pubkey, const mpz_t u)
{
	mpz_t  x, S,k;

	// Simplified SRP : S does not depend on k
	mpz_init_set_ui(k, 0 );

	// 1. u = SHA256(A|B)
	//srp_utils_gen_shared_hash( &u, server_pubkey , c -> srp.pubkey);

	// 2. Generate x
	srp_utils_gen_x(&x, password, password_len, c -> salt_str, c -> salt_len);

	// 5. Generate S = B**(a + u * x) % N
	srp_utils_gen_client_shared_secret(&S, server_pubkey, c -> srp.g, k, x, u, c -> srp.id, c -> srp.N );

    // 6. Generate K = SHA256(S)
	srp_utils_gen_shared_key(c -> K, S);

	/*free(salt_str);*/

	mpz_clear(x);
	mpz_clear(S);
	mpz_clear(k);
}

void client_cleanup(struct client_t *c)
{
	srp_info_cleanup(&(c ->srp));

	if (NULL != c -> salt_str)
		free(c -> salt_str);
	c -> salt_str = NULL;

	memset(c, 0, sizeof(struct client_t));
}