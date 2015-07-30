#ifndef _BLEICHENBACHER_98_H_
	#define _BLEICHENBACHER_98_H_

#include "mini-gmp/mini-gmp.h"
#include "mini-gmp/mpz_invmod.h"

struct bleichenbacher_98_t
{
	/* bleichenbacher's candidate */
	mpz_t r, s;

	/* Search space initial and current boundaries */
	mpz_t min_range, max_range;
	mpz_t a,b;

	/* RSA constants */
	mpz_t e, n;

	/* ciphertext */
	mpz_t c;

	/* server validation function */
	int (*server_padding_validate)(const mpz_t); 
};

/*
 * Initalize bleichenbacher useful variables
 */
int b98_init(struct bleichenbacher_98_t *b98, const size_t rsa_byte_len, const mpz_t c, const mpz_t e, const mpz_t n, int (*server_validation)(const mpz_t) );

/*
 * Step 2.a of bleichenbacher's algorithm : initial search
 */
int b98_initial_search(struct bleichenbacher_98_t *b98);

/*
 * Step 2.c of bleichenbacher's algorithm : search when the domain consists
 * of a single interval
 */
int b98_search_single_range(struct bleichenbacher_98_t *b98);

/*
 *  Check server padding for ciphertext "c*(s**e)".
 */
int b98_check_padding(struct bleichenbacher_98_t *b98);

/*
 * Step 3 of bleichenbacher's algorithm : search space reduction
 */
int b98_update_boundaries(struct bleichenbacher_98_t *b98);



/*
 *  Free any allocated resources
 */
int b98_cleanup(struct bleichenbacher_98_t *b98);

#endif /* _BLEICHENBACHER_98_H_ */