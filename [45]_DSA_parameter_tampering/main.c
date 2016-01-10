#include "dsa.h"

#include "mini-gmp/mpz_invmod.h"
#include <mini-gmp/mini-gmp.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
	mpz_t p_key;
	struct dsa_pubkey_t pubkey;
	struct dsa_signature_t signature;
	
	/* 'Fix' domain parameters */
	dsa_gen_fixed_parameters(&pubkey);
	mpz_add_ui(pubkey.g, pubkey.p, 1);

	/* All public key are congruent to 1 modulo p. */
	dsa_gen_keys(&p_key, &pubkey);

	mpz_init_set_ui(signature.r, 1);
	mpz_init_set_ui(signature.s, 1); /* s can be chosen freely, since it does not have an impact on DSA verification */

	if (EXIT_SUCCESS == dsa_verify(signature, "Hello world", sizeof("Hello world") - 1, pubkey)
	 && EXIT_SUCCESS == dsa_verify(signature, "Goodbye world", sizeof("Goodbye world") - 1, pubkey))
		printf("Signature verified even without knowledge of private key.\n");
	else
		printf("Could not have a valid signature.\n");



	mpz_clear(p_key);
	mpz_clear(signature.r);
	mpz_clear(signature.s);
	mpz_clear(pubkey.p);
	mpz_clear(pubkey.q);
	mpz_clear(pubkey.g);
	mpz_clear(pubkey.y);
	return 0;
}