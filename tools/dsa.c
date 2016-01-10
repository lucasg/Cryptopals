#include "dsa.h"
#include "hex.h"
#include "sha1.h"
#include "mt19937.h"
#include "mini-gmp/mpz_invmod.h"
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

const char CONSTANT_P[] = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
     "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
     "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
     "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
     "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
     "1a584471bb1";
 
const char CONSTANT_Q[] = "f4f47f05794b256174bba6e9b396a7707e563c5b";
 
const char CONSTANT_G[] = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
     "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
     "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
     "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
     "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
     "9fc95302291";

int _dsa_gen_random_number(mpz_t *result, size_t upper_bound_bytelen)
{
	size_t i;
	static struct mt19937_t rgen;
	static unsigned int rgen_init = 0x00;
	unsigned char *x_hexstring, *x_string; 

	if (!rgen_init)
	{	
		mt19937_init(&rgen, time(NULL));
		rgen_init = 1;
	}

	x_string = malloc(upper_bound_bytelen);
	if (NULL == x_string)
		return -EINVAL;

	x_hexstring = malloc(2*upper_bound_bytelen + 1);
	if (NULL == x_hexstring)
	{
		free(x_string);
		return -EINVAL;
	}

	/* Generate random upper_bound_bytelen-byte string for x */
	for (i = 0; i < upper_bound_bytelen/sizeof(uint32_t); i++)
	{
		((uint32_t*) x_string)[i] = mt19937_get_value(&rgen);
	}

	/* Translate the string into a mpz_t number */
	hex_encode((char*) x_hexstring, (char*) x_string, 2*20);
	x_hexstring[2*upper_bound_bytelen] = 0x00;
	mpz_init_set_str(*result, (char*) x_hexstring, 20);

	free(x_hexstring);
	free(x_string);
	return EXIT_SUCCESS;
}

int _dsa_gen_bounded_random_number(mpz_t *result, const mpz_t upper_bound)
{
	char *upper_bound_hex_string;
	size_t upper_bound_bytelen;

	/* Compute necessary amount a bytelen to generate */
	upper_bound_hex_string = mpz_get_str(NULL, 16, upper_bound);
	upper_bound_bytelen = strlen(upper_bound_hex_string)/2;

	/* Loop until we get a generated number lower than the upper bound */
	mpz_init_set(*result, upper_bound);
	while(0 == mpz_sgn(*result) || mpz_cmp(*result, upper_bound) >= 0)
	{
		mpz_clear(*result);
		
		if (_dsa_gen_random_number(result, upper_bound_bytelen))
			return -EINVAL;		
	}

	return EXIT_SUCCESS;
}

int _dsa_get_mpz_from_sha1_hash(mpz_t *hash_number, const char message[], const size_t message_len)
{
	struct sha1nfo  hash;
	unsigned char hexstring[2*SHA1_HASH_LENGTH + 1] = {0};

	sha1_init(&hash);
	sha1_write(&hash, (char *) message, message_len);
	hex_encode((char*) hexstring, (char*) sha1_result(&hash), 2*SHA1_HASH_LENGTH);
	mpz_init_set_str(*hash_number, (char*) hexstring, 16);
	
	return 0x00;
}

/*
 * 
 */
int dsa_gen_fixed_parameters(struct dsa_pubkey_t *pubkey)
{
	mpz_init_set_str(pubkey -> p, CONSTANT_P, 16);
	mpz_init_set_str(pubkey -> q, CONSTANT_Q, 16);
	mpz_init_set_str(pubkey -> g, CONSTANT_G, 16);

	return EXIT_SUCCESS;
}

/*
 * 
 */
int dsa_gen_parameters(struct dsa_pubkey_t *pubkey)
{
	return -1;
}


int dsa_gen_keys(mpz_t *priv_key, struct dsa_pubkey_t *pubkey)
{
	/* Generate random private key */
	if (_dsa_gen_bounded_random_number(priv_key, pubkey -> q))
			return -EINVAL;	

	/* Compute corresponding y */
	mpz_init(pubkey -> y);
	mpz_powm(pubkey -> y, pubkey -> g, *priv_key, pubkey -> p);

	return EXIT_SUCCESS;
}


int dsa_sign(struct dsa_signature_t *signature, const char message[], const size_t message_len, const mpz_t priv_key, const struct dsa_pubkey_t pubkey)
{    
	int dsa_verify_ret_code; 
	mpz_t s, h_number, inv_s, x_mul_s1;

    /* Choose a random nonce */
    if (_dsa_gen_bounded_random_number(&s, pubkey.q))
   		return -EINVAL;	
    

    /* r = (g**nonce mod p) mod q */
	mpz_init(signature -> r);
	mpz_powm(signature -> r, pubkey.g, s, pubkey.p);
	mpz_mod( signature -> r, signature -> r, pubkey.q);

    /*  s = (H(m) + r*x)nonce-1 mod q */
	mpz_init(x_mul_s1);
	mpz_mul(x_mul_s1, priv_key, signature -> r);
	_dsa_get_mpz_from_sha1_hash(&h_number, message, message_len);

	/* inverse the nonce : it's actually better than use t_cdiv_q */
	mpz_init(inv_s);
	if (mpz_invmod(&inv_s, s, pubkey.q))
	{
		mpz_clear(s);
		mpz_clear(h_number);
		mpz_clear(x_mul_s1);
		return -EINVAL; /* modular inverse not found */
	}

    /* signature is (r,s) */
	mpz_init(signature -> s);
	mpz_add(signature -> s, h_number, x_mul_s1);
	mpz_mul(signature -> s, signature -> s, inv_s);
	mpz_mod(signature -> s, signature -> s, pubkey.q);

	/* check valid signature process */
	dsa_verify_ret_code = EXIT_SUCCESS;
	if (EXIT_SUCCESS != dsa_verify(*signature, message, message_len, pubkey))
		dsa_verify_ret_code = -EINVAL;

    mpz_clear(s);
    mpz_clear(h_number);
    mpz_clear(inv_s);
    mpz_clear(x_mul_s1);
	return dsa_verify_ret_code;
}

/*
 *
 */
int dsa_verify(const struct dsa_signature_t signature, const char message[], const size_t message_len, const struct dsa_pubkey_t pubkey)
{
	int verify_ret_code;
	mpz_t inv_s, w, h_number, u_1, u_2, v;

	if (mpz_cmp(signature.r, pubkey.q) > 0 || mpz_cmp(signature.s, pubkey.q) > 0)
		return -EINVAL;

	mpz_init(inv_s);
	if (mpz_invmod(&inv_s, signature.s, pubkey.q))
		return -EINVAL;

	mpz_init(w);
	mpz_mod(w, inv_s, pubkey.q);

	mpz_init(u_1);
	_dsa_get_mpz_from_sha1_hash(&h_number, message, message_len);
	mpz_mul(u_1, h_number, w);
	mpz_mod(u_1, u_1, pubkey.q);

	mpz_init(u_2);
	mpz_mul(u_2, signature.r, w);

	
	/* verify signature */
	mpz_init(v);
	mpz_powm(u_1, pubkey.g, u_1, pubkey.p);
	mpz_powm(u_2, pubkey.y, u_2, pubkey.p);
	mpz_mul(v, u_1, u_2);
	mpz_mod(v, v, pubkey.q);
	
	verify_ret_code = mpz_cmp(v, signature.r) ? EXIT_FAILURE: EXIT_SUCCESS;

	mpz_clear(u_2);
	mpz_clear(u_1);
    mpz_clear(h_number);
	mpz_clear(w);
    mpz_clear(inv_s);

	return verify_ret_code;
}