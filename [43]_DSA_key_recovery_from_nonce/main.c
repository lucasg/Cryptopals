#include "hex.h"
#include "mt19937.h"
#include "sha1.h"
#include "mini-gmp/mpz_invmod.h"

#include <mini-gmp/mini-gmp.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>


struct dsa_signature_t
{
	mpz_t s1, s2;
};

struct dsa_pubkey_t
{
	mpz_t p, q, g, y;
};

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

const char test_message[] = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

const char Y_TO_CRACKED[] = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
      "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
      "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
      "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
      "bb283e6633451e535c45513b2d33c99ea17";

int gen_128_bit_random_number(mpz_t *result)
{
	size_t i;
	static struct mt19937_t rgen;
	static unsigned int rgen_init = 0x00;
	unsigned char x_hexstring[32+1] = {0x00}, x_string[16] = {0x00}; 

	if (!rgen_init)
	{	
		mt19937_init(&rgen, time(NULL));
		rgen_init = 1;
	}

	// Generate random 16-byte string for x
	for (i = 0; i < 16/sizeof(uint32_t); i++)
	{
		((uint32_t*) x_string)[i] = mt19937_get_value(&rgen);
	}
	hex_encode((char*) x_hexstring, (char*) x_string, 2*16);
	x_hexstring[2*16] = 0x00;

	mpz_init_set_str(*result, (char*) x_hexstring, 16);

	return 0x00;
}

int get_mpz_from_sha1_hash(mpz_t *hash_number, const char message[], const size_t message_len)
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
 *	       (s * k) - H(msg)
 *     x = ----------------  mod q
 *                 r
 */
int compute_private_key_from_nonce(mpz_t *private_key, const struct dsa_signature_t signature, const char message[], const size_t message_len, const struct dsa_pubkey_t pubkey, const mpz_t nonce)
{
	mpz_t inv_s1, s_x_k, h_number;

	mpz_init(s_x_k);
	
	mpz_mul(s_x_k, signature.s2, nonce);
	get_mpz_from_sha1_hash(&h_number, message, message_len);
	mpz_sub(s_x_k, s_x_k, h_number);

	mpz_init(inv_s1);
	if (mpz_invmod(&inv_s1, signature.s1, pubkey.q))
		return -EINVAL; // modular inverse not found

	mpz_init(*private_key);
	mpz_mul(*private_key, s_x_k, inv_s1);
	mpz_mod(*private_key, *private_key, pubkey.q);

	mpz_clear(inv_s1);
	mpz_clear(h_number);
	mpz_clear(s_x_k);

	return EXIT_SUCCESS;
}

int dsa_gen_parameters(mpz_t *p, mpz_t *q, mpz_t *g)
{
	mpz_init_set_str(*p, CONSTANT_P, 16);
	mpz_init_set_str(*q, CONSTANT_Q, 16);
	mpz_init_set_str(*g, CONSTANT_G, 16);

	return EXIT_SUCCESS;
}


int dsa_gen_keys(mpz_t *priv_key, struct dsa_pubkey_t *pubkey)
{
	// g here is 128 bit long, and x < g
	mpz_init_set(*priv_key, pubkey -> g);
	while(0 == mpz_sgn(*priv_key) || mpz_cmp(*priv_key, pubkey -> q) >= 0)
	{
		mpz_clear(*priv_key);
		
		if (gen_128_bit_random_number(priv_key))
			return -EINVAL;		
	}
	printf("private_key : %s \n", mpz_get_str(NULL, 16, *priv_key));

	// Compute y
	mpz_init(pubkey -> y);
	mpz_powm(pubkey -> y, pubkey -> g, *priv_key, pubkey -> p);

	return EXIT_SUCCESS;
}


int dsa_sign(struct dsa_signature_t *signature, const char message[], const size_t message_len, const mpz_t priv_key, const struct dsa_pubkey_t pubkey)
{    
	mpz_t s, h_number, inv_s, x_mul_s1, recomputed_privkey;

    //Choisir un nombre aléatoire s, 1 < s < q
	mpz_init_set(s, pubkey.g);
	while(0 == mpz_sgn(s) || mpz_cmp(s, pubkey.q) >= 0)
	{
		mpz_clear(s);
		
		if (gen_128_bit_random_number(&s))
			return -EINVAL;		
	}

    // s1 = (gs mod p) mod q
	mpz_init(signature -> s1);
	mpz_powm(signature -> s1, pubkey.g, s, pubkey.p);
	mpz_mod( signature -> s1, signature -> s1, pubkey.q);

    //  s2 = (H(m) + s1*x)s-1 mod q
	mpz_init(x_mul_s1);
	mpz_mul(x_mul_s1, priv_key, signature -> s1);
	get_mpz_from_sha1_hash(&h_number, message, message_len);

	mpz_init(inv_s);
	if (mpz_invmod(&inv_s, s, pubkey.q))
		return -EINVAL; // modular inverse not found

    // signature is (s1,s2)
	mpz_init(signature -> s2);
	mpz_add(signature -> s2, h_number, x_mul_s1);
	mpz_mul(signature -> s2, signature -> s2, inv_s);
	mpz_mod(signature -> s2, signature -> s2, pubkey.q);

	// check valid signature process
	if (EXIT_SUCCESS == compute_private_key_from_nonce(&recomputed_privkey, *signature, message, message_len, pubkey, s))
	{
		if (0 != mpz_cmp(recomputed_privkey, priv_key))
			printf("Could not recompute the private key : %s != %s \n", mpz_get_str(NULL, 16, recomputed_privkey), mpz_get_str(NULL, 16, priv_key));

		mpz_clear(recomputed_privkey);
	}

    mpz_clear(s);
    mpz_clear(h_number);
    mpz_clear(inv_s);
    mpz_clear(x_mul_s1);
	return 0x00;
}



int crack_private_key(mpz_t *bf_priv_key, const struct dsa_signature_t signature, const char message[], const size_t message_len, const struct dsa_pubkey_t pubkey)
{
	unsigned int private_key_found, k, i = 0;
	mpz_t y, nonce, x, r;

	mpz_init(nonce);

	k = 0;
	private_key_found = 0;
	while (!private_key_found && k <= 0x10000)
	{
		if (0 == (k % 128))
			printf(".");

		mpz_set_ui(nonce, k);
		mpz_init(r);
		mpz_powm(r, pubkey.g, nonce, pubkey.p);
		mpz_mod(r,r, pubkey.q);

		if (0 == mpz_cmp(r, signature.s1))
		{
			i++;

			compute_private_key_from_nonce(&x, signature, message, message_len, pubkey, nonce);
			mpz_init(y);
			mpz_powm(y, pubkey.g, x, pubkey.p);

			if (0 == mpz_cmp(y, pubkey.y))
			{
				printf("\nnonce used : 0x%x \n", k);
				printf("pubkey used : 0x%s \n", mpz_get_str(NULL, 16, y));
				mpz_init_set(*bf_priv_key, x);
				private_key_found = 1;
			}

			mpz_clear(x);
			mpz_clear(y);
		}

		k++;
		mpz_clear(r);
	}

	mpz_clear(nonce);
	return private_key_found ? EXIT_SUCCESS : EXIT_FAILURE;
}


int main(int argc, char *argv[])
{
	size_t i;
	mpz_t p_key, cracked_pkey;
	struct dsa_pubkey_t pubkey;
	struct dsa_signature_t signature;
	struct sha1nfo  hash;
	unsigned char *sha_result;
	char *cracked_pkey_hexstr;

	dsa_gen_parameters(&(pubkey.p), &(pubkey.q), &(pubkey.g));
	dsa_gen_keys(&p_key, &pubkey);

	if (!dsa_sign(&signature, test_message, sizeof(test_message) - 1, p_key, pubkey))
		printf("test signature :\n\t%s\n\t%s\n", mpz_get_str(NULL, 16, signature.s1), mpz_get_str(NULL, 16, signature.s2));


	// Challenge
	mpz_set_str(signature.s1, (char*) "548099063082341131477253921760299949438196259240", 10);
	mpz_set_str(signature.s2, (char*) "857042759984254168557880549501802188789837994940", 10);
	mpz_set_str(pubkey.y, Y_TO_CRACKED, 16);

	if (EXIT_SUCCESS == crack_private_key(&cracked_pkey, signature, test_message, sizeof(test_message) - 1, pubkey))
	{
		cracked_pkey_hexstr = mpz_get_str(NULL, 16, cracked_pkey);
		printf("Found private key : %s\n", cracked_pkey_hexstr);

		sha1_init(&hash);
		sha1_write(&hash, cracked_pkey_hexstr, strlen(cracked_pkey_hexstr));
		sha_result = sha1_result(&hash);
		printf("Cracked private key sha1 hash : ");
		for (i = 0; i < SHA1_HASH_LENGTH; i++)
			printf("%02x:", sha_result[i]);
		printf("\n");

		free(cracked_pkey_hexstr);
		mpz_clear(cracked_pkey);
	}
	else
	{
		printf("Could not found private key \n");
	}

	mpz_clear(p_key);
	mpz_clear(signature.s1);
	mpz_clear(signature.s2);
	mpz_clear(pubkey.p);
	mpz_clear(pubkey.q);
	mpz_clear(pubkey.g);
	mpz_clear(pubkey.y);
	return 0;
}