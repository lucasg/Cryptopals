#include "hex.h"
#include "sha1.h"
#include "dsa.h"

#include "mini-gmp/mpz_invmod.h"
#include <mini-gmp/mini-gmp.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>


const char test_message[] = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

const char Y_TO_CRACKED[] = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
      "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
      "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
      "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
      "bb283e6633451e535c45513b2d33c99ea17";


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
	
	mpz_mul(s_x_k, signature.s, nonce);
	get_mpz_from_sha1_hash(&h_number, message, message_len);
	mpz_sub(s_x_k, s_x_k, h_number);

	mpz_init(inv_s1);
	if (mpz_invmod(&inv_s1, signature.r, pubkey.q))
		return -EINVAL; // modular inverse not found

	mpz_init(*private_key);
	mpz_mul(*private_key, s_x_k, inv_s1);
	mpz_mod(*private_key, *private_key, pubkey.q);

	mpz_clear(inv_s1);
	mpz_clear(h_number);
	mpz_clear(s_x_k);

	return EXIT_SUCCESS;
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

		if (0 == mpz_cmp(r, signature.r))
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


	// DSA implementation test
	dsa_gen_fixed_parameters(&pubkey);
	dsa_gen_keys(&p_key, &pubkey);

	if (!dsa_sign(&signature, test_message, sizeof(test_message) - 1, p_key, pubkey))
		printf("test signature :\n\t%s\n\t%s\n",
						mpz_get_str(NULL, 16, signature.r),
						mpz_get_str(NULL, 16, signature.s));


	// Challenge
	mpz_set_str(signature.r, (char*) "548099063082341131477253921760299949438196259240", 10);
	mpz_set_str(signature.s, (char*) "857042759984254168557880549501802188789837994940", 10);
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
	mpz_clear(signature.r);
	mpz_clear(signature.s);
	mpz_clear(pubkey.p);
	mpz_clear(pubkey.q);
	mpz_clear(pubkey.g);
	mpz_clear(pubkey.y);
	return 0;
}