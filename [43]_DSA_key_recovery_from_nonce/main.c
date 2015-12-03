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

int dsa_gen_parameters(mpz_t *p, mpz_t *q, mpz_t *g)
{
	mpz_init_set_str(*p, CONSTANT_P, 16);
	mpz_init_set_str(*q, CONSTANT_Q, 16);
	mpz_init_set_str(*g, CONSTANT_G, 16);

	return 0x00;
}

int gen_128_bit_random_number(mpz_t *result)
{
	size_t i;
	static struct mt19937_t rgen;
	static unsigned int rgen_init = 0x00;
	unsigned char x_hexstring[32+1], x_string[16]; 

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

int dsa_gen_keys(mpz_t *priv_key, struct dsa_pubkey_t *pubkey)
{
	// g here is 128 bit long, and x < g
	mpz_init_set(*priv_key, pubkey -> g);
	while(0 == mpz_sgn(*priv_key) || mpz_cmp(*priv_key, pubkey -> g) >= 0)
	{
		mpz_clear(*priv_key);
		
		if (gen_128_bit_random_number(priv_key))
			return -EINVAL;		
	}

	// Compute y
	mpz_init(pubkey -> y);
	mpz_powm(pubkey -> y, pubkey -> g, *priv_key, pubkey -> p);

	return 0x00;
}


int dsa_sign(struct dsa_signature_t *signature, const char message[], const size_t message_len, const mpz_t priv_key, const struct dsa_pubkey_t pubkey)
{    
	mpz_t s, h_number, inv_s, x_mul_s1;
	struct sha1nfo  hash;
	unsigned char hexstring[2*SHA1_HASH_LENGTH + 1] = {0};

    // Choisir un nombre aléatoire s, 1 < s < q
	mpz_init_set(s, pubkey.g);
	while(0 == mpz_sgn(s) || mpz_cmp(s, pubkey.g) >= 0)
	{
		mpz_clear(s);
		
		if (gen_128_bit_random_number(&s))
			return -EINVAL;		
	}

    // Calculer s1 = (gs mod p) mod q
	mpz_init(signature -> s1);
	mpz_powm(signature -> s1, pubkey.g, s, pubkey.p);
	mpz_mod( signature -> s1, signature -> s1, pubkey.q);

    // Calculer s2 = (H(m) + s1*x)s-1 mod q, où H(m) est le résultat d'un hachage cryptographique, par exemple avec SHA-1, sur le message m
	sha1_init(&hash);
	sha1_write(&hash, (char *) message, message_len);
	hex_encode((char*) hexstring, (char*) sha1_result(&hash), 2*SHA1_HASH_LENGTH);
	mpz_init_set_str(h_number, (char*) sha1_result(&hash), 16);
	
	mpz_init(x_mul_s1);
	mpz_mul(x_mul_s1, priv_key, signature -> s1);

	mpz_init(inv_s);
	if (mpz_invmod(&inv_s, s, pubkey.q))
		return -EINVAL; // modular inverse not found

	mpz_init(signature -> s2);
	mpz_add(signature -> s2, h_number, x_mul_s1);
	mpz_mul(signature -> s2, signature -> s2, inv_s);
	mpz_mod(signature -> s2, signature -> s2, pubkey.q);


    // La signature est (s1,s2)
    mpz_clear(s);
    mpz_clear(h_number);
    mpz_clear(inv_s);
    mpz_clear(x_mul_s1);
	return 0x00;
}




int main(int argc, char *argv[])
{
	mpz_t p_key, y;
	struct dsa_pubkey_t pubkey;
	struct dsa_signature_t signature;

	dsa_gen_parameters(&(pubkey.p), &(pubkey.q), &(pubkey.g));
	dsa_gen_keys(&p_key, &pubkey);

	if (!dsa_sign(&signature, test_message, sizeof(test_message) - 1, p_key, pubkey))
		printf("test signature :\n\t%s\n\t%s\n", mpz_get_str(NULL, 16, signature.s1), mpz_get_str(NULL, 16, signature.s2));

	
	mpz_init_set_str(pubkey.y, Y_TO_CRACKED, 16);

	return 0;
}