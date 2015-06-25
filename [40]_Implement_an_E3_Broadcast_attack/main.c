#include "hex.h"
#include "mpz_crt.h"
#include "mini-gmp/mpz_invmod.h"
#include "mini-gmp/mpz_nextprime.h"
#include "mini-gmp/mini-gmp.h"
#include "mt19937.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const char NIST_e[] = "3";
const char mc_solaar_secret[] = ""
"Si je meurs ce soir, fuck la Terre\n"
"Je serai sûrement dans le journal comme Nino Ferrer\n"
"Les jours passent et la vie suit son cours\n"
"La politique reste la meme que tu vote contre ou pour\n";


#define BITLEN_MIN (2048)



int gen_random_hex_str(char **hexstring, size_t *hexlen, unsigned int minbitlen, struct mt19937_t *ext_gen)
{
	size_t i;
	unsigned char *random_str;
	struct mt19937_t r_gen, *rgen;

	// 
	if (NULL == ext_gen)
	{
		mt19937_init(&r_gen, time(NULL));
		rgen = &r_gen;
	}

	// We pad the minimum length to fit a multiple of our mt19937 gen output
	size_t min_charlen = minbitlen/(8*sizeof(char));
	if (min_charlen % sizeof(uint32_t))
		min_charlen += min_charlen  - (min_charlen % sizeof(uint32_t));


	random_str = malloc(min_charlen);
	if (NULL == random_str)
		return 0x01;

	*hexstring = malloc(1 + 2*min_charlen);
	if (NULL == *hexstring)
	{
		free(random_str);
		return 0x01;
	}

	for (i = 0; i < min_charlen/sizeof(uint32_t); i++)
	{
		((uint32_t*) random_str)[i] = mt19937_get_value(rgen);
	}

	// Force the first bit to one in order to have a random integer greater than 2**minbitlen
	random_str[0] |= 0x80;

	// Force the last bit to one in order to have an odd number
	random_str[min_charlen - 1] |= 0x01;	


	hex_encode_c(*hexstring, (char*)  random_str, 2*min_charlen);
	(*hexstring)[2*min_charlen] = 0x00;

	free(random_str);
	return 0x00;
}


int rsa_gen_prime_num(mpz_t *p, mpz_t *q, unsigned int bitlen_min)
{
	struct mt19937_t r_gen;
	size_t random_hexlen;
	char *random_hexstr;
	mpz_t min_p, min_q;


	mt19937_init(&r_gen, time(NULL));

	// Generate random hex-strings of at least BITLEN_MIN bits long.
	if (gen_random_hex_str(&random_hexstr, &random_hexlen, bitlen_min, &r_gen))
		return 0x01;
	mpz_init_set_str(min_p, random_hexstr, 16);

	free(random_hexstr);
	if (gen_random_hex_str(&random_hexstr, &random_hexlen, bitlen_min, &r_gen))
		return 0x01;
	mpz_init_set_str(min_q, random_hexstr, 16);

	// Search for next prime using GMP's Miller-Rabin test
	mpz_nextprime(p, (const mpz_t*) &min_p);
	mpz_nextprime(q, (const mpz_t*) &min_q);


	mpz_clear(min_p);
	mpz_clear(min_q);

	return 0x00;
}

int rsa_gen_key(mpz_t *n, mpz_t *e, mpz_t *d)
{
	mpz_t p, q, totient, one, p_m_1, q_m_1;

	mpz_init(p);
	mpz_init(q);
	mpz_init(*n);
	mpz_init(totient);
	mpz_init_set_ui(one, 1);
	mpz_init(p_m_1);
	mpz_init(q_m_1);	
	mpz_init_set_str(*e, NIST_e, 0 );

	mpz_init_set_si(*d, -1);
	while ( 0 ==  mpz_cmp_si(*d, -1))
	{
		// RSA Prime number generation
		rsa_gen_prime_num( &p, &q, BITLEN_MIN / 2);


		/* RSA key generation */
	
		// n = p*q
		mpz_mul(*n, p, q);

		// phi = (p-1)*(q-1)
		mpz_sub(p_m_1, p, one);
		mpz_sub(q_m_1, q, one);
		mpz_mul(totient, p_m_1, q_m_1 );
		
		// d = 1/e % phi
		mpz_invmod(d, *e, totient);

		printf(".");
		
	}

	mpz_clear(totient);
	mpz_clear(one);
	mpz_clear(p_m_1);
	mpz_clear(q_m_1);
	mpz_clear(p);
	mpz_clear(q);
	return 0x00;
}


int rsa_encrypt(mpz_t *c, mpz_t *n, const char *secret, const size_t secret_len)
{
	char *hex_secret = NULL;
	mpz_t e, d, m;


	// RSA key generation
	rsa_gen_key(n, &e, &d);


	// Message creation
	hex_secret = malloc(1 + 2*secret_len*sizeof(char));
	if (NULL == hex_secret)
		return 0x01;

	hex_encode_c(hex_secret, secret, 2*secret_len);
	hex_secret[2*secret_len] = 0x00;
	mpz_init_set_str(m, hex_secret, 16);


	// Message len verification
	if (0 < mpz_cmp(m, *n))
	{
		printf("The secret message is 'longer' than the current rsa modulus can accomodate.\n");
		return 0x01;
	}
	

	// Encryption
	mpz_init(*c);
	mpz_powm(*c, m, e, *n);

	if (NULL != hex_secret)
		free(hex_secret);
	mpz_clear(m);
	return 0x00;
}


int main(int argc, char *argv[])
{
	size_t i;
	char *hex_decrypted, *decrypted;
	mpz_t cipher[3], modulo[3], result;

	test_mpz_crt();
	

	// Capturing ciphertexts
	printf("Looking for RSA ciphertext generation. It can take a while ");
	for (i = 0; i  < 3; i++)
		if (rsa_encrypt(cipher + i, modulo + i, mc_solaar_secret, strlen(mc_solaar_secret)))
			return 0x01; // Error while encrypting
	printf("\nRSA encryption done.\n\n");


	// Chinese Remainder Theorem
	mpz_crt(&result, cipher, modulo);


	hex_decrypted = mpz_get_str(NULL, 16, result);
	printf("Decrypted Hex string : %s \n", hex_decrypted);	

	decrypted = malloc((strlen(hex_decrypted)/2 + 1)*sizeof(char));
	if (NULL == decrypted)
	{
		if (NULL != hex_decrypted)
			free(hex_decrypted);
		return 0x01;
	}

	hex_decode_c(decrypted, hex_decrypted, strlen(hex_decrypted));
	decrypted[strlen(hex_decrypted)/2] = 0;
	printf("Decrypted message : %s \n", decrypted);

	printf("Is decoded message correct ? %s", strncmp(decrypted, mc_solaar_secret, strlen(mc_solaar_secret)) ? "NO" : "YES" );	

	if (NULL != hex_decrypted)
		free(hex_decrypted);
	if (NULL != decrypted)
		free(decrypted);

	return 0x00;
}