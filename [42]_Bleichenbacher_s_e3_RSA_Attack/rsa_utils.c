#include "hex.h"
#include "mt19937.h"
#include "mini-gmp/mpz_invmod.h"
#include "mini-gmp/mpz_nextprime.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>


const char weak_e[] = "3";
const char NIST_e[] = "65537";

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


	hex_encode(*hexstring, (char*)  random_str, 2*min_charlen);
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

	mpz_init(*p);
	mpz_init(*q);
		
	mt19937_init(&r_gen, time(NULL));

	// Generate random hex-strings of at least BITLEN_MIN bits long.
	if (gen_random_hex_str(&random_hexstr, &random_hexlen, bitlen_min, &r_gen))
		return 0x01;
	mpz_init_set_str(min_p, random_hexstr, 16);
	free(random_hexstr);
	
	if (gen_random_hex_str(&random_hexstr, &random_hexlen, bitlen_min, &r_gen))
		return 0x01;
	mpz_init_set_str(min_q, random_hexstr, 16);
	free(random_hexstr);

	// Search for next prime using GMP's Miller-Rabin test
	mpz_nextprime(p, (const mpz_t*) &min_p);
	mpz_nextprime(q, (const mpz_t*) &min_q);


	mpz_clear(min_p);
	mpz_clear(min_q);

	return 0x00;
}

int rsa_gen_key(mpz_t *n, mpz_t *e, mpz_t *d, const unsigned int bitlen_min)
{
	mpz_t p, q, totient, one, p_m_1, q_m_1;

	mpz_init(*n);
	mpz_init(totient);
	mpz_init_set_ui(one, 1);
	mpz_init(p_m_1);
	mpz_init(q_m_1);	
	mpz_init_set_str(*e, /*NIST_e*/ weak_e, 0 );

	mpz_init_set_si(*d, -1);
	while ( 0 ==  mpz_cmp_si(*d, -1))
	{
		// RSA Prime number generation
		rsa_gen_prime_num( &p, &q, bitlen_min / 2);


		/* RSA key generation */
	
		// n = p*q
		mpz_mul(*n, p, q);

		// phi = (p-1)*(q-1)
		mpz_sub(p_m_1, p, one);
		mpz_sub(q_m_1, q, one);
		mpz_mul(totient, p_m_1, q_m_1 );
		
		// d = 1/e % phi
		mpz_clear(*d);
		mpz_invmod(d, *e, totient);

		//printf(".");
		mpz_clear(p);
		mpz_clear(q);
	}

	mpz_clear(totient);
	mpz_clear(one);
	mpz_clear(p_m_1);
	mpz_clear(q_m_1);

	return 0x00;
}

int rsa_encrypt(mpz_t *c, const mpz_t m, const mpz_t n, const mpz_t e)
{
	// Encryption
	mpz_init(*c);
	mpz_powm(*c, m, e, n);

	return 0x00;
}

int rsa_encrypt_msg(mpz_t *c, const mpz_t n, const mpz_t e,  const char *secret, const size_t secret_len)
{
	char *hex_secret = NULL;
	mpz_t m;


	// Message creation
	hex_secret = malloc(1 + 2*secret_len*sizeof(char));
	if (NULL == hex_secret)
		return 0x01;

	hex_encode(hex_secret, secret, 2*secret_len);
	hex_secret[2*secret_len] = 0x00;
	mpz_init_set_str(m, hex_secret, 16);


	// Message len verification
	if (0 < mpz_cmp(m, n))
	{
		printf("The secret message is 'longer' than the current rsa modulus can accomodate.\n");
		return 0x01;
	}
	
	rsa_encrypt(c, m, n , e);

	// Memory release
	if (NULL != hex_secret)
		free(hex_secret);
	
	mpz_clear(m);
	return 0x00;
}

int rsa_decrypt(mpz_t *m, const mpz_t c, const mpz_t d,  const mpz_t n)
{
	mpz_init(*m);
	mpz_powm(*m, c, d, n);

	return 0x00;
}

int rsa_decrypt_msg(char **secret, size_t *secret_len, const mpz_t c, const mpz_t d, const mpz_t n)
{
	mpz_t m;
	char *hex_decrypted;

	rsa_decrypt(&m, c, d, n);
	
	hex_decrypted = mpz_get_str(NULL, 16, m);
	*secret_len = strlen(hex_decrypted)/2;
	*secret = malloc(1 + *secret_len*sizeof(char));
	if (NULL == *secret)
	{
		free(hex_decrypted);
		mpz_clear(m);
		return 0x01;
	}

	hex_decode(*secret, hex_decrypted, strlen(hex_decrypted));
	(*secret)[*secret_len] = 0;	

	free(hex_decrypted);
	mpz_clear(m);

	return 0x00;
}