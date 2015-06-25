#include "mpz_crt.h"
#include "mini-gmp/mpz_invmod.h"
#include <stdio.h>
#include <stdlib.h>

// Chinese Remainder Theorem
void mpz_crt(mpz_t *result, mpz_t residues[3], mpz_t modulus[3])
{
	size_t i;
	mpz_t msn[3], tmp[3], invmod[3], modprod;

	for (i = 0; i  < 3; i++)
	{
		mpz_init(msn[i]);
		mpz_mul(msn[i], modulus[(i+1) % 3], modulus[(i+2) % 3]);
		//printf("msn = %s\n", mpz_get_str(NULL, 0, msn[i]));
		//printf("mod = %s\n", mpz_get_str(NULL, 0, modulus[i]));

		mpz_init(invmod[i]);
		mpz_invmod(invmod + i , msn[i], modulus[i]);
		//printf("inmvod %d = %s\n", i, mpz_get_str(NULL, 0, invmod[i]));
	}

	mpz_init(modprod);
	mpz_mul(modprod, msn[0], modulus[0]); 

	mpz_init_set_ui(*result, 0);
	for (i = 0; i  < 3; i++)
	{
		mpz_init_set(tmp[i], residues[i]);
		mpz_mul(tmp[i], tmp[i], msn[i]);
		mpz_mul(tmp[i], tmp[i], invmod[i]);

		mpz_add(*result, *result, tmp[i]);
	}
	mpz_mod(*result, *result, modprod);

	// Root-Cube
	mpz_root(*result, *result, 3);


	// Clean allocated resources
	for (i = 0; i  < 3; i++)
	{
		mpz_clear(msn[i]);
		mpz_clear(tmp[i]);
		mpz_clear(invmod[i]);
	}
	mpz_clear(modprod);
}

// Chinese Remainder Theorem
void unit_test_mpz_crt(mpz_t *result, char *residues[3], char *modulus[3])
{
	size_t i;
	mpz_t res[3], mod[3];

	for (i = 0; i < 3; i++)
	{
		mpz_init_set_str(res[i], residues[i], 0);
		mpz_init_set_str(mod[i], modulus[i], 0);
	}

	mpz_crt(result, res, mod);

	for (i = 0; i < 3; i++)
	{
		mpz_clear(res[i]);
		mpz_clear(mod[i]);
	}
}

// CRT unit test
unsigned int test_mpz_crt()
{

	mpz_t result;
	char *residues[3] = {"6", "4", "6"},
		 *modulus[3] = {"7", "11", "17"},
		 *result_str;
	unit_test_mpz_crt(&result, residues, modulus);

	result_str = mpz_get_str(NULL, 0, result);
	printf("Expected 0x5 : %s\n", result_str);


	free(result_str);
	return 0x01;
}

