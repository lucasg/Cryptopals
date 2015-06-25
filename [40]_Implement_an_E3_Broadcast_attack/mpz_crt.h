#ifndef _MPZ_CRT_H_
	#define _MPZ_CRT_H_

#include "mini-gmp/mini-gmp.h"

// Chinese Remainder Theorem : r = sum(residue[i]*prod(mod[j], j!=i)*invmod(prod(mod[j], j!=i), modulo[i]), i:=:3)
void mpz_crt(mpz_t *result, mpz_t residues[3], mpz_t modulus[3]);

// CRT unit test
unsigned int test_mpz_crt();


#endif /* _MPZ_CRT_H_ */