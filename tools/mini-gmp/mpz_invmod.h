#ifndef _MPZ_INVMOD_H_
	#define _MPZ_INVMOD_H_

#include "mini-gmp/mini-gmp.h"


// Modular inversion using GMP bignum integers
int mpz_invmod(mpz_t *inv, mpz_t x, mpz_t n);

// Unit Test for MPZ Modular inversion
void test_mpz_invmod();


#endif /* _MPZ_INVMOD_H_ */