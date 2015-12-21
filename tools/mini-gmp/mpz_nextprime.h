#ifndef _MPZ_NEXTPRIME_H_
	#define _MPZ_NEXTPRIME_H_

#include "mini-gmp/mini-gmp.h"

/* Return the firts prime number p over n. */
void mpz_nextprime (mpz_t *p, const mpz_t  *n);

#endif /* _MPZ_NEXTPRIME_H_ */