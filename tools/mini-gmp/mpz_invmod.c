#include "mpz_invmod.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

void print_bignum(const mpz_ptr bignum)
{
	char *bignum_str = mpz_get_str(NULL, 10, bignum);
	printf("%s \n", bignum_str);
	free(bignum_str);
}


int mpz_invmod(mpz_t *inv, const  mpz_t x, const  mpz_t n)
{
	unsigned int return_code = 0x00;
	mpz_t m_one, nt, r, tmp, q, nr;

	mpz_init_set_si(m_one, -1);
	mpz_init_set_si(*inv, 0);
	mpz_init_set_si(nt, 1);
	mpz_init_set(r,n);
	mpz_init(tmp);
	mpz_init(q);
	mpz_init(nr);
	mpz_mod (nr, x, n);
	
	if (0 > mpz_sgn(n))
		mpz_mul(n,n, m_one);

	if (0 > mpz_sgn(x))
	{
		// x = n - (-x % n);
		mpz_mul(x,x, m_one);
		mpz_mod(x, x, n);
		mpz_sub(x, n, x);

	}

    while (0 != mpz_sgn(nr))
    {
    
      // q = r/nr;
      mpz_tdiv_q (q, r, nr);

      //tmp = nt;  nt = t - q*nt;  t = tmp;
	  mpz_set(tmp, nt);
	  mpz_mul(nt, q, nt);
      mpz_sub(nt, *inv, nt);
	  mpz_set(*inv, tmp);
	  
      //tmp = nr;  nr = r - q*nr;  r = tmp;
	  mpz_set(tmp, nr);
	  mpz_mul(nr, q, nr);
      mpz_sub(nr, r, nr);
	  mpz_set(r, tmp);

    }

    if (0 < mpz_cmp_si(r, 1)) 
    {
    	mpz_set(*inv, m_one);  /* No inverse */
    	return_code = -EINVAL;
    }
    else
    {	
    	if (mpz_sgn(*inv) < 0) 
    		mpz_add(*inv, *inv, n);
    }

    mpz_clear(m_one);
    mpz_clear(nt);
    mpz_clear(r);
    mpz_clear(tmp);
    mpz_clear(q);
    mpz_clear(nr);

    return return_code;
	
}

void check_invmod(int x,  int n,  int expected_result)
{
	mpz_t a,b,inv;

	mpz_init_set_si(a, x);
	mpz_init_set_si(b, n);
	//mpz_init(inv);
	mpz_invmod(&inv, a, b);

	printf("Invmod of %d %% %d \n", x, n );
	printf("Expected : %d\n", expected_result );
	printf("Result : ");
	print_bignum(inv);
	printf("\n");

	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(inv);
}


void test_mpz_invmod()
{
	check_invmod(42, 2017, 1969);
	check_invmod(40, 1, 0);
	check_invmod(52, -217, 96);
	check_invmod(-486, 217, 121);
	check_invmod(40, 2018, -1);
}
