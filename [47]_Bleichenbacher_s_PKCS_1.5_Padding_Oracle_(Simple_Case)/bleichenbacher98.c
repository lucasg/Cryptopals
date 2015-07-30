#include "bleichenbacher98.h"

#define B98_FRAC_ADD (0x0)
#define B98_FRAC_SUB (0x1)

/*
 * Compute (ax +/- b)/d
 */
int b98_compute_frac(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d, int sign)
{
	mpz_t num_tmp;

	mpz_init(num_tmp);
	mpz_mul(num_tmp, a, x);

	switch (sign)
	{
	case B98_FRAC_ADD:
		mpz_add(num_tmp, num_tmp, b);
		break;
	case B98_FRAC_SUB:
		mpz_sub(num_tmp, num_tmp, b);
		break;
	default:
		mpz_clear(num_tmp);
		return -1;
	}

	mpz_tdiv_q (result, num_tmp, d);

	mpz_clear(num_tmp);
	return 0x00;
}

/*
 * Compute (ax + b)/d
 */
int b98_compute_frac_add(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d)
{
	
	return b98_compute_frac(result, a, x, b, d, B98_FRAC_ADD);
}

/*
 * Compute (ax - b)/d
 */
int b98_compute_frac_sub(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d)
{
	return b98_compute_frac(result, a, x, b, d, B98_FRAC_SUB);
}

/*
 *  Compute the minimal r value at Step 2.c (1) for s-search
 */
int b98_compute_min_r(mpz_t r, const mpz_t s_1, const mpz_t b, const  mpz_t min_range, const  mpz_t n )
{
	int frac_retcode;

	frac_retcode = b98_compute_frac_sub(r, b, s_1, min_range, n);
	mpz_mul_ui(r, r, 2);

	return frac_retcode;
}

/*
 *  Compute the lower bound s value at Step 2.c (1) for s-search
 */
int b98_compute_min_s(mpz_t min_s, const mpz_t r_1, const mpz_t b, const mpz_t min_range, const mpz_t n )
{
	return b98_compute_frac_add(min_s, r_1, n, min_range, b);
}


/*
 *   Compute the upper bound s value at Step 2.c (1) for s-search
 */
int b98_compute_max_s(mpz_t max_s, const mpz_t r_1, const mpz_t a, const mpz_t max_range, const mpz_t n )
{
	return b98_compute_frac_add(max_s, r_1, n, max_range, a);
}

/* 
 *  Update the lower bound for plaintext candidates domain
 */
int b98_update_a(mpz_t a, const mpz_t r, const mpz_t s, const mpz_t two_B,  const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	b98_compute_frac_add(tmp, r, n, two_B, s);

	
	if (mpz_cmp(tmp, three_B) > 0)
		return 0x00;

	if (mpz_cmp(a, tmp) < 0)
	{
		mpz_set(a, tmp);
		return 0x01;
	}

	mpz_clear(tmp);

	return 0x00;

}

/* 
 *  Update the upper bound for plaintext candidates domain
 */
int b98_update_b(mpz_t b, const mpz_t r, const mpz_t s, const mpz_t two_B, const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	b98_compute_frac_add(tmp, r, n, three_B, s);

	if (mpz_cmp(tmp, two_B) < 0)
		return 0x00;
	
	if (mpz_cmp(b, tmp) > 0)
	{
		mpz_set(b, tmp);
		return 0x01;
	}

	mpz_clear(tmp);

	return 0x00;
}

/*
 * Initalize bleichenbacher useful variables
 */
int b98_init(struct bleichenbacher_98_t *b98, const size_t rsa_byte_len, const mpz_t c, const mpz_t e, const mpz_t n, int (*server_validation)(const mpz_t) )
{
	mpz_t B, two, B_exp;

	mpz_init_set(b98->c, c);
	mpz_init_set(b98->e, e);
	mpz_init_set(b98->n, n);

	/* B = 2**(8*(k-2)) */
	mpz_init(B);
	mpz_init_set_ui(two, 2);
	mpz_init_set_ui(B_exp, 8*(rsa_byte_len - 2));
	mpz_powm(B, two, B_exp, n);

	/* min_range = 2B */
	mpz_init(b98->min_range);
	mpz_mul_ui(b98->min_range, B, 2);	

	/* max_range = 3B - 1*/
	mpz_init(b98->max_range);
	mpz_mul_ui(b98->max_range, B, 3);
	mpz_sub_ui(b98->max_range, b98->max_range, 1);

	mpz_init_set(b98->a, b98->min_range);
	mpz_init_set(b98->b, b98->max_range);

	mpz_init_set_ui(b98->s, 1);
	mpz_init_set_ui(b98->r, 1);


	b98 -> server_padding_validate = server_validation;

	mpz_clear(B);
	mpz_clear(B_exp);
	mpz_clear(two);
	return 0x00;
}

/*
 *  Free any allocated resources
 */
int b98_cleanup(struct bleichenbacher_98_t *b98)
{
	mpz_clear(b98->c);
	mpz_clear(b98->n);
	mpz_clear(b98->e);

	mpz_clear(b98->r);
	mpz_clear(b98->s);



	mpz_clear(b98->min_range);
	mpz_clear(b98->max_range);
	mpz_clear(b98->a);
	mpz_clear(b98->b);

	b98 -> server_padding_validate = NULL;
	return 0x00;
}

/*
 * Step 2.a of bleichenbacher's algorithm : initial search
 */
int b98_initial_search(struct bleichenbacher_98_t *b98)
{
	int pad_check = 0x00;

	mpz_cdiv_q (b98->s, b98->n, b98->max_range);
	while(!pad_check)
	{
		mpz_add_ui(b98->s, b98->s, 1);
		pad_check = b98_check_padding(b98);
	}

	return 0x00;
}

/*
 * Step 2.c of bleichenbacher's algorithm : search when the domain consists
 * of a single interval
 */
int b98_search_single_range(struct bleichenbacher_98_t *b98)
{
	int pad_check = 0x00;
	mpz_t min_s, max_s;

	mpz_init(min_s);
	mpz_init(max_s);

	b98_compute_min_r(b98->r, b98->s, b98->b, b98->min_range, b98->n);
	while (0x01 != pad_check && mpz_cmp(b98->r, b98->max_range) <= 0)
	{
		b98_compute_min_s(min_s, b98->r, b98->b, b98->min_range, b98->n);
		b98_compute_max_s(max_s, b98->r, b98->a, b98->max_range, b98->n);
		
		mpz_set(b98->s, min_s);
		while (mpz_cmp(b98->s, max_s) < 0 && 0x1 != pad_check)
		{
			mpz_add_ui(b98->s, b98->s, 1);
			pad_check = b98_check_padding(b98);
		}

		/* solution found */
		if (pad_check)
			break;

		mpz_add_ui(b98->r, b98->r, 1);
	}

	mpz_clear(min_s);
	mpz_clear(max_s);
	return pad_check;
}


/*
 *  Check server padding for ciphertext "c*(s**e)".
 */
int b98_check_padding(struct bleichenbacher_98_t *b98)
{
	int pad_check;
	mpz_t s_e, c_s_e;

	mpz_init(s_e);
	mpz_init(c_s_e);

		
	mpz_powm(s_e, b98->s, b98->e, b98->n);
	mpz_mul(c_s_e, b98->c, s_e);
	pad_check = (b98->server_padding_validate)(c_s_e);

	mpz_clear(c_s_e);
	mpz_clear(s_e);

	return pad_check;
}

/*
 * Step 3 of bleichenbacher's algorithm : search space reduction
 */
int b98_update_boundaries(struct bleichenbacher_98_t *b98)
{
	mpz_t min_r, max_r;

	mpz_init(min_r);
	mpz_mul(min_r, b98->a, b98->s );
	mpz_sub(min_r, min_r, b98->max_range);
	mpz_cdiv_q (min_r, min_r, b98->n);
	if (!mpz_sgn(min_r))
		mpz_add_ui(min_r, min_r, 1);

	mpz_init(max_r);
	mpz_mul(max_r, b98->b, b98->s );
	mpz_sub(max_r, max_r, b98->min_range);
	mpz_fdiv_q (max_r, max_r, b98->n);

	if (mpz_cmp(min_r, max_r) > 0)
	{
		mpz_set(min_r, b98->r);
		mpz_set(max_r, b98->r);
	}


	b98_update_a(b98->a, min_r, b98->s,  b98->min_range,  b98->max_range, b98->n );
	b98_update_b(b98->b, max_r, b98->s,  b98->min_range,  b98->max_range, b98->n );

	mpz_clear(min_r);
	mpz_clear(max_r);
	return 0x00;
}