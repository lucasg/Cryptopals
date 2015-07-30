#include "rsa_utils.h"
#include "mini-gmp/mpz_invmod.h"
#include "server.h"
#include <string.h>
#include <stdio.h>


const static char secret_plaintext[] = "Let's kick it !";

int compute_min_r(mpz_t *r, const mpz_t s_1, const mpz_t b, const  mpz_t min_range, const  mpz_t n )
{
	mpz_t num_tmp;

	mpz_init(num_tmp);
	mpz_mul(num_tmp, b, s_1);
	mpz_sub(num_tmp, num_tmp, min_range);

	mpz_init(*r);
	mpz_tdiv_q (*r, num_tmp, n);
	mpz_mul_ui(*r, *r, 2);

	mpz_clear(num_tmp);

	return 0x00;
}

int compute_min_s(mpz_t *min_s, const mpz_t r_1, const mpz_t b, const mpz_t min_range, const mpz_t n )
{
	mpz_t num_tmp;

	mpz_init(num_tmp);
	mpz_mul(num_tmp, r_1, n);
	mpz_add(num_tmp, num_tmp, min_range);

	mpz_init(*min_s);
	mpz_tdiv_q (*min_s, num_tmp, b);

	mpz_clear(num_tmp);


	return 0x00;
}

int compute_max_s(mpz_t *max_s, const mpz_t r_1, const mpz_t a, const mpz_t max_range, const mpz_t n )
{
	mpz_t num_tmp;

	mpz_init(num_tmp);
	mpz_mul(num_tmp, r_1, n);
	mpz_add(num_tmp, num_tmp, max_range);

	mpz_init(*max_s);
	mpz_tdiv_q (*max_s, num_tmp, a);

	mpz_clear(num_tmp);


	return 0x00;
}

int update_a(mpz_t a, const mpz_t r, const mpz_t s, const mpz_t two_B,  const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	mpz_mul(tmp, r, n);
	mpz_add(tmp, tmp, two_B);

	mpz_tdiv_q (tmp, tmp, s);
	
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

int update_b(mpz_t b, const mpz_t r, const mpz_t s, const mpz_t two_B, const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	mpz_mul(tmp, r, n);
	mpz_add(tmp, tmp, three_B);

	mpz_tdiv_q (tmp, tmp, s);

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

int main (int argc, char *argv[])
{
	int up_a, up_b;
	int pad_check, i;
	mpz_t min_r, max_r;
	mpz_t n, e, c, c_s_e,  s,s_e, s0, s0_i, diff, min_s, max_s;
	mpz_t a,b, B, two, two_B, three_B,  B_exp, r;
	mpz_t m;

	if (server_init(e, n))
	{
		printf("Error while initializing server\n");
		return -1;	
	}
	printf("[DEBUG] n : %s\n", mpz_get_str(NULL, 16, n));
	printf("[DEBUG] e : %s\n", mpz_get_str(NULL, 16, e));
 
	/*  
	 *  Unit-testing the whole signing and validating process
	 */
	printf("Testing server-side encryption : \n");
	if (server_encrypt_msg(&c, secret_plaintext, strlen(secret_plaintext)))
	{
		printf("Error while encrypting a message\n");
		return -1;	
	}

	pad_check = server_check_padding(c);
	if (pad_check < 0)
	{
		printf("Error while checking ciphertext padding\n");
		return -1;	
	}
	else if (0 == pad_check)
		printf("Message not correctly padded\n");
	else
		printf("OK\n");

	mpz_init(B);
	mpz_init(two_B);
	mpz_init(three_B);
	mpz_init_set_ui(two, 2);
	mpz_init_set_ui(B_exp, 8*(32 - 2));
	mpz_powm(B, two, B_exp, n);

	mpz_mul_ui(two_B, B, 2);	
	mpz_mul_ui(three_B, B, 3);
	mpz_sub_ui(three_B, three_B, 1);

	mpz_init_set(a, two_B);
	mpz_init_set(b, three_B);

	/* Step 2.a : Starting the search. */
	mpz_init_set(s, n);
	mpz_cdiv_q (s, s, three_B);


	pad_check = 0x00;
	while(!pad_check /*&& mpz_cmp(s, max_s) < 0*/)
	{
		mpz_init(s_e);
		mpz_init(c_s_e);

		mpz_add_ui(s, s, 1);
		mpz_powm(s_e, s, e, n);
		mpz_mul(c_s_e, c, s_e);
		pad_check = server_check_padding(c_s_e);

		mpz_clear(s_e);
		mpz_clear(c_s_e);
	}
	mpz_init_set(s0, s);

	/* Step 3: Narrowing the set of solutions. */
	mpz_init(min_r);
	mpz_mul(min_r, a, s );
	mpz_sub(min_r, min_r, three_B);
	mpz_cdiv_q (min_r, min_r, n);
	if (!mpz_sgn(min_r))
		mpz_add_ui(min_r, min_r, 1);

	mpz_init(max_r);
	mpz_mul(max_r, b, s );
	mpz_sub(max_r, max_r, two_B);
	mpz_fdiv_q (max_r, max_r, n);
	
	printf("[DEBUG] min_r : %s\n", mpz_get_str(NULL, 16, min_r));
	printf("[DEBUG] max_r : %s\n", mpz_get_str(NULL, 16, max_r));
	

	/* Step 2.c: Searching with one interval left. */
	i = 1;
	pad_check = 0x00;
	while (0x00 != mpz_cmp(a, b))
	{
		/*mpz_init_set(r, min_r);

		while (!pad_check && mpz_cmp(r, max_r) <= 0 )
		{
		*/
		update_a(a, min_r, s, two_B, three_B,  n );
		update_b(b, max_r, s, two_B, three_B, n );


		printf("(a : %s)\n", mpz_get_str(NULL, 16, a));
		printf("(b : %s)\n", mpz_get_str(NULL, 16, b));
		
		mpz_init_set(diff, b);
		mpz_sub(diff, diff,  a);
		printf("Range (%d) : %s \n", i, mpz_get_str(NULL, 16, diff));

		if (0 == mpz_cmp_ui(diff, 1))
			break;

		/* Error : negative range */
		if (mpz_cmp(a,b) < 0)
		{	

			compute_min_r(&r, s, b, two_B, n);
			while (0x01 != pad_check && mpz_cmp(r, three_B) <= 0)
			{
				compute_min_s(&min_s, r, b, two_B, n);
				compute_max_s(&max_s, r, a, three_B, n);

				mpz_init(s_e);
				mpz_init(c_s_e);
				mpz_set(s, min_s);

				mpz_powm(s_e, s, e, n);
				mpz_mul(c_s_e, c, s_e);
				pad_check = server_check_padding(s);
				mpz_clear(s_e);
				mpz_clear(c_s_e);

				while (mpz_cmp(s, max_s) < 0 && 0x1 != pad_check)
				{
					/*mpz_add_ui(s, s, 1);
					pad_check = server_check_padding(s);*/
					mpz_init(s_e);
					mpz_init(c_s_e);

					mpz_add_ui(s, s, 1);
					mpz_powm(s_e, s, e, n);
					mpz_mul(c_s_e, c, s_e);
					pad_check = server_check_padding(c_s_e);

					mpz_clear(s_e);
					mpz_clear(c_s_e);
				}

				/* solution found */
				if (pad_check)
				{
					i++;
					break;
				}

				mpz_add_ui(r, r, 1);
				mpz_clear(min_s);
				mpz_clear(max_s);
			}
			printf("[DEBUG] s : %s \n", mpz_get_str(NULL, 16, s));
			printf("[DEBUG] r : %s\n", mpz_get_str(NULL, 16, r));

			/*printf("Ran out of space\n");*/
			if (pad_check)
			{


				/* Step 3: Narrowing the set of solutions. */
				mpz_clear(min_r);
				mpz_init(min_r);
				mpz_mul(min_r, a, s );
				mpz_sub(min_r, min_r, three_B);
				mpz_cdiv_q (min_r, min_r, n);
				if (!mpz_sgn(min_r))
					mpz_add_ui(min_r, min_r, 1);

				mpz_clear(max_r);
				mpz_init(max_r);
				mpz_mul(max_r, b, s );
				mpz_sub(max_r, max_r, two_B);
				mpz_fdiv_q (max_r, max_r, n);

				if (mpz_cmp(min_r, max_r) > 0)
				{
					mpz_set(min_r, r);
					mpz_set(max_r, r);
				}
				
				printf("[DEBUG] min_r : %s\n", mpz_get_str(NULL, 16, min_r));
				printf("[DEBUG] max_r : %s\n", mpz_get_str(NULL, 16, max_r));

				/*up_a = 0x00;
				up_b = 0x00;
				mpz_set(r, min_r);
				while (!up_a && mpz_cmp(r, max_r) <= 0)
				{
					up_a = update_a(a, r, s, two_B, n );
					mpz_add_ui(r, r, 1);
				}

				mpz_set(r, max_r);
				while (!up_b && mpz_cmp(r, min_r) >= 0)
				{
					if (!up_b)	
						up_b = update_b(b, r, s, three_B, n );
				
					mpz_sub_ui(r, r, 1);
				}*/
			}
		

			if (!pad_check)
				printf("[DEBUG] wrong domain\n");

			mpz_add_ui(r, r, 1);	
		}

		if (!pad_check)
		{
			printf("[DEBUG] Error\n");
			return 0x01;
		}

		pad_check = 0x00;
		mpz_clear(r);
/*		mpz_clear(min_r);
		mpz_clear(max_r);	*/
	}


/*	/ Step 4: Computing the solution. /
	mpz_invmod(&s0_i, s0, n);
	mpz_mul(m, s0_i, a);*/

	rsa_encrypt(&s_e, a, n, e);
	if (0 == mpz_cmp(s_e, c))
		printf("[DEBUG] m :  %s\n", mpz_get_str(NULL, 16, a));
	else 
	{
		mpz_clear(s_e);
		rsa_encrypt(&s_e, b, n, e);
		if (0 == mpz_cmp(s_e, c))
			printf("[DEBUG] m :  %s\n", mpz_get_str(NULL, 16, b));
		else
			printf("[DEBUG] Error\n");
	}
	mpz_clear(s_e);


	server_cleanup();
	mpz_clear(c);
	mpz_clear(n);
	mpz_clear(e);
	mpz_clear(m);
	mpz_clear(s0);
	mpz_clear(s0_i);

	return 0x00;
}