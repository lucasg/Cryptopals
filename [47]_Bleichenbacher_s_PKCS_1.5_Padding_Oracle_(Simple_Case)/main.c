#include "hex.h"
#include "server.h"
#include "rsa_utils.h"	
#include "pkcs1_v1.5.h"
#include "bleichenbacher98.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


const static char secret_plaintext[] = "Let's kick it !";

#define FRAC_ADD (0x0)
#define FRAC_SUB (0x1)

/*
 * Compute (ax +/- b)/d
 */
int compute_frac(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d, int sign)
{
	mpz_t num_tmp;

	mpz_init(num_tmp);
	mpz_mul(num_tmp, a, x);

	switch (sign)
	{
	case FRAC_ADD:
		mpz_add(num_tmp, num_tmp, b);
		break;
	case FRAC_SUB:
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
int compute_frac_add(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d)
{
	
	return compute_frac(result, a, x, b, d, FRAC_ADD);
}

/*
 * Compute (ax - b)/d
 */
int compute_frac_sub(mpz_t result, const mpz_t a, const mpz_t x, const mpz_t b, const mpz_t d)
{
	return compute_frac(result, a, x, b, d, FRAC_SUB);
}

/*
 *  Compute the minimal r value at Step 2.c (1) for s-search
 */
int compute_min_r(mpz_t *r, const mpz_t s_1, const mpz_t b, const  mpz_t min_range, const  mpz_t n )
{
	int frac_retcode;

	/*mpz_init(*r);*/
	frac_retcode = compute_frac_sub(*r, b, s_1, min_range, n);
	mpz_mul_ui(*r, *r, 2);

	return frac_retcode;
}

/*
 *  Compute the lower bound s value at Step 2.c (1) for s-search
 */
int compute_min_s(mpz_t *min_s, const mpz_t r_1, const mpz_t b, const mpz_t min_range, const mpz_t n )
{
	mpz_init(*min_s);
	return compute_frac_add(*min_s, r_1, n, min_range, b);
}


/*
 *   Compute the upper bound s value at Step 2.c (1) for s-search
 */
int compute_max_s(mpz_t *max_s, const mpz_t r_1, const mpz_t a, const mpz_t max_range, const mpz_t n )
{
	mpz_init(*max_s);
	return compute_frac_add(*max_s, r_1, n, max_range, a);
}

/* 
 *  Update the lower bound for plaintext candidates domain
 */
int update_a(mpz_t a, const mpz_t r, const mpz_t s, const mpz_t two_B,  const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	compute_frac_add(tmp, r, n, two_B, s);

	
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
int update_b(mpz_t b, const mpz_t r, const mpz_t s, const mpz_t two_B, const mpz_t three_B, const mpz_t n )
{
	mpz_t tmp;

	mpz_init(tmp);
	compute_frac_add(tmp, r, n, three_B, s);

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
 * Print the secret data encoded in the plaintext "number" computed
 */
int print_secret_msg(const mpz_t m)
{
	char *msg, pmsg[SERVER_RSA_BLOCK_LEN], *hex_decrypted;
	size_t i, msg_len, hex_dec_len;

	hex_decrypted = mpz_get_str(NULL, 16, m);
	hex_dec_len = strlen(hex_decrypted);

	/* Hex decryption */
	msg_len = hex_dec_len/2;
	if (hex_dec_len % 2)
	{
	/*
	 * In the case where the resulting hex string length is odd (GMP strip every 0-leading digits)
	 * we need to pad it in order to decode it correctly. Since mpz_get_str() return a 
	 * NULL-terminated string, we use to terminator to pad our value to the right.
	 */
	memcpy(hex_decrypted+1, hex_decrypted, hex_dec_len);
	hex_decrypted[0] = 0x00;
	msg_len++;
	}	


	msg = malloc(1 + msg_len*sizeof(char));
	if (NULL == msg)
	{
		free(hex_decrypted);
		return -1;
	}

	memset(msg, 0, msg_len);
	hex_decode(msg, hex_decrypted, 2*msg_len);
	msg[msg_len] = 0;


	/* Right-align the input message to retrieve any leading zeroes */
	memset(pmsg, 0, SERVER_RSA_BLOCK_LEN);
	memcpy(pmsg + (SERVER_RSA_BLOCK_LEN - msg_len), msg, msg_len);

	printf("[DEBUG] m :  ");
	for (i = 0; i < SERVER_RSA_BLOCK_LEN; i++)
		printf("%02x:", (unsigned char) pmsg[i]);
	printf("\n");

	/* Strip padding and print message */
	pkcs1_v1_5_msg_strip(&msg, &msg_len, pmsg, SERVER_RSA_BLOCK_LEN);

	printf("secret_msg :  ");
	for (i = 0; i < msg_len; i++)
		printf("%c",  msg[i]);
	printf("\n");

	free(hex_decrypted);
	free(msg);
	return 0x00;
}

int main (int argc, char *argv[])
{
	size_t dig;
	int pad_check, iteration;
	/*mpz_t min_r, max_r;*/
	mpz_t n, e, c, cc, /*s,*/ s0, diff, min_s, max_s;
	/*mpz_t a,b,  r;*/

	struct bleichenbacher_98_t b98;

	if (server_init(e, n))
	{
		printf("Error while initializing server\n");
		return -1;	
	}
	/*printf("[DEBUG] n : %s\n", mpz_get_str(NULL, 16, n));
	  printf("[DEBUG] e : %s\n", mpz_get_str(NULL, 16, e));*/
 
	/*  
	 *  Unit-testing the whole signing and validating process
	 */
	printf("Testing server-side encryption : ");
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


	b98_init(&b98, SERVER_RSA_BLOCK_LEN, c, e, n, &server_check_padding);

	/* Step 2.a : Starting the search. */
	b98_initial_search(&b98);
	mpz_init_set(s0, b98.s);


	/* Step 3: Narrowing the set of solutions. */
	b98_update_boundaries(&b98);

	
/*	printf("[DEBUG] min_r : %s\n", mpz_get_str(NULL, 16, b98.min_r));
	printf("[DEBUG] max_r : %s\n", mpz_get_str(NULL, 16, b98.max_r));*/

	
	iteration = 1;
	pad_check = 0x00;
	while (0x00 < mpz_cmp(b98.b, b98.a))
	{
/*		printf("(a : %s)\n", mpz_get_str(NULL, 16, b98.a));
		printf("(b : %s)\n", mpz_get_str(NULL, 16, b98.b));*/
		
		mpz_init_set(diff, b98.b);
		mpz_sub(diff, diff,  b98.a);
		if (0 == mpz_cmp_ui(diff, 1)) /* we found the solution. range [a, a+1] */
			break;

		printf("Range digits (iter : %04d) : ", iteration);
		for (dig  = 0; dig < mpz_sizeinbase (diff, 10); dig++)
			printf("#");
		printf("\n");

		mpz_clear(diff);

		/* Step 2.c: Searching with one interval left. */
		compute_min_r(&b98.r, b98.s, b98.b, b98.min_range, n);
		while (0x01 != pad_check && mpz_cmp(b98.r, b98.max_range) <= 0)
		{
			compute_min_s(&min_s, b98.r, b98.b, b98.min_range, n);
			compute_max_s(&max_s, b98.r, b98.a, b98.max_range, n);
			
			mpz_set(b98.s, min_s);
			while (mpz_cmp(b98.s, max_s) < 0 && 0x1 != pad_check)
			{
				mpz_add_ui(b98.s, b98.s, 1);
				/*mpz_set(b98.s, b98.s);*/
				pad_check = b98_check_padding(&b98);
			}

			/* solution found */
			if (pad_check)
			{
				iteration++;
				break;
			}

			mpz_add_ui(b98.r, b98.r, 1);
			mpz_clear(min_s);
			mpz_clear(max_s);
		}
		/*printf("[DEBUG] s : %s \n", mpz_get_str(NULL, 16, s));
		  printf("[DEBUG] r : %s\n", mpz_get_str(NULL, 16, r));*/

		if (pad_check)
		{
			/* Step 3: Narrowing the set of solutions. */
			b98_update_boundaries(&b98);		
		}
		else
		{
			printf("Wrong search space : [%s,%s] \n",  mpz_get_str(NULL, 16, b98.a),  mpz_get_str(NULL, 16, b98.b));
			goto cleanup;
		}

		pad_check = 0x00;
	}

	/* 
	 * Step 4: Computing the solution. 
	 * Usually, the resulting range is the following one : [a, a+1].
	 * Since both can validate the padding, we discriminate the real plaintext number by 
	 * "encrypting" it and compare it to the original ciphertext given by the server.
	 */
	rsa_encrypt(&cc, b98.a, n, e);
	if (0 == mpz_cmp(cc, c))
	{
		print_secret_msg(b98.a);
	}
	else 
	{
		mpz_clear(cc);
		rsa_encrypt(&cc, b98.b, n, e);
		if (0 == mpz_cmp(cc, c))
			print_secret_msg(b98.b);
		else
			printf("The secret message could not be found.\n");
	}
	mpz_clear(cc);

cleanup:
	b98_cleanup(&b98);
	server_cleanup();
	mpz_clear(c);
	mpz_clear(n);
	mpz_clear(e);
	mpz_clear(s0);


	return 0x00;
}