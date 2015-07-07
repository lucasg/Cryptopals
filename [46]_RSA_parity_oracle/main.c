#include "b64.h"
#include "hex.h"
#include "rsa_utils.h"
#include "server.h"
#include <string.h>
#include <stdio.h>

#define NO_NEW_LINEFEED (0)
#define NEW_LINEFEED (1)
#define BITLEN_MIN (1024)

const char *b64secret = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";


int print_secret_message(const mpz_t num, const mpz_t deno, const mpz_t n, unsigned int new_linefeed)
{
	size_t secret_len;
	char *hex_d_secret,*d_secret;
	mpz_t secret_num;

	mpz_init_set(secret_num, n);
	mpz_mul(secret_num, secret_num, num);
	mpz_tdiv_q (secret_num, secret_num, deno);


	hex_d_secret = mpz_get_str(NULL, 16, secret_num);
	secret_len = strlen(hex_d_secret) / 2;

	//printf("secret_num %s \n", hex_d_secret);
	d_secret = malloc(1 + secret_len*sizeof(char));
	if (NULL == d_secret)
	{
		return 0x01;
	}

	hex_decode(d_secret, hex_d_secret, strlen(hex_d_secret));
	d_secret[secret_len] = 0;
	printf("\rsecret msg : %s", d_secret);

	if (new_linefeed)
		printf("\n");

	mpz_clear(secret_num);
	free(hex_d_secret);
	free(d_secret);

	return 0x00;
}

int main (int argc, char *argv[])
{
	mpz_t n, e, c, modulo, deno, numer;
	mpz_t multiplifier, tmp, m;
	char *secret;
	size_t secret_len = b64_get_ascii_wc(strlen(b64secret));

	secret = malloc( 1 + secret_len*sizeof(char));	
	if (NULL == secret)
		return 0x01;

	b64_decode(secret, b64secret, strlen(b64secret));
	secret[secret_len] = 0x00;

	if (server_init(&e, &n))
	{
		free(secret);
		return 0x01;
	}

	if (server_encrypt_msg(&c, secret, secret_len))
	{
		free(secret);
		mpz_clear(e);
		mpz_clear(n);
		server_cleanup();
		return 0x01;
	}
	

	/*
	 *  Binary search : we test wether 2*m > n by looking at the resulting decoded number parity.
	 *  n is prime so it must be odd (or equal to 2), so the resulting parity tells us if the 
	 *  input number has wrapped up the modulo.
	 *	 	- if 2m < n, then we test if 4*m < n.
	 *		- if 2m >= n, the we test if 4*m > 3*n
	 *
	 *  We repeat the previous steps until the search space is completely exhausted (log2(n) times).
	 */
	mpz_init_set_ui(deno, 2);
	mpz_init_set_ui(numer, 1);
	while(mpz_cmp(deno, n) < 0)
	{
		//printf("fraction : %s/%s\n", mpz_get_str(NULL, 0, numer), mpz_get_str(NULL, 0, deno) );

		mpz_init(modulo);
		mpz_mul(modulo, n, numer );

		// mult = 2**num**e [n]	;
		mpz_init_set(multiplifier, deno);
		mpz_powm(multiplifier, multiplifier, e, n);

		mpz_init(tmp);
		mpz_mul(tmp, c, multiplifier);
		mpz_mod(tmp, tmp, modulo);
		
		server_decrypt_msg(&m, tmp);
		print_secret_message(numer, deno, n, NO_NEW_LINEFEED);


		if(mpz_tstbit(m,0))
		{
			//num = 2*num + 1;
			mpz_mul_ui(numer, numer, 2);
			mpz_add_ui(numer, numer, 1);
		}
		else
		{
			//num = 2*num - 1;
			mpz_mul_ui(numer, numer, 2);
			mpz_sub_ui(numer, numer, 1);
		}
		mpz_mul_ui(deno, deno, 2);

		mpz_clear(modulo);
		mpz_clear(multiplifier);
		mpz_clear(tmp);
		mpz_clear(m);
	}

	printf("\n-----------------------------------------\n");
	print_secret_message(numer, deno, n, NEW_LINEFEED);

	free(secret);
	mpz_clear(c);
	mpz_clear(e);
	mpz_clear(n);
	mpz_clear(numer);
	mpz_clear(deno);
	server_cleanup();
	return 0x00;
}