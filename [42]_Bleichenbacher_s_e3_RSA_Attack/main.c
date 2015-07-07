#include "rsa_utils.h"
#include "client.h"
#include "server.h"
#include "rsa_sign_constants.h"
#include <string.h>
#include <stdio.h>


/*
 * Forged message : 'hi mom !' + 0x00 0x01 0xff 0x00 'sha1' + sha1('hi mom !') + filler with '0x80'
 * The filler part is here to help finding a perfect root-cube number which will have the same string as the message we want to forge.
 * I abused the validator since I know it will look for the last null byte and check the sha-buffer after, regardless of the string size.
 * The fe filler can also be inserted after the 0x01 0x0ff, but it is more complicated to convert back-and-forth to number that way.
 */
static char forged_msg[] = "6869206d6f6d20210001ff007368613199ed8c2f4b3000293d1823f1a493b6a1dc17d55d80808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808008080808080808080808080808080808080808080808080";
		


int main (int argc, char *argv[])
{
	int res_sig_greater;
	mpz_t n, e, d, s, f_msg, f_sig, valid_f_sig;

	if (rsa_gen_key(&n, &e, &d, RSA_SIGN_BLOCK_LEN))
	{
		printf("Error while generating RSA keys\n");
		return -1;
	}


	
	if (client_init(d, n))
	{
		printf("Error while initializing client\n");
		return -1;	
	}

	if (server_init(e, n))
	{
		printf("Error while initializing server\n");
		return -1;	
	}
 
	/*  
	 *  Unit-testing the whole signing and validating process
	 */
	printf("Testing server-side signature with a correctly built RSA sig : ");
	if (client_sign_msg(&s, "hi mom !", 8, SHA1))
	{
		printf("Error while signing a message\n");
		return -1;	
	}


	switch(server_validate_signature(s))
	{
		case 0:
			printf("RSA signature invalid\n");
			break;

		case 1:
			printf("RSA signature valid\n");
			break;

		default:
			printf("Error while validating a signature\n");
			return -1;

	}


	/* 
	 *  Forging our RSA signature : with e=3, some numbers don't wrap the modulo when cubed.
	 *  The whole priv/pubkey is bypassed. Since GMP root cube has a tendency to round the 
	 *  result to the floor, we need to increment it until we get back the exact string (we need 72 
	 *  exact leading chars at least for sha1) when cubed.
	 */
	mpz_init_set_str(f_msg, forged_msg , 16);
	mpz_init(f_sig);
	mpz_root(f_sig, f_msg, 3); 

	res_sig_greater = 0x00;
	while (!res_sig_greater)
	{
		mpz_init(valid_f_sig);
		mpz_powm_ui(valid_f_sig, f_sig, 3, n);

		res_sig_greater = mpz_cmp(valid_f_sig, f_msg) >= 0;

		
		if (!res_sig_greater)
			mpz_add_ui(f_sig, f_sig, 1);

		mpz_clear(valid_f_sig);
	}
	
	printf("Testing server-side signature with a fake RSA certificate : ");
	switch(server_validate_signature(f_sig))
	{
		case 0:
			printf("RSA signature invalid\n");
			break;

		case 1:
			printf("RSA signature valid\n");
			break;

		default:
			printf("Error while validating a signature\n");
			return -1;

	}




	mpz_clear(s);
	server_cleanup();
	client_cleanup();
	mpz_clear(n);
	mpz_clear(e);
	mpz_clear(d);

	return 0x00;
}