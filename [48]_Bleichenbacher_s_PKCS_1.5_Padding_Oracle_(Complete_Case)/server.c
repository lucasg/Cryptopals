#include "server.h"
#include "rsa_utils.h"
#include "pkcs1_v1.5.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


static mpz_t pubkey, privkey, n;

/*
 * Server initialization using public key and modulo
 */
int server_init(mpz_t e,  mpz_t modulo)
{
	mpz_t B, two, B_exp;

	
	mpz_init_set_ui(B, 0);
	mpz_init_set_ui(two, 2);
	mpz_init_set_ui(B_exp, 8*(SERVER_RSA_BLOCK_LEN - 2));
	
	mpz_init_set_ui(n,0);
	mpz_init_set_ui(pubkey,0);
	mpz_init_set_ui(privkey,0);

	/* We need to generate a n bigger than 3B -1 in order to be able to 
	   encrypt message using PKCS#1 v1.5 */
	while (mpz_cmp(n, B) <= 0)
	{
		mpz_clear(n);
		mpz_clear(pubkey);
		mpz_clear(privkey);

		if (rsa_gen_key(&n, &pubkey, &privkey,  SERVER_RSA_BITSIZE ))
			return -1;

		/* B = 2**(8*(k-2)) */
		mpz_powm(B, two, B_exp, n);
		mpz_mul_ui(B, B, 3);
		mpz_sub_ui(B, B, 1);
	}

	mpz_init_set(e, pubkey);
	mpz_init_set(modulo, n);
	
	mpz_clear(B);
	mpz_clear(two);
	mpz_clear(B_exp);

	return 0x00;
}


/* 
 *  Encrypt a new message, using pkcs#14 v1.5 padding and the server's secret key.
 */
int server_encrypt_msg(mpz_t *ciphertext, const char *plaintext, const size_t ptext_len)
{
	char p_msg[SERVER_RSA_BLOCK_LEN];

	if (pkcs1_v1_5_generate((unsigned char*) p_msg, (unsigned char*)  plaintext, ptext_len, SERVER_RSA_BLOCK_LEN, pkcs1_msg, SHA1))
		return -1;

	if (rsa_encrypt_msg(ciphertext, n, pubkey, p_msg, SERVER_RSA_BLOCK_LEN))
		return -1;


	return 0x00;
}	


/*
 * Test whether the input number is a valid RSA signature .
 */
int server_check_padding(const mpz_t ciphertext)
{
	char *msg, pmsg[SERVER_RSA_BLOCK_LEN];
	size_t msg_len;
	int valid_block_type;

	if (rsa_decrypt_msg(&msg, &msg_len, ciphertext, privkey, n))
		return -1;

	/* Right-align the input message to retrieve any leading zeroes */
	memset(pmsg, 0, SERVER_RSA_BLOCK_LEN);
	memcpy(pmsg + (SERVER_RSA_BLOCK_LEN - msg_len), msg, msg_len);

	valid_block_type = (0x00 == pmsg[0]) && (0x02 == pmsg[1]); 
	
	free(msg);
	return valid_block_type;
}


/*
 * Free any allocated resources
 */
int server_cleanup()
{
	mpz_clear(privkey);
	mpz_clear(pubkey);
	mpz_clear(n);

	return 0x00;	
}