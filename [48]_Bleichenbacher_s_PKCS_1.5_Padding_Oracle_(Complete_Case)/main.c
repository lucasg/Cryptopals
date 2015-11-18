#include "hex.h"
#include "server.h"
#include "rsa_utils.h"	
#include "pkcs1_v1.5.h"
#include "bleichenbacher98.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


const static char secret_plaintext[] = "Let's kick it !";

/*
 * Print the secret data encoded in the plaintext "number" computed
 */
int print_secret_msg(const mpz_t m)
{
	char *msg, *msg_cpy, pmsg[SERVER_RSA_BLOCK_LEN], *hex_decrypted, *phex_decrypted;
	size_t i, msg_len, hex_dec_len;

	hex_decrypted = mpz_get_str(NULL, 16, m);
	hex_dec_len = strlen(hex_decrypted);

	printf("[DEBUG] hex_decrypted :  %s\n", hex_decrypted);
	
	/* Hex padding */
	if (hex_dec_len % 2)
	{
	/*
	 * In the case where the resulting hex string length is odd (GMP strip every 0-leading digits)
	 * we need to pad it in order to decode it correctly. Since mpz_get_str() return a 
	 * NULL-terminated string, we use to terminator to pad our value to the right.
	 *
	 *  Think : hex_array = \x00 + hex_array
	 */
	 	phex_decrypted  = malloc((1 + hex_dec_len)*sizeof(char));
		if (NULL == phex_decrypted)
		{
			free(hex_decrypted);
			return -1;
		} 	

		phex_decrypted[0] = 0x00;
		memcpy(phex_decrypted + 1, hex_decrypted, hex_dec_len*sizeof(char));
		free(hex_decrypted);

		hex_dec_len +=1;
	}	
	else
	{
		phex_decrypted = hex_decrypted;
	}

	/* Hex decoding */
	msg_len = hex_dec_len/2;
	msg = malloc(1 + msg_len*sizeof(char));
	if (NULL == msg)
	{
		free(phex_decrypted);
		return -1;
	}

	memset(msg, 0, msg_len);
	hex_decode(msg, phex_decrypted, 2*msg_len);
	msg[msg_len] = 0;


	/* Right-align the input message to retrieve any leading zeroes */
	memset(pmsg, 0, SERVER_RSA_BLOCK_LEN);
	memcpy(pmsg + (SERVER_RSA_BLOCK_LEN - msg_len), msg, msg_len);

	// printf("[DEBUG] m :  ");
	// for (i = 0; i < SERVER_RSA_BLOCK_LEN; i++)
	// 	printf("%02x:", (unsigned char) pmsg[i]);
	// printf("\n");

	/* Strip padding and print message */
	msg_cpy = msg;
	pkcs1_v1_5_msg_strip(&msg, &msg_len, pmsg, SERVER_RSA_BLOCK_LEN);

	printf("secret_msg :  ");
	for (i = 0; i < msg_len; i++)
		printf("%c",  msg[i]);
	printf("\n");

	free(phex_decrypted);
	free(msg_cpy);
	return 0x00;
}

int main (int argc, char *argv[])
{
	int pad_check;
	size_t dig, iteration;
	mpz_t n, e, c, cc, diff;

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


	if (-1 == b98_init(&b98, SERVER_RSA_BLOCK_LEN, c, e, n, &server_check_padding))
	{
		printf("Error while allocating resources for b98\n");
		goto cleanup;
	}

	printf("(min_range : %s)\n", mpz_get_str(NULL, 16, b98.min_range));
	printf("(max_range : %s)\n", mpz_get_str(NULL, 16, b98.max_range));
	

	printf("Initial search\n");
	/* Step 2.a : Starting the search. */
	if (0 == b98_initial_search(&b98))
	{
		printf("Did not found a single solution.\n");
		goto cleanup;
	}
	printf("\n");

	printf("(new solution found : %s)\n", mpz_get_str(NULL, 16, b98.s));
	printf("(min_range : %s)\n", mpz_get_str(NULL, 16, b98.min_range));
	printf("(max_range : %s)\n", mpz_get_str(NULL, 16, b98.max_range));
	

	printf("Update boundaries\n");
	/* Step 3: Narrowing the set of solutions. */
	b98_update_boundaries(&b98);
	
	iteration = 1;
	while (0x00 < mpz_cmp(b98.sets.b, b98.sets.a))
	{
		printf("(interval count : %ld)\n", b98.sets.sets.size);
		//printf("(a : %s)\n", mpz_get_str(NULL, 16, b98.sets.a));
		//printf("(b : %s)\n", mpz_get_str(NULL, 16, b98.sets.b));
		
		mpz_init_set(diff, b98.sets.b);
		mpz_sub(diff, diff,  b98.sets.a);
		if (0 == mpz_cmp_ui(diff, 1)) /* we found the solution. range [a, a+1] */
			break;

		printf("Range digits (iter : %04d) : ", (int) iteration);
		for (dig  = 0; dig < mpz_sizeinbase (diff, 10); dig++)
			printf("#");
		printf("\n");

		mpz_clear(diff);

		/* Step 2.c: Searching . */
		if (1 == b98.sets.sets.size)
			pad_check = b98_search_single_range(&b98);
		else
			pad_check = b98_search_multiple_range(&b98);

		if (pad_check)
		{
			/* solution found */
			iteration++;
			printf("(new solution found : %s)\n", mpz_get_str(NULL, 16, b98.s));	

			/*printf("[DEBUG] s : %s \n", mpz_get_str(NULL, 16, s));
		  	  printf("[DEBUG] r : %s\n", mpz_get_str(NULL, 16, r));*/

			/* Step 3: Narrowing the set of solutions. */
			b98_update_boundaries(&b98);	
			//printf("(interval count : %ld)\n", b98.sets.sets.size);	
		}
		else
		{
			printf("Wrong search space : [%s,%s] \n",  mpz_get_str(NULL, 16, b98.sets.a),  mpz_get_str(NULL, 16, b98.sets.b));
			goto cleanup;
		}
	}

	/* 
	 * Step 4: Computing the solution. 
	 * Usually, the resulting range is the following one : [a, a+1].
	 * Since both can validate the padding, we discriminate the real plaintext number by 
	 * "encrypting" it and compare it to the original ciphertext given by the server.
	 */
	rsa_encrypt(&cc, b98.sets.a, n, e);
	if (0 == mpz_cmp(cc, c))
	{
		print_secret_msg(b98.sets.a);
	}
	else 
	{
		mpz_clear(cc);
		rsa_encrypt(&cc, b98.sets.b, n, e);
		if (0 == mpz_cmp(cc, c))
			print_secret_msg(b98.sets.b);
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


	return 0x00;
}