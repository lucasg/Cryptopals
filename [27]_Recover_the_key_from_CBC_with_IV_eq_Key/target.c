#include "target.h"
#include "aes_128/aes_128.h"
#include "pkcs7.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

static int rkey_init = 0x00;
static unsigned char rkey[16] = {0};

static const char pre_str[] = "comment1=cooking%20MCs;userdata=";
static const char post_str[] = ";comment2=%20like%20a%20pound%20of%20bacon";

/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_rkey_and_iv()
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) rkey)[i] = rand();
}

/*
 * Check if the recovered 'key' using the decrypted plaintext 
 * is really the secret one.
 */
int check_recovered_key(const unsigned char *key_candidate)
{
	return 0 == strncmp((char*) key_candidate, (char*) rkey, 16);
}

/*
 * 'Clean' the input. In reality we truncate the part after the
 *  forbidden chars.
 */
int sanitize_input(const char *input, unsigned int input_len)
{
	unsigned int i = 0;

	while (i < input_len && input[i] != ';' && input[i] != '=')
		i++;

	return i; 
}


/*
 *  Check for ASCII compliance (every char between 0x00 and 0x7f)
 */
int check_ascii_compliance(const char *input, unsigned int input_len)
{
	unsigned int i = 0;

	while (i < input_len && !(input[i] & 0x80))
		i++;

	return i == input_len; 
}


/*
 * Encrypt the arbitrary input string under AES-CBC
 */
int encrypt(unsigned char **output, const char *input, unsigned int input_len)
{
	unsigned int len, s_input_len;
	unsigned char *tmp;

	if (!rkey_init)
	{
		generate_rkey_and_iv();
		rkey_init = 1;	
	}

	s_input_len = sanitize_input(input, input_len);
	len = strlen(pre_str) + s_input_len + strlen(post_str);
	if (len % aes_128_block_len)
		len += (aes_128_block_len - (len % aes_128_block_len));

	*output = malloc(len*sizeof(char));
	if (NULL == output)
		return 0x00;

	tmp = malloc(len*sizeof(char));
	if (NULL == tmp)
		return 0x00;

	memset(tmp, 0, len*sizeof(char));
	memset(*output, 0, len*sizeof(char));

	memcpy(tmp,  pre_str, strlen(pre_str)*sizeof(*pre_str));
	memcpy(tmp + strlen(pre_str)*sizeof(*pre_str), input , s_input_len*sizeof(*input));
	memcpy(tmp + strlen(pre_str)*sizeof(*pre_str) + s_input_len*sizeof(*input), post_str , strlen(post_str)*sizeof(*post_str));

	aes_128_encrypt_msg(*output, (unsigned char*) tmp, strlen(pre_str) + s_input_len + strlen(post_str), rkey, CBC, (union aes_128_init*) rkey);

	free(tmp);

	return len;
}


/*
 *
 */
unsigned char *decrypt(const unsigned char *cipher, unsigned int cipher_len)
{
	unsigned char *tmp;

	if (!rkey_init)
		return NULL;

	tmp = malloc((cipher_len + 1)*sizeof(unsigned char));
	if (NULL==tmp)
		return NULL;

	aes_128_decrypt_msg(tmp, cipher, cipher_len, rkey, CBC, (union aes_128_init*) rkey);
	tmp[cipher_len] = 0;

#ifdef DEBUG
	if (pkcs7_validate(tmp, cipher_len))
	{
		tmp[pkcs7_strip(tmp, cipher_len)] = 0x00;
		printf("DEBUG : decryption %s\n", tmp);
	}
	else
	{
		printf("DEBUG : decryption ");
		write(1, tmp, cipher_len);
		printf("\n");
	}

#endif /* DEBUG */	

	if (!check_ascii_compliance((char*) tmp, cipher_len))
	{
		printf("Error found in the plaintext data : ");
		write(1, tmp, cipher_len);
		printf("\n");

		return tmp;
	}
	else
	{
		if(strstr((char*) tmp,  "admin=true") != NULL)
			printf("Admin account found\n");
		else
			printf("Regular account found\n");
	}
	
	free(tmp);
	return NULL;
}