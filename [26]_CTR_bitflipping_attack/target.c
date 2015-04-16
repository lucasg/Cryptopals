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
static uint64_t rnonce = 0;

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

	rnonce = 0;
	for (i=0; i<4; i++)
		rnonce |= rand() << 8*i;

}


/*
 * 'Clean' the input. In reality we truncate the part after the
 *  forbidden chars.
 */
int sanitize_input(const char *input, unsigned int input_len)
{
	unsigned int i = 0;

	while (i < input_len && i != ';' && i != '=')
		i++;

	return i; 
}

/*
 * Encrypt the arbitrary input string under AES-CTR
 */
int encrypt(unsigned char **output, const char *input, unsigned int input_len)
{
	size_t len, s_input_len;
	unsigned char *tmp;

	if (!rkey_init)
	{
		generate_rkey_and_iv();
		rkey_init = 1;	
	}

	s_input_len = sanitize_input(input, input_len);
	len = aes_128_get_padded_length(strlen(pre_str) + s_input_len + strlen(post_str), CTR);
	
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

	aes_128_encrypt_msg(*output, (unsigned char*) tmp, strlen(pre_str) + s_input_len + strlen(post_str), rkey, CTR, (union aes_128_init*) &rnonce);

	free(tmp);

	return len;
}


/*
 *
 */
void decrypt(const unsigned char *cipher, unsigned int cipher_len)
{
	unsigned char *tmp;

	if (!rkey_init)
		return;

	tmp = malloc((cipher_len + 1)*sizeof(unsigned char));
	if (NULL==tmp)
		return;

	aes_128_decrypt_msg(tmp, cipher, cipher_len, rkey, CTR, (union aes_128_init*) &rnonce);
	tmp[cipher_len] = 0;

#ifdef DEBUG
	printf("DEBUG : decryption ");
	write(1, tmp, cipher_len);
	printf("\n");
#endif /* DEBUG */	

	if(strstr((char*) tmp,  "admin=true") != NULL)
		printf("Admin account found\n");
	else
		printf("Regular account found\n");

	
	free(tmp);
}