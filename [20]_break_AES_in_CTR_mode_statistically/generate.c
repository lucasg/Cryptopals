#include "generate.h"
#include "constants.h"
#include "plaintexts.h"
#include "../tools/b64.h"
#include "../tools/aes_128/aes_128.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 *  Random key and IV.
 *  Init once per session
 */ 
static unsigned char rkey[16] = {0};
static uint64_t nonce = 0;


/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_rkey()
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) rkey)[i] = rand();
}

/*
 * Encrypt an arbitrary input string under AES-CTR
 */
size_t encrypt(unsigned char **output, const unsigned char *input, size_t input_len)
{
	unsigned char *tmp;
	size_t output_len , b64_decoded_len;

	output_len = b64_get_ascii_wc(input_len);

	tmp = malloc((output_len)*sizeof(char));
	if (NULL == tmp)
		return 0x00;

	
	*output = malloc((output_len)*sizeof(char));
	if (NULL == *output)
	{
		free(tmp);
		return 0x00;
	}

	memset(tmp, 0, (output_len)*sizeof(char));
	memset(*output, 0, (output_len)*sizeof(char));

	b64_decoded_len = b64_decode((char*)tmp, (char*)input, input_len);
	output_len = aes_128_encrypt_msg(*output, tmp, b64_decoded_len, rkey, CTR, (const union aes_128_init*) &nonce);

	free(tmp);

	return output_len;
}

char *get_ctext_file_path(size_t i)
{
	char *output;
	size_t output_len;

	//					ciphertext_folder    /  XX 
	output_len = strlen(ciphertext_folder) + 2 + 2;

	output = malloc((output_len + 1)*sizeof(char));
	if (NULL == output)
		return NULL;
	 

	snprintf(output, output_len, "%s/%02d", ciphertext_folder, i);
	output[output_len] = 0x01;

	return output;
}

int generate_ciphertexts()
{
	size_t i, ctext_len;
	unsigned char *ctext; 
	char *ctext_fp;
	FILE *fd;

	i = 0;
	while (NULL != plaintexts[i])
	{
		printf("Encrypting plaintext n.%02d\n", (int) i);
		ctext_len = encrypt(&ctext, (unsigned char *) plaintexts[i], strlen(plaintexts[i]));
		if (!ctext_len)
			return 0x01;

		ctext_fp = get_ctext_file_path(i);
		if (NULL == ctext_fp)
			return 0x02;

		fd = fopen(ctext_fp, "wb");
		if (NULL == fd)
			return 0x03;

		fwrite(ctext, sizeof(char), ctext_len, fd);

		fclose(fd);
		free(ctext_fp);
		free(ctext);

		i++;
	}

	return 0x00;
}