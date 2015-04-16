#include "edit_target.h"
#include "decrypt_msg.h"
#include "aes_128/aes_128.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>


/*
 *	Generate a random sequence of data. Not secure at all.
 */
void generate_rseq(unsigned char array[] )
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((unsigned int*)array)[i]  = rand();
}


static unsigned char r_key[16];
static union aes_128_init r_nonce;



unsigned int init_edit_target(const char ctext_filename[], const char secret_key[], unsigned char **ciphertext, size_t *ciphertext_len)
{
	unsigned char *msg;
	size_t msg_len;

	generate_rseq(r_nonce.iv);
	generate_rseq(r_key);


	// AES-ECB decryption
	if (decrypt_msg(ctext_filename, secret_key, &msg, &msg_len))
		return 0x01;

	*ciphertext_len = aes_128_get_padded_length(msg_len, CTR);
	*ciphertext = malloc(*ciphertext_len*sizeof(size_t));
	if( NULL == *ciphertext)
	{
		free(msg);
		return 0x01;
	}


	*ciphertext_len = aes_128_encrypt_msg(*ciphertext, msg, msg_len, r_key, CTR, &r_nonce);

	free(msg);
	return 0x00;
}


/*
 *
 */
unsigned int edit_ciphertext(unsigned char *ciphertext, const size_t ciphertext_len, const size_t offset, const char *newtext, const size_t newtext_len)
{
	unsigned char *tmp;

	if (offset + newtext_len > ciphertext_len)
		return 0x01;

	tmp = malloc((offset + newtext_len)*sizeof(size_t));
	if (NULL == tmp)
		return 0x01;

	/*
	 * It could be way faster to generate the correct keystream at the offset position
	 * instead of simply decrypt everything before and re-encrypt then. Well, I'm lazy ...
	 */
	aes_128_decrypt_msg(tmp, ciphertext, offset + newtext_len, r_key, CTR, &r_nonce);
	memcpy(tmp + offset, newtext, newtext_len*sizeof(size_t));

	aes_128_encrypt_msg(ciphertext, tmp, offset + newtext_len, r_key, CTR, &r_nonce);

	free(tmp);

	return 0x00;
}
