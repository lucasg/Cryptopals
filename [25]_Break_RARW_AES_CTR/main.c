#include "edit_target.h"
#include "aes_128/aes_128.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char manpage[] = "\n"
"Usage : \n"
"	bin/25 filename key \n"
"\n"
"	- filename : the path where is located the encrypted file\n"
"	- key : the AES-ECB used to decrypt the message\n"
"\n";

int main (int argc, char *argv[])
{
	unsigned char *ciphertext, *ciphertext_cpy;
	size_t ciphertext_len, i, blk_idx, blk_len;

	if (argc < 3)
	{
		printf("%s\n", manpage);
		return 0x01;
	}


	if (init_edit_target(argv[1], argv[2], &ciphertext, &ciphertext_len))
		return 0x01;


	ciphertext_cpy = malloc(ciphertext_len*sizeof(size_t));
	if (NULL == ciphertext_cpy)
	{
		free(ciphertext);
		return 0x01;
	}
	memcpy(ciphertext_cpy, ciphertext, ciphertext_len*sizeof(size_t));
	
	/* 
	 *  The edit function is vulnerable to chosen plaintext attacks : we can
	 *  retrieve the keystream, which is simply xor'ed against the known text, and
	 *  use it to decrypt the secret ciphertext.
	 */
	for (blk_idx = 0; blk_idx*aes_128_block_len < ciphertext_len; blk_idx++)
	{
		blk_len = aes_128_block_len;
		if (ciphertext_len - blk_idx*aes_128_block_len < aes_128_block_len)
			blk_len = ciphertext_len - blk_idx*aes_128_block_len;

		edit_ciphertext(ciphertext_cpy, ciphertext_len, blk_idx*aes_128_block_len , "AAAAAAAAAAAAAAAA", blk_len);

		for (i = 0; i < blk_len; i++)
			printf("%c", (ciphertext_cpy[i + blk_idx*aes_128_block_len] ^ 'A') ^ ciphertext[blk_idx*aes_128_block_len + i]);
	}
	printf("\n");

	free(ciphertext_cpy);
	free(ciphertext);
	return 0;
}