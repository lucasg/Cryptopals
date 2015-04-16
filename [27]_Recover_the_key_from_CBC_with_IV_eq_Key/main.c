#include "target.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "../tools/xor.h"

/*
 * A dummy encryption payload only useful to get the
 * secret payload following our userdata
 */
static const char bogus_payload[] = "AAAAAAAAAAAAAAAAbbbbbbbbbbbbbbbbCCCCCCCCCCCCCCCC";

/*
 *	We have to know what is appended to the userdata in order
 *  to tamper it correctly, since CBC xor the previous block with the current one after AES encryption.
 */
static const char suffix_payload[] = ";comment2=%20like%20a%20pound%20of%20bacon";
static const char admin_payload[] = ";admin=true;";


int main (int argc, char *argv[])
{
	size_t i, clen;
	unsigned char *cipher, *badly_formated_cipher, *ptext, recovered_key[16];


	clen = encrypt(&cipher, bogus_payload, strlen(bogus_payload));
	if (NULL == cipher || 0 == clen)
		return 0x01;

	badly_formated_cipher = malloc(clen*sizeof(char));
	if (NULL == badly_formated_cipher)
	{
		free(cipher);
		return 0x00;
	}

	memcpy(badly_formated_cipher, cipher, clen*sizeof(char));
	memset(badly_formated_cipher + 16, 0, 16*sizeof(char));
	memcpy(badly_formated_cipher + 32, cipher, 16*sizeof(char));
	
	ptext = decrypt(badly_formated_cipher, clen);
	if (NULL != ptext)
	{

		printf("Recovered key ");
		for (i = 0; i < 16; i++)
		{
			recovered_key[i] = ptext[i] ^ ptext[32 + i];
			printf(":%02x", recovered_key[i]);
		}
		printf("\n");
		printf("Correct key found : %d\n", check_recovered_key(recovered_key));
	}

	if (NULL != ptext)
		free(ptext);
	free(badly_formated_cipher);
	free(cipher);
	return 0x00;
}