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
static const char bogus_payload[] = "AAAABBBBCCCCDDDD";

/*
 *	We have to know what is appended to the userdata in order
 *  to tamper it correctly, since CBC xor the previous block with the current one after AES encryption.
 */
static const char suffix_payload[] = ";comment2=%20like%20a%20pound%20of%20bacon";
static const char admin_payload[] = ";admin=true;";


int main (int argc, char *argv[])
{
	size_t i, clen;
	unsigned char *cipher;


	clen = encrypt(&cipher, bogus_payload, strlen(bogus_payload));
	if (NULL == cipher || 0 == clen)
		return 0x01;

	
	for (i = 1; i < strlen(admin_payload); i++)
		(cipher + 32)[i] ^= suffix_payload[i] ^ admin_payload[i];

	decrypt(cipher, clen);

	free(cipher);
	return 0x00;
}