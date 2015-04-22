#include "target.h"
#include "xor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 * A dummy encryption payload only useful to get the
 * secret payload following our userdata.
 */
static const char bogus_payload[] = "AAAABBBBCCCCDDDD";
static const char admin_payload[] = ";admin=true;";


int main (int argc, char *argv[])
{
	size_t i, clen;
	unsigned char *cipher;


	clen = encrypt(&cipher, bogus_payload, strlen(bogus_payload));
	if (NULL == cipher || 0 == clen)
		return 0x01;

	
	for (i = 1; i < strlen(admin_payload); i++)
		(cipher + 32)[i] ^= bogus_payload[i] ^ admin_payload[i]; 

	decrypt(cipher, clen);

	free(cipher);
	return 0x00;
}