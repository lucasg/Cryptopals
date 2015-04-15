#include "target.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

int main (int argc, char *argv[])
{
	size_t cipher1_len, cipher2_len;
	unsigned char *cipher1, *cipher2, *ccp;

	cipher1_len = encrypt(&cipher1, "AAAA", 4);
	if (NULL == cipher1 || 0 == cipher1_len)
		return 0x01;

	cipher2_len = encrypt(&cipher2, "BBBBBBBBBBadmin", 15);
	if (NULL == cipher2 || 16 > cipher2_len)
		return 0x01;

	ccp = malloc(cipher2_len*sizeof(char));
	if (NULL == ccp)
		return 0x01;
	
	memcpy(ccp, cipher1, 16);
	memcpy(ccp + 16 , cipher2 + 16 , 16);
	if (32 < cipher2_len)
		memset(ccp + 32, 0, cipher2_len - 32 );

	decrypt(ccp, cipher2_len);

	free(cipher1);
	free(cipher2);
	free(ccp);
	return 0x00;
}

