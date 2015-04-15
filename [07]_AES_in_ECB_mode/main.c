#include "../tools/aes_128/aes_128.h"
#include "../tools/b64.h"
#include "../tools/pkcs7.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>



static const unsigned char secret_key[] = "YELLOW SUBMARINE";


int main (int argc, char *argv[])
{
	//unsigned int i = 0;
	unsigned char b64_block[64] = {0}, aes_block[48]= {0}, decoded_block[48] = {0};

	while (read(0, b64_block , 64))
	{
		memset(aes_block, 0, sizeof(aes_block) );
		memset(decoded_block, 0, sizeof(decoded_block) );


		b64_decode((char*) aes_block, (char*) b64_block, 64);

		aes_128_decrypt_msg(decoded_block, aes_block, 48, secret_key, ECB, NULL);
	

		write(1, decoded_block, pkcs7_strip(decoded_block, 48));
		
	}

	return 0;
}