#include "../tools/aes_128/aes_128.h"
#include "../tools/hex.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>


static const unsigned char secret_key[] = "YELLOW SUBMARINE";


int main (int argc, char *argv[])
{
	
	unsigned int i = 0, j = 0, k = 0;
	unsigned char hex_line[32*10 + 2] = {0};
	unsigned char buf[16*10 + 1] = {0}, aes_buf[16*10 + 1] = {0};
	

	unsigned int scores[205] = {0};

	FILE *hexf_fd = fopen("8.txt", "r");


	for (i = 0; i < 204; i++)
	{
		 

		fgets((char*) hex_line, 32*10 + 1, hexf_fd);
		fgetc(hexf_fd);


		for(j = 0; j < 320; j+=32)
			for(k = j; k < 320; k+=32)
				scores[i] += ((k != j) && 0 == strncmp( (char*) hex_line + j, (char*) hex_line + k, 32));
		
		if (scores[i])
		{
			printf("%d : score %u \n", i, scores[i]);
			printf("%d : hex   %s \n", i, hex_line);

			for(j = 0; j < 160; j+=16)
			{
				hex_decode((char*) buf + j, (char*) hex_line + 2*j, 2*j);
				aes_128_decrypt(aes_buf + j, buf + j, secret_key);
			}

			printf("%d : aes   %s \n", i, aes_buf);

		}

	}

	return 0;
}