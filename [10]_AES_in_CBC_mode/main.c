#include "../tools/aes_128/aes_128.h"
#include "../tools/b64.h"
#include "../tools/xor.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


static const unsigned char iv[16] = {0};
static const unsigned char secret_key[] = "YELLOW SUBMARINE";


int main (int argc, char *argv[])
{
	unsigned char b64_block[64] = {0},
				edat[48]= {0},
				prev_state[16]= {0},
				ddat[48] = {0};


    memcpy(prev_state, iv, sizeof(prev_state));

	while (read(0, b64_block , 64))
	{
		memset(edat, 0, sizeof(edat) );
		memset(ddat, 0, sizeof(ddat) );
		
		b64_decode((char*) edat, (char*) b64_block, 64);
		aes_128_decrypt_msg(ddat, edat, 48, secret_key, CBC, (const union aes_128_init *) prev_state);
		

		memcpy(prev_state, edat + 32, sizeof(prev_state));
		write(1, ddat, 48);
	}

	return 0;
}