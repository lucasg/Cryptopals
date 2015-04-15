#include "../tools/b64.h"
#include "../tools/xor.h"
#include "../tools/aes_128/aes_128.h"


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static const char b64_secret[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
static const char secret[] = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby I";



int main ( int argc, char *argv[] )
{
	uint64_t nonce = 0; 
	unsigned char *ascii_secret, *encoded, *decoded;
	size_t msg_len, msgbuf_len = b64_get_ascii_wc(strlen(b64_secret));

	ascii_secret = malloc((1+msgbuf_len)*sizeof(char));
	if (NULL == ascii_secret)
		return 0x1;

	decoded = malloc((1+msgbuf_len)*sizeof(char));
	if (NULL == decoded)
	{
		free(ascii_secret);
		return 0x1;
	}

	encoded = malloc((1+msgbuf_len)*sizeof(char));
	if (NULL == encoded)
	{
		free(decoded);
		free(ascii_secret);
		return 0x1;
	}
	
	memset(ascii_secret, 0, (1+msgbuf_len)*sizeof(char));
	memset(decoded, 0, (1+msgbuf_len)*sizeof(char));
	memset(encoded, 0, (1+msgbuf_len)*sizeof(char));

	/*
	 *  Challenge 18  decryption
	 */ 

	msg_len = b64_decode((char *) ascii_secret, (char *) b64_secret, strlen(b64_secret));
	printf("msg len : %d\n", msg_len );

	aes_128_decrypt_msg(decoded, ascii_secret, msg_len, (unsigned char*) "YELLOW SUBMARINE", CTR, (union aes_128_init*) &nonce );

	printf("Decoded string : %s\n", decoded );



	/*
	 *  Roundtrip Test
	 */ 

	srand (time (NULL));
	nonce = rand();

	aes_128_encrypt_msg( encoded , (unsigned char*) secret, msg_len, (unsigned char*) "YELLOW SUBMARINE", CTR, (union aes_128_init*) &nonce );
	aes_128_decrypt_msg( decoded , encoded, msg_len, (unsigned char*) "YELLOW SUBMARINE", CTR, (union aes_128_init*) &nonce );

	printf("RoundTrip test : %s\n", strncmp(secret, (char*)decoded, strlen(secret)*sizeof(char)) ? "KO" : "OK" );

	free(ascii_secret);
	free(decoded);
	free(encoded);

	return 0x00;
};