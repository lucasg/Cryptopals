#include "target.h"
#include "../tools/aes_128/aes_128.h"
#include "../tools/pkcs7.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>


/*
 *  Random key and IV.
 *  Init once per session
 */ 
static int rkey_init = 0x00;
static unsigned char rkey[16] = {0};
static unsigned char riv[16] = {0};
static char* sel_input;

/*
 *  Randomly chosen plaintext.
 *  Simulate a server-side cookie.
 */ 
const static char* const rplaintext[] = {
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};


/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_rkey_and_iv()
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) rkey)[i] = rand();

	for (i=0; i<4; i++)
		((int*) riv)[i] = rand();

}


/*
 * Encrypt the arbitrary input string under AES-CBC
 */
size_t encrypt(unsigned char **output)
{
	size_t output_len, pidx;
	

	// One-Time key&iv generation
	if (!rkey_init)
	{
		generate_rkey_and_iv();
		rkey_init = 1;	
	}


	// Plaintext random selection
	pidx =  (rand() / (double)RAND_MAX * (10 - 1));
	sel_input = (char*) rplaintext[pidx];
	
	output_len = strlen(sel_input);
	if (output_len % aes_128_block_len)
		output_len += (aes_128_block_len - (output_len % aes_128_block_len));


	*output = malloc((output_len + sizeof(riv))*sizeof(char));
	if (NULL == output)
		return 0x00;


	// Encryption
	memcpy(*output , riv, sizeof(riv)*sizeof(char));
	aes_128_encrypt_msg(*output + sizeof(riv)*sizeof(char) , (unsigned char*) sel_input, strlen(sel_input), rkey, CBC, (const union aes_128_init*) riv);

	return output_len + sizeof(riv);
}


/*
 *
 */
int decrypt(const unsigned char *cipher, size_t cipher_len)
{
	unsigned char *tmp;
	int valid_padding;

	if (!rkey_init)
		return 0x00;

	tmp = malloc((cipher_len + 1)*sizeof(unsigned char));
	if (NULL==tmp)
		return 0x00;

	// Decryption
	aes_128_decrypt_msg(tmp, cipher, cipher_len, rkey, CBC, (const union aes_128_init*) riv);
	tmp[cipher_len] = 0;
	
	valid_padding = pkcs7_validate(tmp, cipher_len);

	free(tmp);

	return (0 != valid_padding);
}

int is_right_answer(const char *input)
{
	return !strncmp(sel_input, input, strlen(sel_input));
}