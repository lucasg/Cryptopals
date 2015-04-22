#include "sha1.h"
#include "sha1_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef WIN32
	#include <Winsock2.h>
#endif

static const char admin_key[] = ";admin=true";
static const char secret[] = "it's a secret";
static const char basic_oauth[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";



unsigned int test_sha1_sig(const uint8_t *command, const size_t command_len, const uint8_t *signature)
{
	uint8_t secret_sig[SHA1_HASH_LENGTH];
	
	sha1_utils_keyed_mac(secret_sig, (uint8_t*) secret, strlen(secret), (uint8_t*) command, command_len);
	return 0 == strncmp((char*) signature, (char*)  secret_sig, SHA1_HASH_LENGTH*sizeof(uint8_t));
}

#define SHA_BIG_ENDIAN
/*
 *  The liboauth sha1 is too intelligent : it detect the platform's endianess and
 *  return a coherent result, independant from endian. However it's much more simple
 *  to work in bitstream (i.e. big endian) when it's come to padding. Of course on a 
 *  real platform you don't have access to the endianess, therefore you have to test
 *  both cases.
 */
int main (int argc, char **argv) {
	
	uint8_t basic_hash[SHA1_HASH_LENGTH],
			pad_basic_oauth[2*SHA1_BLOCK_LENGTH];
	size_t i,padlen,
		   basic_oauthlen = strlen(basic_oauth) + strlen(secret), // Supposedly known by the attacker.
		   padded_basic_oauthlen;
	uint8_t *padded_basic_oauth;

	// SHA pad test
	sha1_utils_test_pad();

	// Break SHA-1
	printf("Exercice : break keyed SHA-1\n");

		// Create basic token	
	sha1_utils_keyed_mac(basic_hash, (uint8_t*) secret, strlen(secret), (uint8_t*) basic_oauth, strlen(basic_oauth));
	printf("Basic auth hash :");
	sha1_utils_printHash(basic_hash);

		// Compute pad 
	sha1_utils_md_pad(pad_basic_oauth, &padlen, (uint8_t*) basic_oauth, basic_oauthlen);
	padded_basic_oauthlen = strlen(basic_oauth) + padlen + strlen(admin_key);

	padded_basic_oauth = malloc(padded_basic_oauthlen*sizeof(uint8_t));
	if (NULL == padded_basic_oauth)
		return 0x01;

	sha1_utils_concat(padded_basic_oauth, (uint8_t*) basic_oauth, strlen(basic_oauth), pad_basic_oauth, padlen);	
	
		// check if padding works
	struct sha1nfo padded_basic_s;
	sha1_init(&padded_basic_s);
	sha1_write(&padded_basic_s,  secret, strlen(secret));
	sha1_write(&padded_basic_s,  (char*) padded_basic_oauth, strlen(basic_oauth) + padlen);

	printf("Basic padded auth hash :");
	sha1_utils_print_array((uint8_t*) padded_basic_s.state, SHA1_HASH_LENGTH, SWAP_ENDIAN );


		//SHA-1 "fixation"
	struct sha1nfo s;
	s.state[0] =  htonl(((uint32_t*) basic_hash)[0]);
	s.state[1] =  htonl(((uint32_t*) basic_hash)[1]);
	s.state[2] =  htonl(((uint32_t*) basic_hash)[2]);
	s.state[3] =  htonl(((uint32_t*) basic_hash)[3]);
	s.state[4] =  htonl(((uint32_t*) basic_hash)[4]);
	s.byteCount = strlen(secret) + strlen(basic_oauth) + padlen;
	s.bufferOffset = 0;
	

		// Add new data
	sha1_write(&s, admin_key, strlen(admin_key));
	uint8_t *result = sha1_result(&s);

	for (i = 0; i < strlen(admin_key); i++)
		padded_basic_oauth[i + strlen(basic_oauth) + padlen] =  admin_key[i];

		// Check signature
	if (test_sha1_sig(padded_basic_oauth, padded_basic_oauthlen, result))
	{
		printf("Valid command : "); 	
		write(1, padded_basic_oauth, padded_basic_oauthlen);
		printf("\n");
	}


	free(padded_basic_oauth);
	return 0;
}