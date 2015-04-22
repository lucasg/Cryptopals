#include "md4.h"
#include "md4_utils.h"
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



unsigned int test_md4_sig(const uint8_t *command, const size_t command_len, const uint8_t *signature)
{
	uint8_t secret_sig[MD4_HASH_LENGTH];
	
	md4_utils_keyed_mac(secret_sig, (uint8_t*) secret, strlen(secret), (uint8_t*) command, command_len);

	printf("\n");


	return 0 == strncmp((char*) signature, (char*)  secret_sig, MD4_HASH_LENGTH*sizeof(uint8_t));
}


int main (int argc, char **argv) {
	
	uint8_t basic_hash[MD4_HASH_LENGTH],
			pad_basic_oauth[2*MD4_BLOCK_LENGTH],
			padded_basic_oauth_hash[MD4_HASH_LENGTH];
	size_t i,padlen,
		   basic_oauthlen = strlen(basic_oauth) + strlen(secret), // Supposedly known by the attacker.
		   padded_basic_oauthlen;
	uint8_t *padded_basic_oauth;

	// MD4 implementation test
	struct md4_ctx ctx;
	md4_init(&ctx);

	printf("Test: MD4 implementation\n");
	printf("Expect: MD4 ('abc') => a448017aaf21d8525fc10ae87aa6729d\n");
	printf("Result:");

	md4_write(&ctx, "abc", 3);
	md4_utils_print_array(md4_digest(&ctx), 16, 0);
	printf("\n");


	// Break MD4
	printf("Exercice : break keyed MD4\n");

	// Create basic token	
	md4_utils_keyed_mac(basic_hash, (uint8_t*) secret, strlen(secret), (uint8_t*) basic_oauth, strlen(basic_oauth));
	printf("Basic auth hash :");
	md4_utils_printHash(basic_hash);

	// Compute pad 
	md4_utils_md_pad(pad_basic_oauth, &padlen, (uint8_t*) basic_oauth, basic_oauthlen);
	padded_basic_oauthlen = strlen(basic_oauth) + padlen + strlen(admin_key);

	padded_basic_oauth = malloc(padded_basic_oauthlen*sizeof(uint8_t));
	if (NULL == padded_basic_oauth)
		return 0x01;

	md4_utils_concat(padded_basic_oauth, (uint8_t*) basic_oauth, strlen(basic_oauth), pad_basic_oauth, padlen);	
	for (i = 0; i < strlen(admin_key); i++)
		padded_basic_oauth[i + strlen(basic_oauth) + padlen] =  admin_key[i];

	// check if padding works
	struct md4_ctx padded_basic_s;
	md4_init(&padded_basic_s);
	md4_write(&padded_basic_s,  secret, strlen(secret));
	md4_write(&padded_basic_s,  (char*) padded_basic_oauth, strlen(basic_oauth) + padlen);

	printf("Basic padded auth hash :");
	padded_basic_oauth_hash[0] = padded_basic_s.a;
	padded_basic_oauth_hash[1] = padded_basic_s.a >> 8;
	padded_basic_oauth_hash[2] = padded_basic_s.a >> 16;
	padded_basic_oauth_hash[3] = padded_basic_s.a >> 24;
	padded_basic_oauth_hash[4] = padded_basic_s.b;
	padded_basic_oauth_hash[5] = padded_basic_s.b >> 8;
	padded_basic_oauth_hash[6] = padded_basic_s.b >> 16;
	padded_basic_oauth_hash[7] = padded_basic_s.b >> 24;
	padded_basic_oauth_hash[8] = padded_basic_s.c;
	padded_basic_oauth_hash[9] = padded_basic_s.c >> 8;
	padded_basic_oauth_hash[10] =padded_basic_s.c >> 16;
	padded_basic_oauth_hash[11] =padded_basic_s.c >> 24;
	padded_basic_oauth_hash[12] =padded_basic_s.d;
	padded_basic_oauth_hash[13] =padded_basic_s.d >> 8;
	padded_basic_oauth_hash[14] =padded_basic_s.d >> 16;
	padded_basic_oauth_hash[15] =padded_basic_s.d >> 24;
	md4_utils_print_array((uint8_t*) padded_basic_oauth_hash, MD4_HASH_LENGTH, SWAP_ENDIAN );
	printf("\n");

	// MD4 "fixation"
	struct md4_ctx s;
	s.a =  ((uint32_t*) basic_hash)[0];
	s.b =  ((uint32_t*) basic_hash)[1];
	s.c =  ((uint32_t*) basic_hash)[2];
	s.d =  ((uint32_t*) basic_hash)[3];
	s.lo = (strlen(secret) + strlen(basic_oauth) + padlen) & 0x1fffffff;
	s.hi = (strlen(secret) + strlen(basic_oauth) + padlen) >> 29;

	

	// Add new data
	md4_write(&s, admin_key, strlen(admin_key));
	uint8_t *result = md4_digest(&s);

	// Check signature
	if (test_md4_sig(padded_basic_oauth, padded_basic_oauthlen, result))
	{
		printf("Valid command : "); 	
		write(1, padded_basic_oauth, padded_basic_oauthlen);
		printf("\n");
	}


	free(padded_basic_oauth);
	return 0;
}
