#include "pkcs1_v1.5.h"
#include "sha256.h"
#include "sha1.h"
#include <stdio.h>


/*
 * 	Generate a #PKCS1.5 padded message
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_v1_5_generate(unsigned char *output, const unsigned char *msg, const size_t msg_len, const size_t block_len, const enum rsa_sign_hash_method h_method)
{
	size_t pad_len, hash_len;
	uint8_t sha256_buf[SHA256_HASH_SIZE];
	struct sha256nfo sha256_h;
	struct sha1nfo sha1_h;
	char *hash_name;


	memset(output, 0, block_len);

	/* 
	 *  Hash type
	 */
	switch(h_method)
	{
	case SHA1:
		hash_len = SHA1_HASH_LENGTH;
		hash_name = RSA_SIGN_HASH_METHOD_SHA_1;
		break;
	case SHA256:
		hash_len =	SHA256_HASH_SIZE;
		hash_name = RSA_SIGN_HASH_METHOD_SHA_256;
		break;
	default:
		return -1;
	}

	if (3 + strlen(hash_name) + hash_len > block_len)
		return 0x01;

	
	// Padding
	output[0] = 0x00;
	output[1] = 0x01;
	pad_len = block_len - strlen(hash_name) - hash_len - (3);
	memset(output + 2, 0xff, pad_len);
	output[2 + pad_len] = 0x00;


	/* 
	 *  Hash value
	 */
	memcpy(output +  3 + pad_len, hash_name, strlen(hash_name));
	switch(h_method)
	{
	case SHA1:
		sha1_init(&sha1_h);
		sha1_write(&sha1_h, (char*) msg, msg_len); 
		memcpy(output  + 3 + pad_len + strlen(hash_name), sha1_result(&sha1_h), SHA1_HASH_LENGTH);
		break;

	case SHA256:
		sha256_init(&sha256_h);
		sha256_write(&sha256_h, (uint8_t*) msg, msg_len); 
		sha256_result(&sha256_h, sha256_buf);

		memcpy(output  + 3 + pad_len + strlen(hash_name), sha256_buf, SHA256_HASH_SIZE);
		break;
	default:
		return -1;
	}

	return 0x00;
}

/*
 * Wrong validation useful for Bleichenbacher attack (challenge #42).
 * This validator only look at what's at the end of the message and compute the hash of what's before, without checking the padding size.
 * It allow forging fake rsa signature if the e value is low enough.
 */
int pkcs1_v1_5_insecure_validate(const 	char *signature, const size_t signature_len, const unsigned char *origin_hash, const size_t origin_hash_len)
{
	unsigned char *sig_pointer, *hash;
	enum rsa_sign_hash_method h_method;


	sig_pointer = (unsigned char*) signature;

	/* 
	 *  Padding parsing
	 */
	if (*sig_pointer != 0x00)
		return -1;

	sig_pointer++;
	if (*sig_pointer != 0x01)
	{
		return -1;
	}

	sig_pointer++;
	while (0x00 != *sig_pointer)
	{
		if (0xff != *sig_pointer)
		{
			return -1;
		}

		sig_pointer++;

		if (sig_pointer > signature + signature_len)
			return -1;
	}

	/* 
	 *   Hash type 
	 */
	if (0 == memcmp(sig_pointer + 1, RSA_SIGN_HASH_METHOD_SHA_1, strlen(RSA_SIGN_HASH_METHOD_SHA_1)))
	{
		h_method = SHA1;
		hash = sig_pointer + 1 + strlen(RSA_SIGN_HASH_METHOD_SHA_1);

	}
	else if (0 == memcmp(sig_pointer + 1, RSA_SIGN_HASH_METHOD_SHA_256, strlen(RSA_SIGN_HASH_METHOD_SHA_256)))
	{
		h_method = SHA256;
		hash = sig_pointer + 1 + strlen(RSA_SIGN_HASH_METHOD_SHA_256);
	}
	else
		return -1;

	/* 
	 *  Hash value
	 */
	return (0 == memcmp(hash, origin_hash , origin_hash_len));
}
