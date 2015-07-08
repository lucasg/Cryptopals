#include "pkcs1_5.h"
#include "sha256.h"
#include "sha1.h"
#include "rsa_sign_constants.h"


/*
 * 	Generate a #PKCS1.5 padded message
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_5_generate(unsigned char *output, const unsigned char *msg, const size_t msg_len, const   char hash_name[8], const unsigned char* hash_value, const size_t hash_len ,const size_t block_len)
{
	size_t i,pad_len;

	if (msg_len + 3 + strlen(hash_name) + hash_len > block_len)
		return 0x01;

	memset(output, 0, block_len);

	pad_len = block_len - msg_len - strlen(hash_name) - hash_len - (3);

	// Message
	strncpy((char*) output, (char*) msg, msg_len);
	
	// Padding
	output[msg_len] = 0x00;
	output[msg_len + 1] = 0x01;
	memset(output + msg_len + 2, 0xff, pad_len);
	output[msg_len + 2 + pad_len] = 0x00;


	// Hash value
	memcpy(output + msg_len + 3 + pad_len, hash_name, strlen(hash_name));
	memcpy(output + msg_len + 3 + pad_len + strlen(hash_name), hash_value, hash_len);


	return 0x00;
}

/*
 * Wrong validation useful for Bleichenbacher attack (challenge #42).
 * This validator only look at what's at the end of the message and compute the hash of what's before, without checking the padding size.
 * It allow forging fake rsa signature if the e value is low enough.
 */
int pcks1_5_insecure_validate(unsigned char *signature, const size_t signature_len)
{
	size_t hash_len;
	unsigned char *sig_pointer, *hash;
	uint8_t sha256_buf[SHA256_HASH_SIZE];
	enum rsa_sign_hash_method h_method;
	struct sha256nfo sha256_h;
	struct sha1nfo sha1_h;

	/* 
	 *  Msg parsing
	 */
	sig_pointer = signature;
	while (0x00 != *sig_pointer)
	{
		sig_pointer++;

		if (sig_pointer > signature + signature_len)
			return -1;
	}

	/* 
	 *  Padding parsing
	 */
	sig_pointer++;
	if (*sig_pointer != 0x01)
		return -1;

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
	hash_len = signature_len - (hash - signature);


	/* 
	 *  Hash value
	 */
	switch(h_method)
	{
	case SHA1:
		sha1_init(&sha1_h);
		sha1_write(&sha1_h,  signature, strlen((char *) signature)); // signature is padded with '0x00'.

		return 0 == memcmp(sha1_result(&sha1_h), hash, SHA1_HASH_LENGTH);

		break;

	case SHA256:
		sha256_init(&sha256_h);
		sha256_write(&sha256_h, (uint8_t*) signature, strlen((char *)  signature)); // signature is padded with '0x00'.
		sha256_result(&sha256_h, sha256_buf);

		return 0 == memcmp(sha256_buf, hash, SHA256_HASH_SIZE);
		break;
	default:
		return -1;
	}

	return -1;
}
