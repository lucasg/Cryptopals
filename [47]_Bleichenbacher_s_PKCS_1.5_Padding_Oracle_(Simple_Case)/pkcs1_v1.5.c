#include "pkcs1_v1.5.h"
#include "sha256.h"
#include "sha1.h"
#include "mt19937.h"
#include <stdio.h>
#include <time.h>

#define PKCS1_BT_00	   (0x01)
#define PKCS1_BT_01	   (0x01)
#define PKCS1_BT_02	   (0x02)

#define PKCS1_SIGN_HASH_METHOD_SHA_1 ("sha1")
#define PKCS1_SIGN_HASH_METHOD_SHA_256 ("sha256")

/*
 * 	Generate a #PKCS1.5 padding with non-zeros random values (for block type 2)
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_v1_5_gen_rpadding(unsigned char *padding, const size_t padlen)
{
	int non_zero;
	size_t i, j;
	struct mt19937_t r_gen;

	mt19937_init(&r_gen, time(NULL));
	
	i = 0x00;
	while (4*i < padlen)
	{
		((uint32_t*) padding)[i] = mt19937_get_value(&r_gen);

		non_zero = 0x01;
		for (j = 4*i; j < 4*(i+1); j++)
			non_zero &= (padding[j] != 0x00);

		if (non_zero)
			i++;
	}

	return 0x00;
}

/*
 * 	Generate a #PKCS1.5 padded message
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_v1_5_generate(unsigned char *output, const unsigned char *msg, const size_t msg_len, const size_t block_len, enum pkcs1_v1_5_msg_type msg_type, const enum pkcs1_v1_5_sign_hash_method h_method)
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
		hash_name = PKCS1_SIGN_HASH_METHOD_SHA_1;
		break;
	case SHA256:
		hash_len =	SHA256_HASH_SIZE;
		hash_name = PKCS1_SIGN_HASH_METHOD_SHA_256;
		break;
	default:
		return -1;
	}

	if (3 + strlen(hash_name) + hash_len > block_len)
		return 0x01;

	
	/* Padding */
	output[0] = 0x00;
	switch (msg_type)
	{
	case pkcs1_signature:
		output[1] = PKCS1_BT_01;
		pad_len = block_len - strlen(hash_name) - hash_len - (3);
		memset(output + 2, 0xff, pad_len);
		break;
	case pkcs1_msg:
		output[1] = PKCS1_BT_02;
		pad_len = block_len - msg_len - (3);
		pkcs1_v1_5_gen_rpadding(output + 2, pad_len);
		break;
	}
	output[2 + pad_len] = 0x00;


	/* 
	 *  Hash value
	 */
    switch (msg_type)
	{
	case pkcs1_signature:
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
		break;

	case pkcs1_msg:
		memcpy(output + 3 + pad_len, msg, msg_len);
		break;
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

		if (sig_pointer > (unsigned char*) (signature + signature_len))
			return -1;
	}

	/* 
	 *   Hash type 
	 */
	if (0 == memcmp(sig_pointer + 1, PKCS1_SIGN_HASH_METHOD_SHA_1, strlen(PKCS1_SIGN_HASH_METHOD_SHA_1)))
	{
		hash = sig_pointer + 1 + strlen(PKCS1_SIGN_HASH_METHOD_SHA_1);
	}
	else if (0 == memcmp(sig_pointer + 1, PKCS1_SIGN_HASH_METHOD_SHA_256, strlen(PKCS1_SIGN_HASH_METHOD_SHA_256)))
	{
		hash = sig_pointer + 1 + strlen(PKCS1_SIGN_HASH_METHOD_SHA_256);
	}
	else
		return -1;

	/* 
	 *  Hash value
	 */
	return (0 == memcmp(hash, origin_hash , origin_hash_len));
}

/*  
 * For pkcs1_msg blocks, strip from a valid block the unecessary padding and reserved block, in order to retrieve the message
 * Since the message is in the data block, this functions does not allocate memory, it just place the pointer at the correct location 
 */
int pkcs1_v1_5_msg_strip(char **message, size_t *message_len , const char *block, const size_t block_len)
{
	/*int pad_valid;*/

	if (block_len < 2)
		return -1;

	/*pad_valid = pkcs1_v1_5_insecure_validate(block, block_len, NULL, 0);
	if ( 0x1 != pad_valid)
		return pad_valid;*/

	/* 0x00 0x02 reserved bytes */
	*message = (char *) block + 2;

	/* looking for padding terminator */
	*message += strlen(*message);

	if (((int) (*message - block)) > block_len)
		return -1;

	(*message)++;
	*message_len = block_len - (size_t) (*message - block);
	return 0x01;
}