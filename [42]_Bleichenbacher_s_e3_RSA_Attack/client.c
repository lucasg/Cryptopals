#include "client.h"
#include "rsa_utils.h"
#include "pkcs1_5.h"
#include "sha1.h"
#include "sha256.h"

static mpz_t pkey, n;

/*
 * Initialize the client with the private key used to sign the messages.
 */
int client_init(const mpz_t private_key,const  mpz_t modulo)
{
	mpz_init_set(pkey, private_key);
	mpz_init_set(n, modulo);

	return 0x00;
}


/* 
 * Sign a mesage using the private key.
 */
int client_sign_msg(mpz_t *signature, const char *msg, const size_t msg_len, const enum rsa_sign_hash_method hash_method )
{
	size_t i;
	struct sha256nfo sha256_h;
	struct sha1nfo sha1_h;
	char padded_msg[RSA_SIGN_BLOCK_LEN/8 - 2];
	uint8_t sha256_buf[SHA256_HASH_SIZE];

	switch(hash_method)
	{
	case SHA1:
		sha1_init(&sha1_h);
		sha1_write(&sha1_h, msg, msg_len);

		if(pkcs1_5_generate((unsigned char*) padded_msg, (unsigned char*)  msg, msg_len, RSA_SIGN_HASH_METHOD_SHA_1 , (char*) sha1_result(&sha1_h), SHA1_HASH_LENGTH , RSA_SIGN_BLOCK_LEN/8 - 2))
			return -1;

		break;
		
	case SHA256:
		sha256_init(&sha256_h);
		sha256_write(&sha256_h, (uint8_t*) msg, msg_len);
		sha256_result(&sha256_h, sha256_buf);

		if(pkcs1_5_generate((unsigned char*) padded_msg, (unsigned char*)  msg, msg_len, RSA_SIGN_HASH_METHOD_SHA_256 , (unsigned char*) sha256_buf, SHA256_HASH_SIZE , RSA_SIGN_BLOCK_LEN/8 - 2))
			return -1;

		break;

	default:
		return -1;
	}

/*	printf("[DEBUG] s : ");
	for (i = 0; i < msg_len; i++)
		printf("%c", padded_msg[i]);
	for (i = msg_len; i < RSA_SIGN_BLOCK_LEN/8 - 2; i++ )
		printf("%02x", (unsigned char) padded_msg[i]);
	printf("\n");*/

	/*
	 *  RSA "encryption" using d (inverse of e modulo phi). It's in fact a "decryption".
	 */
	return rsa_encrypt_msg(signature, n, pkey, padded_msg , sizeof(padded_msg));
}

/*
 * Free any allocated resources
 */
int client_cleanup()
{
	mpz_clear(pkey);
	mpz_clear(n);

	return 0x00;	
}