#include "client.h"
#include "rsa_utils.h"
#include "pkcs1_v1.5.h"
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
	char padded_msg[RSA_SIGN_BLOCK_LEN];


	if(pkcs1_v1_5_generate((unsigned char*) padded_msg, (unsigned char*)  msg, msg_len, RSA_SIGN_BLOCK_LEN, hash_method))
		return -1;

	/*
	 *  RSA "encryption" using d (inverse of e modulo phi). It's in fact a "decryption".
	 */
	return rsa_encrypt_msg(signature, n, pkey, padded_msg , RSA_SIGN_BLOCK_LEN);

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