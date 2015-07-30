#ifndef _PKCS_1_5_H_
	#define _PKCS_1_5_H_

#include <stddef.h>

/*
 *	Supported message type for PKCS#1 v1.5 padding scheme and validation
 */
enum pkcs1_v1_5_msg_type { pkcs1_signature, pkcs1_msg }; 

/*
 *	Supported Hashing methods for RSA signature validation
 */
enum pkcs1_v1_5_sign_hash_method {SHA1, SHA256 }; 



/*
 * 	Generate a PKCS# v1.5 padded message
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_v1_5_generate(unsigned char *output, const unsigned char *msg, const size_t msg_len, const size_t block_len, const enum pkcs1_v1_5_msg_type msg_type,  const enum pkcs1_v1_5_sign_hash_method h_method);

/*
 * Wrong PKCS# v1.5 validation useful for Bleichenbacher attack (challenge #42).
 * This validator only look at what's at the end of the message and compute the hash of what's before, without checking the padding size.
 * It allow forging fake rsa signature if the e value is low enough.
 */
int pkcs1_v1_5_insecure_validate(const char *signature, const size_t signature_len,  const unsigned char *origin_hash, const size_t origin_hash_len);

#endif /* _PKCS_1_5_H_ */