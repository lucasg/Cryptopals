#ifndef _RSA_SIGN_CONSTANTS_H_
	#define _RSA_SIGN_CONSTANTS_H_

/*
 *  RSA Block length. Used to determine the modulo's size.
 */
#define RSA_SIGN_BLOCK_LEN (RSA_SIGN_KEY_BITSIZE/8)
#define RSA_SIGN_KEY_BITSIZE (1024)
#define RSA_SIGN_HASH_METHOD_SHA_1 ("sha1")
#define RSA_SIGN_HASH_METHOD_SHA_256 ("sha256")

/*
 *	Supported Hashing methods for RSA signature validation
 */
enum rsa_sign_hash_method {SHA1, SHA256 }; 

#endif /* _RSA_SIGN_CONSTANTS_H_ */

