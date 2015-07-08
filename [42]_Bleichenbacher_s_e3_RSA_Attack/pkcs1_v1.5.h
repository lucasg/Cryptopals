#ifndef _PKCS_1_5_H_
	#define _PKCS_1_5_H_

#include <stddef.h>

/*
 * 	Generate a #PKCS1.5 padded message
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
int pkcs1_5_generate(unsigned char *output, const unsigned char *msg, const size_t msg_len, const  char hash_name[8], const unsigned char* hash_value, const size_t hash_len ,const size_t block_len);

/*
 * Wrong validation useful for Bleichenbacher attack (challenge #42).
 * This validator only look at what's at the end of the message and compute the hash of what's before, without checking the padding size.
 * It allow forging fake rsa signature if the e value is low enough.
 */
int pcks1_5_insecure_validate(unsigned char *signature, const size_t signature_len);

#endif /* _PKCS_1_5_H_ */