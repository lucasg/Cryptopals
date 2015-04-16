#ifndef _TARGET_H_
	#define _TARGET_H_

/*
 * Check if the recovered 'key' using the decrypted plaintext 
 * is really the secret one.
 */
int check_recovered_key(const unsigned char *key_candidate);

/*
 * Encrypt the arbitrary input string under AES-CBC
 */
int encrypt(unsigned char **output, const char *input, unsigned int input_len);


/*
 * Decrypt the ciphertext if valid (no high-ascii characters in the plaintext).
 * Otherwise, dump the erroneous plaintext.
 */
unsigned char *decrypt(const unsigned char *cipher, unsigned int cipher_len);


#endif /* _TARGET_H_ */