#ifndef _TARGET_H_
	#define _TARGET_H_


/*
 * Encrypt the arbitrary input string under AES-CBC
 */
int encrypt(unsigned char **output, const char *input, unsigned int input_len);


/*
 *
 */
void decrypt(const unsigned char *cipher, unsigned int cipher_len);


#endif /* _TARGET_H_ */