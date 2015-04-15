#ifndef _TARGET_H_
	#define _TARGET_H_


/*
 *
 */
int encrypt(unsigned char **output, const char *email, unsigned int email_len);


/*
 *
 */
void decrypt(const unsigned char *cipher, unsigned int cipher_len);


#endif /* _TARGET_H_ */