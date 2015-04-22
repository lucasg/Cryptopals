#ifndef _TARGET_H_
	#define _TARGET_H_

#include <stdlib.h>

/*
 * Encrypt the arbitrary input string under AES-CBC
 */
size_t encrypt(unsigned char **output);


/*
 *
 */
int decrypt(const unsigned char *cipher, size_t cipher_len);


/*
 *
 */
int is_right_answer(const char *input);

#endif /* _TARGET_H_ */