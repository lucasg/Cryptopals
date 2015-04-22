#ifndef _TARGET_H_
	#define _TARGET_H_

#include <string.h>
#include "../tools/aes_128/aes_128.h"

/*
 *  Allocate the ciphertext buffer, which has to be manually freed
 *	encrypt plaintext data, using the randomly generated key.
 *  Append the secret to the plaintext before encryption.
 *  
 *  return the ciphertext len 
 */
size_t encrypt(unsigned char **cipher, const unsigned char* data, size_t datalen);

#endif /* _TARGET_H_ */