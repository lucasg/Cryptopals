#ifndef _AES_DETECT_ECB_MODE_H_
	#define _AES_DETECT_ECB_MODE_H_

#include <string.h>

// functions prototype for oracle encryption
typedef size_t (*aes_encrypt)(unsigned char** cipher, const unsigned char* data, size_t datalen, const unsigned char* key, size_t keylen, const unsigned char *iv );

/*
 *  Return 1 if the ciphertext has been encrypted using ECB mode.
 *  Return 0 otherwise.
 *  
 *	Perfs :
 * 			est\real     cbc, ecb
 * 			cbc     0.997942, 0.003891
 *  		ecb     0.002058, 0.996109
 *
 */
int aes_ecb_detection_oracle(aes_encrypt encryption_method, unsigned int block_size);

int aes_detect_ecb_mode(const unsigned char *ciphertext, unsigned int cipherlength, unsigned int block_size);

#endif /* _AES_DETECT_ECB_MODE_H_ */
