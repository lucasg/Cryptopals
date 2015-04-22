#ifndef _AES_DETECT_ECB_MODE_H_
	#define _AES_DETECT_ECB_MODE_H_

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
int aes_detect_ecb_mode(const unsigned char *ciphertext, unsigned int cipherlength);

#endif /* _AES_DETECT_ECB_MODE_H_ */
