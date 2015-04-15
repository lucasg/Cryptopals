#ifndef _AES_DETECT_BLOCK_SIZE_H_
	#define _AES_DETECT_BLOCK_SIZE_H_

#include <string.h>

// functions prototype for oracle encryption
typedef size_t (*aes_detect_block_size_encrypt)(unsigned char** cipher, const unsigned char* data, size_t datalen);


int aes_detect_block_size(aes_detect_block_size_encrypt encryption_method);


#endif /*_AES_DETECT_BLOCK_SIZE_H_ */