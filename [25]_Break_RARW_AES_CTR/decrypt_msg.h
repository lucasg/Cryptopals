#ifndef _DECRYPT_MSG_H_
	#define _DECRYPT_MSG_H_

#include <unistd.h>

/*
 *  Decrypt the file provided, using AES-ECB mode on a base64 string.
 */
unsigned int decrypt_msg(const char input_file[], const char key[], unsigned char **msg, size_t *msg_len);


#endif /* _DECRYPT_MSG_H_ */