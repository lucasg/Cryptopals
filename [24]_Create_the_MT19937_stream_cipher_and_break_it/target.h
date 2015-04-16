#ifndef _TARGET_H_
	#define _TARGET_H_
#include <unistd.h>
#include <stdint.h>

/*
 * Invalidate the current password token.
 */
void password_token_reset();

/*
 * Encrypt a plaintext message. Each call to encrypt invalidate the previous
 * password token.
 */
size_t encrypt( uint8_t *ctext[], const  uint8_t ptext[], const size_t len);

/*
 * Decrypt a previously encrypted plaintext message.
 */
unsigned int decrypt( uint8_t *ptext[], const  uint8_t ctext[], const size_t len);

#endif