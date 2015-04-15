#ifndef _AES_128_H_
	#define _AES_128_H_

static const unsigned int aes_128_num_rounds = 10;
static const unsigned int aes_128_block_len  = 16;

void aes_128_encrypt(unsigned char *ctext, const unsigned char *ptext, const unsigned char *key);
void aes_128_decrypt(unsigned char *ptext, const unsigned char *ctext, const unsigned char *key);

#endif /* _AES_128_H_ */