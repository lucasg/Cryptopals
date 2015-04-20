#ifndef _AES_128_H_
	#define _AES_128_H_

#include <stdint.h>
#include <stdlib.h>

#define AES_128_NUM_ROUNDS (10)
#define AES_128_BLOCK_LEN  (16)
/*
 *	AES-128 constants.
 */
static const unsigned int aes_128_block_len  = 16;

/*
 *	AES-128 operation mode currently supported.
 */
enum AES_128_OPERATION_MODE {ECB, CBC, CTR } ; 

/*
 *	Initialisation parameters. Can be :
 *   - an initial vector (iv). Has to be 16 8-bit chars long.
 *   - a 64-bit nonce
 */
union aes_128_init
{
	uint8_t iv[AES_128_BLOCK_LEN];
	uint64_t nonce;

};

/*
 *  AES 128-bit block encryption/decryption
 *  plaintext, ciphertext and key are all 16 bytes char buffer.
 */
void aes_128_encrypt(unsigned char *ctext, const unsigned char *ptext, const unsigned char *key);
void aes_128_decrypt(unsigned char *ptext, const unsigned char *ctext, const unsigned char *key);

/*
 *  AES 128-bit arbitrary long messages encryption/decryption, 
 *  using the following modes:
 * 		- ECB : do not use the IV.
 * 		- CBC
 *      - CTR : use the nonce.
 *  Keylen is still fixed to 16 bytes.
 *  Pkcs#7 padding is used before encryption. memcheck for available padding space on cmsg is left to the caller.
 *  Return the (padded) ciphertext length
 */
size_t aes_128_encrypt_msg(unsigned char *cmsg, const unsigned char *msg, size_t msglen, const unsigned char *key, enum AES_128_OPERATION_MODE mode, const union aes_128_init *IV);
void aes_128_decrypt_msg(unsigned char *msg, const unsigned char *cmsg, size_t msglen, const unsigned char *key, enum AES_128_OPERATION_MODE mode, const union aes_128_init *IV);


/*
 * Return the padded length necessary to encode an arbitrary message 
 * under AES-128 using the PKCS#7 mechanism. This function is primarly used
 * to compute the memory neeeded to hold the ciphertext.
 */
size_t aes_128_get_padded_length(const size_t msg_length, const enum AES_128_OPERATION_MODE mode);

#endif /* _AES_128_H_ */