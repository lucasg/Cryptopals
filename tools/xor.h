#ifndef _XOR_H_
	#define _XOR_H_

#include <string.h>

/*
 *	XOR encoding of a plaintext source with a key. The keylength and source text len can be different,
 *  it cycle the key as long as necessary (vigenere cipher).
 */
void xor_encode(unsigned char* dst, const unsigned char* src, size_t len, const  unsigned char* key, size_t keylen);
void xor_encode_uint(unsigned int* dst, const  unsigned int* src, size_t len, const  unsigned int* key, size_t keylen);

/*
 *	XOR decoding of a ciphertext source with a key. The keylength and source text len can be different,
 *  it cycle the key as long as necessary (vigenere cipher).
 */
void xor_decode(unsigned char* dst, const unsigned char* src, size_t len, const unsigned char* key, size_t keylen);
void xor_decode_uint(unsigned int* dst, const  unsigned int* src, size_t len, const  unsigned int* key, size_t keylen);

/*
 *	XOR encoding of a plaintext source with a single char key, aka letter shift cipher or Casear cipher.
 */
void caesar_encode(unsigned char* dst, const unsigned char* src, size_t len, unsigned char key);
void caesar_encode_uint(unsigned int* dst, const unsigned int* src, size_t len, unsigned int key);

/*
 *	XOR decoding of a ciphertext source with a single char key, aka letter shift cipher or Casear cipher.
 */
void caesar_decode(unsigned char* dst, const unsigned char* src, size_t len, unsigned char key);
void caesar_decode_uint(unsigned int* dst, const unsigned int* src, size_t len, unsigned int key);

#ifdef TEST
	/* 
	 *	Simple round trip unit test. 
	 *  Returns 100*(errors for int version) + 1*(errors for char version)
	 */
	unsigned int xor_roundtrip_test();
	unsigned int caesar_roundtrip_test();
#endif /* TEST */

#endif /* _XOR_H_ */