#ifndef _SHA_1_UTILS_H_
	#define _SHA_1_UTILS_H_

#include <unistd.h>

#define SWAP_ENDIAN (1)

/*
 *	A simple array printing in the following form : /xde/xad/xbe/xef.
 *  Set swap_endianess to SWAP_ENDIAN in order to reverse the byte order.
 */
void md4_utils_print_array(uint8_t* array, size_t array_len, unsigned int swap_endianess);

/*
 * Print the hexadecimal array representing the hash
 */
void md4_utils_printHash(uint8_t* hash);

/*
 * Compute the following hash : h(key || msg). 
 * The hash parameter must be a 20 char array.
 */
void md4_utils_keyed_mac(uint8_t hash[], const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen);


/*
 * Compute the padding done to an arbitrary message before being hashed.
 * The padding follow this scheme : \x80\x00\x00....\x00\x$(msglen in bits). 
 */
void md4_utils_md_pad(uint8_t *padded, size_t *paddedlen, const uint8_t* msg, size_t msglen);

/*
 * Concatenate two string into a third one : out = str1 || str2.
 */
void md4_utils_concat(uint8_t *output, const uint8_t* str1, size_t str1len, const uint8_t* str2, size_t str2len);

/*
 * SHA-1 padding mechanism unit test.
 */
void md4_utils_test_pad();

#endif /* _SHA_1_UTILS_H_ */