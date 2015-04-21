/* 
 * SHA-1 digest algorithm implementation in C, copied from
 * the liboauth project located here : https://code.google.com/p/oauth/ or http://liboauth.sourceforge.net/
 * 
 * liboauth disclaimer :
 * 		This code is public-domain - it is based on libcrypt
 * 		placed in the public domain by Wei Dai and other contributors.
 *
 * Added also some platform dependant helpers in order to port it on Windows
 */

#ifndef _SHA_1_H_
	#define _SHA_1_H_

#include <stdint.h>
 #include <string.h>

#define SHA1_HASH_LENGTH 20
#define SHA1_BLOCK_LENGTH 64

/*
 * SHA-1 "internal" data structure
 */
struct sha1nfo {
	uint32_t buffer[SHA1_BLOCK_LENGTH/4];
	uint32_t state[SHA1_HASH_LENGTH/4];
	uint32_t byteCount;
	uint8_t bufferOffset;
	uint8_t keyBuffer[SHA1_BLOCK_LENGTH];
	uint8_t innerHash[SHA1_HASH_LENGTH];
};


/*
 * Initialise the data structure
 */
void sha1_init(struct sha1nfo *s);

/*
 * Add a new byte of data in the buffer
 */
void sha1_writebyte(struct sha1nfo *s, uint8_t data);

/*
 * Add several new bytes of data in the buffer
 */
void sha1_write(struct sha1nfo *s, const char *data, size_t len);

/*
 *  Get the digested result
 */
uint8_t* sha1_result(struct sha1nfo *s);

/*
 *  HMAC implementation using SHA-1 as a hash function.
 */
void sha1_init_Hmac(struct sha1nfo *s, const uint8_t* key, size_t keyLength);

/*
 *  Get the digested result from the HMAC
 */
uint8_t* sha1_result_Hmac(struct sha1nfo *s);




#endif /* _SHA_1_H_ */