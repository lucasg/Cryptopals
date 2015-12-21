/*
 * SHA256 implementation in C, copied from https://github.com/B-Con/crypto-algorithms
 * Functions name and typedefs modified to fit the project's code style.
 */

/* Original Disclaimer
 *********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef _SHA256_H_
	#define _SHA256_H_

#include <stddef.h>
#include <stdint.h>


#define SHA256_HASH_SIZE  (32)
#define SHA256_BLOCK_SIZE (64)


struct sha256nfo{
	uint8_t data[SHA256_BLOCK_SIZE];
	uint32_t datalen;
	uint64_t bitlen;
	uint32_t state[SHA256_HASH_SIZE/4];

	uint8_t keyBuffer[SHA256_BLOCK_SIZE];
	uint8_t innerHash[SHA256_HASH_SIZE];
};

/*
 * Initialize the internal data structure
 */
void sha256_init(struct sha256nfo *ctx);

/*
 * "Write" a string 
 */
void sha256_write(struct sha256nfo *ctx, const uint8_t data[], size_t len);

/*
 * Get the resulting padded hash. 
 */
void sha256_result(struct sha256nfo *ctx, uint8_t hash[]);


/*
 *  HMAC implementation using SHA-1 as a hash function.
 */
void sha256_init_Hmac(struct sha256nfo *s, const uint8_t* key, size_t keyLength);

/*
 *  Get the digested result from the HMAC
 */
void sha256_result_Hmac(struct sha256nfo *s, uint8_t hash[]);

#endif   /* _SHA256_H_ */
