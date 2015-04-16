/*
 * MD4 implementation copied from OpenSSL (OpenWall). I have modified the naming
 * convention to fit mine.
 *
 * Original disclaimer : 
 * ---------------------------------------------------------------------------------
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 * This differs from Colin Plumb's older public domain implementation in that
 * no exactly 32-bit integer data type is required (any 32-bit or wider
 * unsigned integer data type will do), there's no compile-time endianness
 * configuration, and the function prototypes match OpenSSL's.  No code from
 * Colin Plumb's implementation has been reused; this comment merely compares
 * the properties of the two independent implementations.
 *
 * The primary goals of this implementation are portability and ease of use.
 * It is meant to be fast, but not as fast as possible.  Some known
 * optimizations are not included to reduce source code size and avoid
 * compile-time configuration.
 */

#include "md4.h"
#include <string.h>


/*
 * The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			((x) ^ (y) ^ (z))

/*
 * The MD4 transformation for all three rounds.
 */
#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
	(*(uint32_t *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(ctx->block[(n)] = \
	(uint32_t)ptr[(n) * 4] | \
	((uint32_t)ptr[(n) * 4 + 1] << 8) | \
	((uint32_t)ptr[(n) * 4 + 2] << 16) | \
	((uint32_t)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])
#endif


/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
static const uint8_t *body(struct md4_ctx *ctx, const uint8_t *data, size_t size)
{
	const unsigned char *ptr;
	uint32_t a, b, c, d;
	uint32_t saved_a, saved_b, saved_c, saved_d;

	ptr = (const unsigned char *)data;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

/* Round 1 */
		STEP(F, a, b, c, d, SET(0), 3)
		STEP(F, d, a, b, c, SET(1), 7)
		STEP(F, c, d, a, b, SET(2), 11)
		STEP(F, b, c, d, a, SET(3), 19)
		STEP(F, a, b, c, d, SET(4), 3)
		STEP(F, d, a, b, c, SET(5), 7)
		STEP(F, c, d, a, b, SET(6), 11)
		STEP(F, b, c, d, a, SET(7), 19)
		STEP(F, a, b, c, d, SET(8), 3)
		STEP(F, d, a, b, c, SET(9), 7)
		STEP(F, c, d, a, b, SET(10), 11)
		STEP(F, b, c, d, a, SET(11), 19)
		STEP(F, a, b, c, d, SET(12), 3)
		STEP(F, d, a, b, c, SET(13), 7)
		STEP(F, c, d, a, b, SET(14), 11)
		STEP(F, b, c, d, a, SET(15), 19)

/* Round 2 */
		STEP(G, a, b, c, d, GET(0) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(4) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(8) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(12) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(1) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(5) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(9) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(13) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(2) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(6) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(10) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(14) + 0x5a827999, 13)
		STEP(G, a, b, c, d, GET(3) + 0x5a827999, 3)
		STEP(G, d, a, b, c, GET(7) + 0x5a827999, 5)
		STEP(G, c, d, a, b, GET(11) + 0x5a827999, 9)
		STEP(G, b, c, d, a, GET(15) + 0x5a827999, 13)

/* Round 3 */
		STEP(H, a, b, c, d, GET(0) + 0x6ed9eba1, 3)
		STEP(H, d, a, b, c, GET(8) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(4) + 0x6ed9eba1, 11)
		STEP(H, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(2) + 0x6ed9eba1, 3)
		STEP(H, d, a, b, c, GET(10) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(6) + 0x6ed9eba1, 11)
		STEP(H, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(1) + 0x6ed9eba1, 3)
		STEP(H, d, a, b, c, GET(9) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(5) + 0x6ed9eba1, 11)
		STEP(H, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
		STEP(H, a, b, c, d, GET(3) + 0x6ed9eba1, 3)
		STEP(H, d, a, b, c, GET(11) + 0x6ed9eba1, 9)
		STEP(H, c, d, a, b, GET(7) + 0x6ed9eba1, 11)
		STEP(H, b, c, d, a, GET(15) + 0x6ed9eba1, 15)

		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (size -= 64);

	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;

	return ptr;
}

void md4_init(struct md4_ctx *ctx)
{
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void md4_write(struct md4_ctx *ctx, const char *data, size_t size)
{
	uint32_t saved_lo;
	unsigned long used, available;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		available = 64 - used;

		if (size < available) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, available);
		data = (const char *)data + available;
		size -= available;
		body(ctx, ctx->buffer, 64);
	}

	while (size >= 64) {
		data = (const char *) body(ctx, (const uint8_t*) data, size & ~(unsigned long)0x3f);
		//size &= 0x3f;
		size -= 64;
	}
	size &= 0x3f;

	memcpy(ctx->buffer, data, size);
}

uint8_t* md4_digest(struct md4_ctx *ctx)
{
	unsigned long used, available;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	available = MD4_BLOCK_LENGTH - used;

	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		body(ctx, ctx->buffer, MD4_BLOCK_LENGTH);
		used = 0;
		available = MD4_BLOCK_LENGTH;
	}

	memset(&ctx->buffer[used], 0, available - 8);

	ctx->lo <<= 3;
	ctx->buffer[56] = ctx->lo;
	ctx->buffer[57] = ctx->lo >> 8;
	ctx->buffer[58] = ctx->lo >> 16;
	ctx->buffer[59] = ctx->lo >> 24;
	ctx->buffer[60] = ctx->hi;
	ctx->buffer[61] = ctx->hi >> 8;
	ctx->buffer[62] = ctx->hi >> 16;
	ctx->buffer[63] = ctx->hi >> 24;

	body(ctx, ctx->buffer, MD4_BLOCK_LENGTH);

	/* We are using the buffer to store the resulting output.
	   It doesn't matters if we overwrite data, since a digested
	   hash can't receive new data */
	ctx->buffer[0] = ctx->a;
	ctx->buffer[1] = ctx->a >> 8;
	ctx->buffer[2] = ctx->a >> 16;
	ctx->buffer[3] = ctx->a >> 24;
	ctx->buffer[4] = ctx->b;
	ctx->buffer[5] = ctx->b >> 8;
	ctx->buffer[6] = ctx->b >> 16;
	ctx->buffer[7] = ctx->b >> 24;
	ctx->buffer[8] = ctx->c;
	ctx->buffer[9] = ctx->c >> 8;
	ctx->buffer[10] = ctx->c >> 16;
	ctx->buffer[11] = ctx->c >> 24;
	ctx->buffer[12] = ctx->d;
	ctx->buffer[13] = ctx->d >> 8;
	ctx->buffer[14] = ctx->d >> 16;
	ctx->buffer[15] = ctx->d >> 24;

	return (uint8_t*) ctx->buffer;
}

