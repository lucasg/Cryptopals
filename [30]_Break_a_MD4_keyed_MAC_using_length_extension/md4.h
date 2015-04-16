/* 
 * MD4 implementation copied from OpenSSL (OpenWall).
 * Modifications done :
 *  - changed naming conventions
 *  - stripped OpenSSL special defines and routines
 *  - modified specific types for uintXX_t
 *  - deleted extern qualifiers for functions
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
 * See md4.c for more information.
 */

#ifndef _MD4_H
	#define _MD4_H

#include <unistd.h> 

#define MD4_HASH_LENGTH 16
#define MD4_BLOCK_LENGTH 64

struct  md4_ctx {
	uint32_t lo, hi;
	uint32_t a, b, c, d;
	uint8_t buffer[MD4_BLOCK_LENGTH];
	uint32_t block[MD4_HASH_LENGTH];
};

/*
 * Initialise the data structure
 */
void md4_init(struct md4_ctx *ctx);

/*
 *  Add several new bytes of data in the buffer
 */
void md4_write(struct md4_ctx *ctx, const char *data, size_t size);

/*
 *  Get the digested result
 */
uint8_t* md4_digest(struct md4_ctx *ctx);

#endif
