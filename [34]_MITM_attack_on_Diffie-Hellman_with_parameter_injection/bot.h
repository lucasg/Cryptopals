#ifndef _BOT_H_
	#define _BOT_H_

#include "mini-gmp/mini-gmp.h"
#include "aes_128/aes_128.h"
#include <stddef.h>
#include <stdint.h>

/* 
 *  Internal data structure
 */
struct bot_t
{
	// DH parameters
	mpz_t p,g;

	// keys 
	mpz_t privkey;
	mpz_t pubkey;
	mpz_t shared_secret;

	// AES internal buffer
	union aes_128_init iv;
	uint8_t *msg_buffer, hashed_skey[AES_128_BLOCK_LEN];
	size_t msg_bufferlen;
};

/*
 *  Init the key exchange protocol parameters.
 */
void bot_init(struct bot_t *bot, const mpz_t privkey, const mpz_t p, const mpz_t g );

/*
 *  Generate the public key used in DH key exchange protocol, based on modular exponenetiation.
 */
mpz_t* bot_gen_pubkey(struct bot_t *bot);

/*
 *  Generate the shared secret between two bots, give the other public key
 */
mpz_t* bot_gen_shared_secret(struct bot_t *bot, const mpz_t o_pubkey);

/*
 *  "Send" a message : in reality encrypt it and prepend the random IV.
 */
size_t send_msg(struct bot_t *bot, const uint8_t *msg, const size_t msg_len);

/*
 *  "Receive" a message : in reality decrypt it.
 */
size_t recv_msg(struct bot_t *bot, const uint8_t *cmsg, const size_t cmsg_len);


/*
 *  Free any allocated memory
 */
void bot_cleanup(struct bot_t *bot);


#endif /* _BOT_H_ */ 