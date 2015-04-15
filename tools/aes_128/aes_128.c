#include "aes_128.h"
#include "aes_128_key_schedule.h"
#include "aes_128_shift_rows.h"
#include "aes_128_s_box.h"
#include "aes_128_mix_columns.h"
#include "xor.h"
#include "pkcs7.h"
#include <stdio.h>
#include <string.h>


#define AES_128_NUM_ROUNDS (10)
#define AES_128_BLOCK_LEN  (16)

/*
 *  Specific data structure used to increment
 *  easily the ctr counter and cast it into a
 *  regular char buffer
 */
union aes_128_ctr_counter{
	uint8_t buf[AES_128_BLOCK_LEN];

	struct nonce_counter_t{
		uint64_t nonce;
		uint64_t counter;
	} nc;
	
};

/*
 *  OS-dependant implementation of 64bits little endian convert function
 */
#ifdef WIN32
uint64_t htole64(uint64_t host_64bits)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return host_64bits;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__	
#include <bswap.h>
	return bswap_64(host_64bits);
#else
#error("Byte order unknown")
#endif /* byte order under Windows */
}

#elif defined (linux) 
#include <endian.h>

#else
#error("Current platforms supported : Win, *nux")
#endif /* endian.h platform */


size_t aes_128_get_padded_length(const size_t msg_length, const enum AES_128_OPERATION_MODE mode)
{
	if (CTR == mode)
		return msg_length;

	if (msg_length % AES_128_BLOCK_LEN)
		return  msg_length + AES_128_BLOCK_LEN - (msg_length % AES_128_BLOCK_LEN);
	
	return msg_length;
}


size_t aes_128_encrypt_msg_ctr(unsigned char *cmsg, const unsigned char *msg, size_t msglen, const unsigned char *key, const int64_t nonce)
{
	size_t i, blk_len;
	unsigned char encrypted_counter[AES_128_BLOCK_LEN], *blk;

	union aes_128_ctr_counter ctr_counter = { 
			.nc = {
				 .counter = 0,
				 .nonce = nonce 
			}};
	
	blk = cmsg;
	for (i = 0; i*aes_128_block_len < msglen; i++ )
	{
		memset(encrypted_counter, 0, sizeof(encrypted_counter));

		ctr_counter.nc.counter = htole64(i);
		

		aes_128_encrypt( encrypted_counter, ctr_counter.buf , key);

		blk_len = (cmsg + msglen - blk) < aes_128_block_len ? (cmsg + msglen - blk) : aes_128_block_len;
		xor_encode(blk, encrypted_counter, blk_len, msg, blk_len);


		msg += blk_len;
		blk += blk_len;
	}

	return msglen;
}

void aes_128_decrypt_msg_ctr(unsigned char *msg, const unsigned char *cmsg, size_t msglen, const unsigned char *key, const int64_t nonce)
{
 	aes_128_encrypt_msg_ctr(msg, cmsg, msglen, key, nonce);
}


size_t aes_128_encrypt_msg_cbc(unsigned char *cmsg, const unsigned char *msg, size_t msglen, const unsigned char *key, const unsigned char *IV)
{
	unsigned char filler[AES_128_BLOCK_LEN] = {0};
	unsigned char state[AES_128_BLOCK_LEN]= {0}, prev_state[AES_128_BLOCK_LEN]= {0};
 	unsigned char *blk = (unsigned char*) msg;

 	memcpy(prev_state, IV, sizeof(prev_state));

 	while ( blk  <  msg + msglen )
	{
		// pkcs7 padding
		if ( 0 < msg+msglen-blk && msg+msglen-blk < AES_128_BLOCK_LEN)
		{
			pkcs7_generate(filler, blk, msg+msglen-blk,  AES_128_BLOCK_LEN);
			xor_encode(state, filler, AES_128_BLOCK_LEN, prev_state, AES_128_BLOCK_LEN);
		}
		else
			xor_encode(state, blk, AES_128_BLOCK_LEN, prev_state, AES_128_BLOCK_LEN);
		

		aes_128_encrypt(cmsg, state, key);


		memcpy(prev_state, cmsg, sizeof(prev_state));

		blk += AES_128_BLOCK_LEN;
		cmsg += AES_128_BLOCK_LEN;
	}

	return (int)(blk-msg);
}

void aes_128_decrypt_msg_cbc(unsigned char *msg, const unsigned char *cmsg, size_t msglen, const unsigned char *key, const unsigned char *IV)
{
 	unsigned char state[AES_128_BLOCK_LEN]= {0}, prev_cblk[AES_128_BLOCK_LEN]= {0};
 	unsigned char *cblk = (unsigned char*) cmsg;

 	memcpy(prev_cblk, IV, sizeof(prev_cblk));

 	while ( cblk  <  cmsg + msglen )
	{
		aes_128_decrypt(state, cblk, key);
		xor_decode(msg, state, AES_128_BLOCK_LEN, prev_cblk, AES_128_BLOCK_LEN);

		memcpy(prev_cblk, cblk, sizeof(prev_cblk));

		cblk += AES_128_BLOCK_LEN;
		msg += AES_128_BLOCK_LEN;
	}

}

int aes_128_encrypt_msg_ecb(unsigned char *cmsg, const unsigned char *msg, size_t msglen, const unsigned char *key)
{
	unsigned char filler[AES_128_BLOCK_LEN] = {0};
	unsigned char *blk = (unsigned char*) msg;
	
	while ( blk  <  msg + msglen )
	{
		// pkcs7 padding
		if ( 0 < msg+msglen-blk && msg+msglen-blk < AES_128_BLOCK_LEN)
		{
			pkcs7_generate(filler, blk, msg+msglen-blk,  AES_128_BLOCK_LEN);
			aes_128_encrypt(cmsg, filler, key); 
		}
		else
			aes_128_encrypt(cmsg, blk, key);
		

		blk += AES_128_BLOCK_LEN;
		cmsg += AES_128_BLOCK_LEN;
	}

	return (int)(blk-msg);
}

void aes_128_decrypt_msg_ecb(unsigned char *msg, const unsigned char *cmsg, size_t msglen, const unsigned char *key)
{
	unsigned char *cblk = (unsigned char*) cmsg;
	
	while ( cblk  <  cmsg + msglen )
	{
		aes_128_decrypt(msg, cblk, key);

		cblk += AES_128_BLOCK_LEN;
		msg += AES_128_BLOCK_LEN;
	}
}


size_t aes_128_encrypt_msg(unsigned char *cmsg, const unsigned char *msg, size_t msglen, const unsigned char *key, enum AES_128_OPERATION_MODE mode, const union aes_128_init *IV)
{
	switch (mode)
	{
	case CBC:
		return aes_128_encrypt_msg_cbc(cmsg, msg, msglen,key,IV->iv);
		break;
	case CTR:
		return aes_128_encrypt_msg_ctr(cmsg, msg, msglen,key,IV->nonce);
		break;			
	default:
	case ECB:
		return aes_128_encrypt_msg_ecb(cmsg, msg, msglen,key);		
		break;
	}
}

void aes_128_decrypt_msg(unsigned char *msg, const unsigned char *cmsg, size_t msglen, const unsigned char *key, enum AES_128_OPERATION_MODE mode, const union aes_128_init *IV)
{
	switch (mode)
	{
	case CBC:
		aes_128_decrypt_msg_cbc(msg, cmsg, msglen,key,IV->iv);
		break;
	case CTR:
		aes_128_decrypt_msg_ctr(msg, cmsg, msglen,key,IV->nonce);
		break;			
	default:
	case ECB:
		aes_128_decrypt_msg_ecb(msg, cmsg, msglen,key);		
		break;
	}
}


void aes_128_encrypt(unsigned char *ctext, const unsigned char *ptext, const unsigned char *key)
{
	unsigned int r;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];

	// key expansion
	aes_128_key_expansion(round_keys, key);

	memcpy(state, ptext, AES_128_BLOCK_LEN*sizeof(char));
	aes_128_add_round_key(state,round_keys);

	for (r = 0; r < AES_128_NUM_ROUNDS - 1; r++)
	{
		aes_128_sub_bytes(state);
		aes_128_shift_rows(state);
		aes_128_mix_columns(state);
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(r+1) );
	}

	aes_128_sub_bytes(state);
	aes_128_shift_rows(state);
	aes_128_add_round_key(state,round_keys + aes_128_block_len*AES_128_NUM_ROUNDS ); 

	memcpy(ctext, state, aes_128_block_len);
}


void aes_128_decrypt(unsigned char *ptext, const unsigned char *ctext, const unsigned char *key)
{
	unsigned int r;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];


	aes_128_key_expansion(round_keys, key);

	memcpy(state, ctext, aes_128_block_len);
	aes_128_add_round_key(state,round_keys + aes_128_block_len*AES_128_NUM_ROUNDS);

	for (r = 0; r < AES_128_NUM_ROUNDS - 1; r++)
	{
		aes_128_inv_shift_rows(state);
		aes_128_inv_sub_bytes(state);
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(AES_128_NUM_ROUNDS - 1 - r) );
		aes_128_inv_mix_columns(state);
	}

	aes_128_inv_shift_rows(state);
	aes_128_inv_sub_bytes(state);
	aes_128_add_round_key(state,round_keys); 

	memcpy(ptext, state, aes_128_block_len);

}

