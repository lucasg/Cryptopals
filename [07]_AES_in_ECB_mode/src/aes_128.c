#include "aes_128.h"
#include "aes_128_key_schedule.h"
#include "aes_128_shift_rows.h"
#include "aes_128_s_box.h"
#include "aes_128_mix_columns.h"
#include <stdio.h>
#include <string.h>

#define AES_128_NUM_ROUNDS (10)
#define AES_128_BLOCK_LEN  (16)



void aes_128_encrypt(unsigned char *ctext, const unsigned char *ptext, const unsigned char *key)
{
	unsigned int r;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];

	// key expansion
	aes_128_key_expansion(round_keys, key);

	memcpy(state, ptext, aes_128_block_len);
	aes_128_add_round_key(state,round_keys);

	for (r = 0; r < aes_128_num_rounds - 1; r++)
	{
		aes_128_sub_bytes(state);
		aes_128_shift_rows(state);
		aes_128_mix_columns(state);
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(r+1) );
	}

	aes_128_sub_bytes(state);
	aes_128_shift_rows(state);
	aes_128_add_round_key(state,round_keys + aes_128_block_len*aes_128_num_rounds ); 

	memcpy(ctext, state, aes_128_block_len);
}

void aes_128_decrypt(unsigned char *ptext, const unsigned char *ctext, const unsigned char *key)
{
	unsigned int r;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];


	aes_128_key_expansion(round_keys, key);

	memcpy(state, ctext, aes_128_block_len);
	aes_128_add_round_key(state,round_keys + aes_128_block_len*aes_128_num_rounds);

	for (r = 0; r < aes_128_num_rounds - 1; r++)
	{
		aes_128_inv_shift_rows(state);
		aes_128_inv_sub_bytes(state);
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(aes_128_num_rounds - 1 - r) );
		aes_128_inv_mix_columns(state);
	}

	aes_128_inv_shift_rows(state);
	aes_128_inv_sub_bytes(state);
	aes_128_add_round_key(state,round_keys); 

	memcpy(ptext, state, aes_128_block_len);

}

