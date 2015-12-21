#include "aes_128_known_vectors.h"
#include "aes_128.h"
#include "aes_128_s_box.h"
#include "aes_128_shift_rows.h"
#include "aes_128_mix_columns.h"
#include "aes_128_key_schedule.h"
#include <stdio.h>
#include <string.h>

#define AES_128_NUM_ROUNDS (10)
#define AES_128_BLOCK_LEN  (16)

int test_aes_128_decrypt()
{
	unsigned int r, ts_idx;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];

	memcpy(state, aes_128_decrypt_test_ciphertext, aes_128_block_len);

	/* ciphertext state */
	ts_idx = 0;
	if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;	

	/* first key expansion */
	aes_128_key_expansion(round_keys, aes_128_decrypt_test_key);
	if (strncmp((char*) round_keys + aes_128_block_len*aes_128_num_rounds, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;

	/* add round key  */
	aes_128_add_round_key(state,round_keys + aes_128_block_len*aes_128_num_rounds);
	if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;

	for (r = 0; r < aes_128_num_rounds - 1; r++)
	{
		/* inv shift rows */
		aes_128_inv_shift_rows(state);
		if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* add inv subbytes */
		aes_128_inv_sub_bytes(state);
		if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* i-th key expansion */
		if (strncmp((char*) round_keys + aes_128_block_len*(aes_128_num_rounds - 1 - r), (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;
		
		/* add round key */
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(aes_128_num_rounds - 1 - r) );
		if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* inv mix columns	 */	
		aes_128_inv_mix_columns(state);
		if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

	}

	/* shift rows */
	aes_128_inv_shift_rows(state);
	if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	/* add subbytes */
	aes_128_inv_sub_bytes(state);
	if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;


	/* Last key expansion */
	if (strncmp((char*) round_keys, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	/* final add round key -> ciphertext  */
	aes_128_add_round_key(state,round_keys); 
	if (strncmp((char*) state, (char*) aes_128_decrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	return ts_idx;
}





int test_aes_128_encrypt()
{
	unsigned int r, ts_idx;
	unsigned char state[AES_128_BLOCK_LEN] = {0};
	unsigned char round_keys[AES_128_BLOCK_LEN*(AES_128_NUM_ROUNDS + 1)];

	memcpy(state, aes_128_encrypt_test_plaintext, aes_128_block_len);

	/* plaintext state */
	ts_idx = 0;
	if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;	

	/* first key expansion */
	aes_128_key_expansion(round_keys, aes_128_encrypt_test_key);
	if (strncmp((char*) round_keys, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;

	/* add round key */
	aes_128_add_round_key(state,round_keys);
	if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
	else
		ts_idx++;

	for (r = 0; r < aes_128_num_rounds - 1; r++)
	{
		/* add subbytes */
		aes_128_sub_bytes(state);
		if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* shift rows */
		aes_128_shift_rows(state);
		if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* mix columns */	
		aes_128_mix_columns(state);
		if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

		/* i-th key expansion */
		if (strncmp((char*) round_keys + aes_128_block_len*(r+1), (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;
		
		/* add round key */
		aes_128_add_round_key(state,round_keys + aes_128_block_len*(r+1) );
		if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
			return ts_idx;
		else
			ts_idx++;

	}

	/* add subbytes */
	aes_128_sub_bytes(state);
	if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	/* shift rows */
	aes_128_shift_rows(state);
	if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	/* Last key expansion */
	if (strncmp((char*) round_keys + aes_128_block_len*aes_128_num_rounds, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	/* final add round key -> ciphertext  */
	aes_128_add_round_key(state,round_keys + aes_128_block_len*aes_128_num_rounds ); 
	if (strncmp((char*) state, (char*) aes_128_encrypt_test_states + aes_128_block_len*ts_idx, aes_128_block_len ))
		return ts_idx;
	else
		ts_idx++;

	return ts_idx;
}

/* Test the key expansion algorithm against a known test case */
int test_aes_128_key_schedule()
{
	unsigned int i;
	unsigned char round_keys[16*(aes_128_num_rounds + 1)];


	aes_128_key_expansion(round_keys, aes_128_key_schedule_test_key);


	for (i = 0; i < aes_128_num_rounds + 1; i++)
		if (0 != strncmp( (char*) round_keys + 16*i, 
						  (char*)  aes_128_key_schedule_test + 16*(aes_128_num_rounds - i),
						  16))
			return 0x00;

	return 0x01;
}

int test_aes_128_add_round_key()
{
	unsigned int i = 0;
	unsigned char state[16];


	for (i=0; i < aes_128_num_rounds + 1; i++)
	{
		memcpy(state, aes_128_add_round_key_test_inputs + 16*i, 16 );
		aes_128_add_round_key(state, aes_128_add_round_key_test_round_keys + 16*i);

		if (strncmp((char*) state, (char*) aes_128_add_round_key_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;
}


int test_aes_128_mix_columns()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_mix_columns_test_inputs + 16*i, 16 );
		aes_128_mix_columns(state);

		if (strncmp((char*) state, (char*) aes_128_mix_columns_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;
}

int test_aes_128_inv_mix_columns()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_inv_mix_columns_test_inputs + 16*i, 16 );
		aes_128_inv_mix_columns(state);

		if (strncmp((char*) state, (char*) aes_128_inv_mix_columns_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;

}

int test_aes_128_sub_bytes()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_sub_bytes_test_inputs + 16*i, 16 );
		aes_128_sub_bytes(state);

		if (strncmp((char*) state, (char*) aes_128_sub_bytes_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;
}

int test_aes_128_inv_sub_bytes()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_inv_sub_bytes_test_inputs + 16*i, 16 );
		aes_128_inv_sub_bytes(state);

		if (strncmp((char*) state, (char*) aes_128_inv_sub_bytes_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;

}


int test_aes_128_shift_rows()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_shift_rows_test_inputs + 16*i, 16 );
		aes_128_shift_rows(state);

		if (strncmp((char*) state, (char*) aes_128_shift_rows_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;
}

int test_aes_128_inv_shift_rows()
{
	unsigned int i = 0;
	unsigned char state[16];

	for (i=0; i < 10; i++)
	{
		memcpy(state, aes_128_inv_shift_rows_test_inputs + 16*i, 16 );
		aes_128_inv_shift_rows(state);

		if (strncmp((char*) state, (char*) aes_128_inv_shift_rows_test_outputs + 16*i, 16 ))
			return 0x00;
	}

	return 0x01;
}



int main(int argc, char *argv[])
{

	printf("test_aes_128_key_schedule : %s \n",  test_aes_128_key_schedule() ? "OK" : "KO" );
	printf("test_aes_128_add_round_key : %s \n",  test_aes_128_add_round_key() ? "OK" : "KO" );

	printf("test_aes_128_mix_columns : %s \n",  test_aes_128_mix_columns() ? "OK" : "KO" );
	printf("test_aes_inv_128_mix_columns : %s \n",  test_aes_128_inv_mix_columns() ? "OK" : "KO" );

	printf("test_aes_128_sub_bytes : %s \n",  test_aes_128_sub_bytes() ? "OK" : "KO" );
	printf("test_aes_128_inv_sub_bytes : %s \n",  test_aes_128_inv_sub_bytes() ? "OK" : "KO" );

	printf("test_aes_128_shift_rows : %s \n",  test_aes_128_shift_rows() ? "OK" : "KO" );
	printf("test_aes_128_inv_shift_rows : %s \n",  test_aes_128_inv_shift_rows() ? "OK" : "KO" );

	printf("test_aes_128_encrypt : %s \n",  52 == test_aes_128_encrypt() ? "OK" : "KO" );
	printf("test_aes_128_decrypt : %s \n",  52 == test_aes_128_decrypt() ? "OK" : "KO" );
	return 0;
}