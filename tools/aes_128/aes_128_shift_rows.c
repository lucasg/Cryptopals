#include "aes_128_shift_rows.h"
#include <stdio.h>
#include <string.h>


static const unsigned char aes_128_shift_rows_table[4*4] = 
{
	 0,  5, 10, 15,
	 4,  9, 14,  3,
	 8, 13,  2,  7,
	12,  1,  6, 11
};

static const unsigned char aes_128_inv_shift_rows_table[4*4] = 
{
	 0, 13, 10,  7,
	 4,  1, 14, 11,
	 8,  5,  2, 15,
	12,  9,  6,  3
};



void aes_128_shift_rows(unsigned char *state)
{
	unsigned int i;
	unsigned char tmp_state[16] = {0};

	for (i = 0; i < 16; i++)
		tmp_state[i] = state[ aes_128_shift_rows_table[i] ];

	memcpy(state, tmp_state, 16);
	memset(tmp_state, 0,  sizeof(tmp_state));

}

void aes_128_inv_shift_rows(unsigned char *state)
{
	unsigned int i;
	unsigned char tmp_state[16] = {0};

	for (i = 0; i < 16; i++)
		tmp_state[i] = state[ aes_128_inv_shift_rows_table[i] ];

	memcpy(state, tmp_state, 16);
	memset(tmp_state, 0,  sizeof(tmp_state));
}

