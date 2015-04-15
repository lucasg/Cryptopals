#include "aes_128_s_box.h"
#include <stdio.h>
#include <string.h>





void aes_128_inv_sub_bytes(unsigned char *state)
{
	unsigned int i;
	for( i = 0 ; i < 16; i++)
		state[i] = aes_128_inv_s_box[state[i]];
}


void aes_128_sub_bytes(unsigned char *state)
{
	unsigned int i;
	for( i = 0 ; i < 16; i++)
		state[i] = aes_128_s_box[state[i]];
}


