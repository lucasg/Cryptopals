#include "aes_128_mix_columns.h"
#include <stdio.h>
#include <string.h>

unsigned char galois_mult_by_two(unsigned char val)
{
	if ((val >> 7) & 0x1)
		return (val << 1) ^ 0x1b;
	else
		return (val << 1);
}

/* x*3 = (x*2)+x */
unsigned char galois_mult_by_three(unsigned char val)
{
	return galois_mult_by_two(val) ^ val;
}

/* x×9=(((x×2)×2)×2)+x */
unsigned char galois_mult_by_nine(unsigned char val)
{
	return galois_mult_by_two( galois_mult_by_two( galois_mult_by_two(val) ) ) ^ val;
}

/* x×11=((((x×2)×2)+x)×2)+x */
unsigned char galois_mult_by_eleven(unsigned char val)
{
	return galois_mult_by_two( galois_mult_by_two( galois_mult_by_two(val) ) ^ val ) ^ val;
}

/* x×13=((((x×2)+x)×2)×2)+x  */
unsigned char galois_mult_by_thirteen(unsigned char val)
{
	return galois_mult_by_two( galois_mult_by_two( galois_mult_by_two(val) ^ val ) ) ^ val;
}

/* x×14=((((x×2)+x)×2)+x)×2  */
unsigned char galois_mult_by_fourteen(unsigned char val)
{
	return galois_mult_by_two( galois_mult_by_two( galois_mult_by_two(val) ^ val ) ^ val ) ;
}

void gmix_column(unsigned char *r) {
	unsigned char a[4];
	unsigned char b[4];
	unsigned char c;
	unsigned char h;
	/* The array 'a' is simply a copy of the input array 'r'
	 * The array 'b' is each element of the array 'a' multiplied by 2
	 * in Rijndael's Galois field
	 * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	for(c=0;c<4;c++) {
		a[c] = r[c];
		/* h is 0xff if the high bit of r[c] is set, 0 otherwise */
		h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
		b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
		b[c] ^= 0x1B & h; /* Rijndael's Galois field */
	}
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}



void aes_128_mix_columns(unsigned char *state)
{
	unsigned j;
	unsigned char tmp_col[4] = {0};

	for (j = 0; j < 4; j++)
	{

		tmp_col[0] = galois_mult_by_two(state[4*j]) ^ galois_mult_by_three(state[4*j + 1]) ^ state[4*j + 2] ^  state[4*j + 3];
		tmp_col[1] = galois_mult_by_two(state[4*j + 1]) ^ galois_mult_by_three(state[4*j + 2]) ^ state[4*j + 3] ^  state[4*j];
		tmp_col[2] = galois_mult_by_two(state[4*j + 2]) ^ galois_mult_by_three(state[4*j + 3]) ^ state[4*j] ^  state[4*j + 1];
		tmp_col[3] = galois_mult_by_two(state[4*j + 3]) ^ galois_mult_by_three(state[4*j]) ^ state[4*j + 1] ^  state[4*j + 2];

		state[4*j] = tmp_col[0];
		state[4*j + 1] = tmp_col[1];
		state[4*j + 2] = tmp_col[2];
		state[4*j + 3] = tmp_col[3];
	}

}

void aes_128_inv_mix_columns(unsigned char *state)
{
	unsigned j;
	unsigned char tmp_col[4] = {0};

	for (j = 0; j < 4; j++)
	{

		tmp_col[0] = galois_mult_by_fourteen(state[4*j]) ^ galois_mult_by_eleven(state[4*j + 1]) ^ galois_mult_by_thirteen(state[4*j + 2]) ^  galois_mult_by_nine(state[4*j + 3]);
		tmp_col[1] = galois_mult_by_fourteen(state[4*j + 1]) ^ galois_mult_by_eleven(state[4*j + 2]) ^ galois_mult_by_thirteen(state[4*j + 3]) ^  galois_mult_by_nine(state[4*j]);
		tmp_col[2] = galois_mult_by_fourteen(state[4*j + 2]) ^ galois_mult_by_eleven(state[4*j + 3]) ^ galois_mult_by_thirteen(state[4*j]) ^  galois_mult_by_nine(state[4*j + 1]);
		tmp_col[3] = galois_mult_by_fourteen(state[4*j + 3]) ^ galois_mult_by_eleven(state[4*j]) ^ galois_mult_by_thirteen(state[4*j + 1]) ^  galois_mult_by_nine(state[4*j + 2]);

		state[4*j] = tmp_col[0];
		state[4*j + 1] = tmp_col[1];
		state[4*j + 2] = tmp_col[2];
		state[4*j + 3] = tmp_col[3];
	}
}

