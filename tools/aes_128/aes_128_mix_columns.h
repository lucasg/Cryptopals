#ifndef _AES_128_INV_MIX_COLUMNS_H_
	#define _AES_128_INV_MIX_COLUMNS_H_

void aes_128_mix_columns(unsigned char *state);
void aes_128_inv_mix_columns(unsigned char *state);

int test_aes_128_mix_columns();
int test_aes_128_inv_mix_columns();

#endif /* _AES_128_INV_MIX_COLUMNS_H_ */
