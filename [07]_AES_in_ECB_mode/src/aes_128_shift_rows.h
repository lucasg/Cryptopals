#ifndef _AES_128_SHIFT_ROWS_H_
	#define _AES_128_SHIFT_ROWS_H_



void aes_128_shift_rows(unsigned char *state);
void aes_128_inv_shift_rows(unsigned char *state);


int test_aes_128_shift_rows();
int test_aes_128_inv_shift_rows();


#endif /* _AES_128_SHIFT_ROWS_H_ */