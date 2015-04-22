#ifndef _AES_128_KEY_SCHEDULE_H_
	#define _AES_128_KEY_SCHEDULE_H_

void aes_128_add_round_key(unsigned char *state, const unsigned char *key);
void aes_128_key_expansion(unsigned char *round_keys, const unsigned char *key);

//int test_aes_128_add_round_key();
int test_aes_128_key_schedule();

#endif /* _AES_128_KEY_SCHEDULE_H_ */