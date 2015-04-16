#include "target.h"
#include "mt19937.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>	

unsigned int test_mt_cipher(const uint8_t *ctext, const uint8_t *ptext, const size_t len, const uint32_t seed)
{
	unsigned int i = 0;
	struct mt19937_t test_mt;

	mt19937_init( &test_mt, seed);
	while (i < len)
	{
		if ((ctext[i] ^ ((uint8_t) mt19937_get_value(&test_mt))) != ptext[i])
			return 0x00;

		i++;
	}


	return 0x01;
}

int main(int argc, char *argv[])
{
	const char known_ptext[] = "AAAAAAAAAAAAAA";
    uint8_t *ctext;
	size_t ctext_len, rand_prefix_len;
	uint32_t encrypt_call_time, current_time, t;
	struct mt19937_t mt_gen;
	unsigned int i;

	encrypt_call_time = time(NULL);
	ctext_len = encrypt(&ctext, (const uint8_t*) known_ptext, strlen(known_ptext));
	if (!ctext_len)
		return 0x01;

	rand_prefix_len = ctext_len - strlen(known_ptext);
	current_time = time(NULL);


	for (t = current_time; t >= encrypt_call_time; t--)
	{
		if (test_mt_cipher(ctext + rand_prefix_len, (const uint8_t*) known_ptext, strlen(known_ptext), t))
		{
			printf("MT19937 seed generator found : %d\n", t);
		

			printf("Keystream : ");
			mt19937_init( &mt_gen, t);
			for (i = 0; i < strlen(known_ptext); i++)
				printf("%02x:", (uint8_t) mt19937_get_value(&mt_gen));
			printf("\n");

			break;
		}
		
	}

	if ( encrypt_call_time > t)
		printf("The cipher does not seemed to use a MT19937 generator seeded with the current timestamp\n");

	free(ctext);
	return 0x00;
}