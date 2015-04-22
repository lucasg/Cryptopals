#include "sha1_utils.h"
#include "sha1.h"
#include <stdio.h>
#include <string.h>

void sha1_utils_print_array(uint8_t* array, size_t array_len, unsigned int swap_endianess)
{
	int i;
	for (i=0; i<array_len; i++) {
		if (SWAP_ENDIAN == swap_endianess)
			printf("/x%02x", array[i ^ 3]);
		else
			printf("/x%02x", array[i]);
	}
	printf("\n");
}

void sha1_utils_printHash(uint8_t* hash) {
	sha1_utils_print_array(hash, 20, 0x00);
}

void sha1_utils_keyed_mac(uint8_t hash[], const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen)
{
	struct sha1nfo s;
	sha1_init(&s);
	
	sha1_write(&s, (char*) key, keylen);
	sha1_write(&s, (char*) msg, msglen);

	memcpy(hash, sha1_result(&s), SHA1_HASH_LENGTH*sizeof(uint8_t));
}

void sha1_utils_md_pad(uint8_t *padded, size_t *paddedlen, const uint8_t* msg, size_t msglen)
{
	size_t ch_index;
	
	padded[0] = 0x80;

	// pad with zeros
	ch_index = 1;
	while ((ch_index + msglen + 8) % SHA1_BLOCK_LENGTH)
	{
		padded[ch_index] = 0x00;
		ch_index++;
	}

	padded[ch_index++] = 0;
	padded[ch_index++] = 0; // But SHA-1 supports 64 bit lengths
	padded[ch_index++] = 0; // So zero pad the top bits
	padded[ch_index++] = msglen >> 29;
	padded[ch_index++] = msglen >> 21;
	padded[ch_index++] = msglen >> 13;
	padded[ch_index++] = msglen >> 5;
	padded[ch_index++] = msglen << 3;
	
	*paddedlen = ch_index;
}

void sha1_utils_concat(uint8_t *output, const uint8_t* str1, size_t str1len, const uint8_t* str2, size_t str2len)
{
	size_t i;

	for (i = 0; i < str1len; i++)
		output[i] = str1[i];

	for (i = 0; i < str2len; i++)
		output[(str1len + i)] = str2[i];
}

void sha1_utils_test_pad()
{
	uint8_t padtest[2*SHA1_BLOCK_LENGTH], padtestconcat[3*SHA1_BLOCK_LENGTH];
	size_t padtestlen;

	printf("Test: Padding mechanism\n");
	printf("Expect:/x61/x62/x63/x80/x00/../x00/x18\n");
	printf("Result:");

	sha1_utils_md_pad(padtest, &padtestlen, (uint8_t*) "abc", 3);
	sha1_utils_concat(padtestconcat, (uint8_t*) "abc", 3, padtest, padtestlen );
	sha1_utils_print_array(padtestconcat, 3 + padtestlen, 0);
	printf("\n");

	printf("Expect:/x30/x31/x32/x33/x34/x35/x36/x37/x80/x00/x00/.../x00/x40/\n");
	printf("Result:");

	sha1_utils_md_pad(padtest, &padtestlen, (uint8_t*) "01234567", 8);
	sha1_utils_concat(padtestconcat, (uint8_t*) "01234567", 8, padtest, padtestlen);
	sha1_utils_print_array(padtestconcat, 8 + padtestlen, 0);
	printf("\n\n");
}