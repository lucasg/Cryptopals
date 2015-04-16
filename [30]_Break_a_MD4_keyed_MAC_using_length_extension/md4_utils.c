#include "md4_utils.h"
#include "md4.h"
#include <stdio.h>
#include <string.h>

void md4_utils_print_array(uint8_t* array, size_t array_len, unsigned int swap_endianess)
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

void md4_utils_printHash(uint8_t* hash) {
	md4_utils_print_array(hash, MD4_HASH_LENGTH, 0x00);
}

void md4_utils_keyed_mac(uint8_t hash[], const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen)
{
	struct md4_ctx s;
	md4_init(&s);
	
	md4_write(&s, (char*) key, keylen);
	md4_write(&s, (char*) msg, msglen);

	memcpy(hash, md4_digest(&s), MD4_HASH_LENGTH*sizeof(uint8_t));
}

void md4_utils_md_pad(uint8_t *padded, size_t *paddedlen, const uint8_t* msg, size_t msglen)
{
	size_t ch_index;
	
	padded[0] = 0x80;

	// pad with zeros
	ch_index = 1;
	while ((ch_index + msglen + 8) % MD4_BLOCK_LENGTH)
	{
		padded[ch_index] = 0x00;
		ch_index++;
	}

	// MD4 implementation specify to add the x80 high-bit big-endian style, but the length is little
	// endian (by design, not platform dependant).
	padded[ch_index++] = msglen << 3;
	padded[ch_index++] = msglen >> 5;
	padded[ch_index++] = msglen >> 13;
	padded[ch_index++] = msglen >> 21;
	padded[ch_index++] = msglen >> 29;
	padded[ch_index++] = 0;
	padded[ch_index++] = 0; 
	padded[ch_index++] = 0;
	
	*paddedlen = ch_index;
}

void md4_utils_concat(uint8_t *output, const uint8_t* str1, size_t str1len, const uint8_t* str2, size_t str2len)
{
	size_t i;

	for (i = 0; i < str1len; i++)
		output[i] = str1[i];

	for (i = 0; i < str2len; i++)
		output[(str1len + i)] = str2[i];
}
