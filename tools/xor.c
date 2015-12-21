#include "xor.h"
#include <stdio.h>

void xor_decode(unsigned char* dec, const unsigned char* enc, size_t len, const unsigned char* key, size_t keylen)
{
	/* symetrical properties of xor. */
	xor_encode(dec, enc, len, key, keylen);
}

void xor_encode(unsigned char* enc, const unsigned char* dec, size_t len, const unsigned char* key, size_t keylen)
{
	unsigned int i = 0;

	while(i < len)
	{
		enc[i] = dec[i] ^ key[i % keylen];
		/* printf("0x%x ^ 0x%x -> 0x%x \n", dec[i] , key[i % keylen], enc[i] ); */
		i++;
	}
}

void xor_decode_uint(unsigned int* dec, const unsigned int* enc, size_t len, const unsigned int* key, size_t keylen)
{
	/* symetrical properties of xor. */
	xor_encode_uint(dec, enc, len, key, keylen);
}

void xor_encode_uint(unsigned int* enc, const unsigned int* dec, size_t len, const unsigned int* key, size_t keylen)
{
	unsigned int i = 0;

	while(i < len)
	{
		enc[i] = dec[i] ^ key[i % keylen];
		i++;
	}
}


void caesar_encode(unsigned char* enc, const unsigned char* dec, size_t len, unsigned char key)
{
	xor_encode(enc, dec, len, &key, 1);
}

void caesar_decode(unsigned char* dec, const unsigned char* enc, size_t len, unsigned char key)
{
	xor_decode(dec, enc, len, &key, 1);
}



void caesar_encode_uint(unsigned int* enc, const unsigned int* dec, size_t len, unsigned int key)
{
	xor_encode_uint(enc, dec, len, &key, 1);
}

void caesar_decode_uint(unsigned int* dec, const unsigned int* enc, size_t len, unsigned int key)
{
	xor_decode_uint(dec, enc, len, &key, 1);
}



static const unsigned char password[4] = "pa$$";
static const unsigned char plaintext_c[14] = "attack at dawn";
static const unsigned int  plaintext_i[14] = {'a','t','t','a','c','k',' ','a','t',' ','d','a','w','n'};


unsigned int xor_roundtrip_test()
{
	unsigned int i, err_count;

	unsigned char ciphertext_c[14], rtriptext_c[14];
	unsigned int  ciphertext_i[14], rtriptext_i[14];

	xor_encode(ciphertext_c, plaintext_c, 14, password, 4 );
	xor_decode(rtriptext_c, ciphertext_c, 14, password, 4 );

	xor_encode_uint(ciphertext_i, plaintext_i, 14, (unsigned int*) password, 4 );
	xor_decode_uint(rtriptext_i, ciphertext_i, 14, (unsigned int*) password, 4 );


	for(i = 0; i < 14; i++)
	{
		err_count += (rtriptext_c[i] != ciphertext_c[i]);
		err_count += 100*(rtriptext_i[i] != ciphertext_i[i]);
	}

	return err_count;
}

unsigned int caesar_roundtrip_test()
{
	unsigned int i, err_count;

	unsigned char ciphertext_c[14], rtriptext_c[14];
	unsigned int  ciphertext_i[14], rtriptext_i[14];

	/* ROT-13 encoding scheme */
	caesar_encode(ciphertext_c, plaintext_c, 14, 13 );
	caesar_decode(rtriptext_c, ciphertext_c, 14, 13 );

	/* also ROT-13 encoding scheme */
	caesar_encode_uint(ciphertext_i, plaintext_i, 14, 13 );
	caesar_decode_uint(rtriptext_i, ciphertext_i, 14, 13 );

	for(i = 0; i < 14; i++)
	{
		err_count += (rtriptext_c[i] != ciphertext_c[i]);
		err_count += 100*(rtriptext_i[i] != ciphertext_i[i]);
	}

	return err_count;
}