#include "../tools/b64.h"
#include "../tools/aes_128/aes_128.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const static char ciphertext_folder[] = "ctexts";
const static char* const plaintexts[] = {"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
										  "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
										  "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
										  "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
										  "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
										  "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
										  "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
										  "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
										  "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
										  "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
										  "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
										  "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
										  "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
										  "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
										  "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
										  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
										  "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
										  "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
										  "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
										  "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
										  "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
										  "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
										  "U2hlIHJvZGUgdG8gaGFycmllcnM/",
										  "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
										  "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
										  "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
										  "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
										  "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
										  "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
										  "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
										  "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
										  "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
										  "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
										  "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
										  "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
										  "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
										  "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
										  "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
										  "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
										  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
										  NULL};


/*
 *  Random key and IV.
 *  Init once per session
 */ 
static unsigned char rkey[16] = {0};
static uint64_t nonce = 0;

/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_rkey()
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) rkey)[i] = rand();
}


/*
 * Encrypt an arbitrary input string under AES-CTR
 */
size_t encrypt(unsigned char **output, const unsigned char *input, size_t input_len)
{
	unsigned char *tmp;
	size_t output_len , b64_decoded_len;

	output_len = b64_get_ascii_wc(input_len);
/*	if (output_len % aes_128_block_len)
		output_len += (aes_128_block_len - (output_len % aes_128_block_len));*/

	tmp = malloc((output_len)*sizeof(char));
	if (NULL == tmp)
		return 0x00;

	
	*output = malloc((output_len)*sizeof(char));
	if (NULL == *output)
	{
		free(tmp);
		return 0x00;
	}

	memset(tmp, 0, (output_len)*sizeof(char));
	memset(*output, 0, (output_len)*sizeof(char));

	b64_decoded_len = b64_decode((char*)tmp, (char*)input, input_len);
	output_len = aes_128_encrypt_msg(*output, tmp, b64_decoded_len, rkey, CTR, (const union aes_128_init*) &nonce);

	free(tmp);

	return output_len;
}

char *get_ctext_file_path(size_t i)
{
	char *output;
	size_t output_len;

	//					ciphertext_folder    /  XX 
	output_len = strlen(ciphertext_folder) + 2 + 2;

	output = malloc((output_len + 1)*sizeof(char));
	if (NULL == output)
		return NULL;
	 

	snprintf(output, output_len, "%s/%02d", ciphertext_folder, i);
	output[output_len] = 0x01;

	return output;
}


/*
 * Encrypt every plaintext using the same keystream and save the ciphertexts in folder ctext
 */
int main(int argc, char *argv[])
{
	size_t i, ctext_len;
	unsigned char *ctext; 
	char *ctext_fp;
	FILE *fd;


	i = 0;
	while (NULL != plaintexts[i])
	{
		printf("Encrypting plaintext n.%02d\n", i);
		ctext_len = encrypt(&ctext, (unsigned char *) plaintexts[i], strlen(plaintexts[i]));
		if (!ctext_len)
			return 0x01;

		ctext_fp = get_ctext_file_path(i);
		if (NULL == ctext_fp)
			return 0x02;

		fd = fopen(ctext_fp, "wb");
		if (NULL == fd)
			return 0x03;

		fwrite(ctext, sizeof(char), ctext_len, fd);

		fclose(fd);
		free(ctext_fp);
		free(ctext);

		i++;
	}

	return 0x00;
}