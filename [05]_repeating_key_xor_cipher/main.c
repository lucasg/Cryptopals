#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* 
 * Use :  vigenere.out KEY < input.txt > output
 */
int main(int argc, char *argv[])
{
	char *key;
	unsigned char decrypted, encrypted;
	size_t key_idx = 0, key_len;

	if(argc < 2)
		return 1;

	key = argv[1];
	key_len = strlen(key);

	while (read(STDIN_FILENO, &decrypted, 1))
	{
		encrypted = decrypted ^ key[key_idx];
		write(STDOUT_FILENO, &encrypted, 1);

		key_idx = (key_idx+1) % key_len;
	}

	return 0x00;
}