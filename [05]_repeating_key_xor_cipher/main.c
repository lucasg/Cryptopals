#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// Use :  vigenere.out KEY < input.txt > output
int main(int argc, char *argv[])
{
	if(argc < 2)
		return 1;

	char *key = argv[1];
	unsigned int key_idx = 0, key_len = strlen(key);

	unsigned char dchar,echar;
	while(read(0,&dchar,1))
	{
		echar = dchar ^ key[key_idx];
		write(1, &echar,1 );
		key_idx = (key_idx+1) % key_len;
	}

	return 0;
}