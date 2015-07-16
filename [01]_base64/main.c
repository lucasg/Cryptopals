#include "b64.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/*
 * There is a 0.75 decompression ration between b64 and ascii encodings
 */ 
#define ASCII_WORDCOUNT (3)
#define B64_WORDCOUNT 	(4)


/* 
 * Usage : b64enc.EXEC < input > output
 */
int main(int argc, char *argv[])
{
	char ascii[ASCII_WORDCOUNT]= {0},
		 b64[B64_WORDCOUNT] = {0};

	while (read(STDIN_FILENO, ascii, ASCII_WORDCOUNT))
	{

		b64_encode(b64, ascii, ASCII_WORDCOUNT);

		write(STDOUT_FILENO, b64, B64_WORDCOUNT);


		memset(b64,0, sizeof(b64));
		memset(ascii,0, sizeof(ascii));

	}

	return 0;
}