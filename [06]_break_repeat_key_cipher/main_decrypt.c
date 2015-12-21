#include "../tools/b64.h"
#include "../tools/xor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/*
 *   Load the next line of the filestream
 */
unsigned load_file(char *fd_stream,	char **contents, size_t *contents_size)
{
	FILE *stream;
	unsigned int fileSize = 0;
	void *p;

	/* Open the stream. Note "b" to avoid DOS/UNIX new line conversion. */
	stream = fopen(fd_stream, "rb");

	/* Seek to the end of the file to determine the file size */
	fseek(stream, 0L, SEEK_END);
	fileSize = ftell(stream);
	fseek(stream, 0L, SEEK_SET);

	/* Allocate enough memory (add 1 for the \0, since fread won't add it) */
	p = malloc(fileSize+1);
	if( NULL == p)
		return 0x00;
	(*contents) = (char*) p;

	/* Read the file */
	*contents_size=fread((*contents),1,fileSize,stream) + 1;
	(*contents)[*contents_size]=0; /* Add terminating zero. */

	/*Close the file */
	fclose(stream);

	return 0x1;
}


int main(int argc, char *argv[])
{
	unsigned char *encdata, *decdata;
	size_t b64encdatalen, encdatalen;
	
	if (argc < 3)
		return 0x1;

	/*
	 *	Contents loading
	 */
	if (!load_file( argv[1], (char **) &encdata, &b64encdatalen))
	{
		free(encdata);
		return 0x2;
	}
	encdatalen = 1 + b64_get_ascii_wc(b64encdatalen);

	decdata =  malloc(encdatalen*sizeof(*encdata));
 	if(NULL == decdata)
 	{
 		free(encdata);
 		return 0x2;
 	}
 	memset(decdata, 0, encdatalen*sizeof(*encdata));

 	/*
 	 *  Base64 decoding
 	 */
 	b64_decode((char*) decdata, (char*) encdata, b64encdatalen);
 	memcpy(encdata, decdata, (encdatalen - 1)*sizeof(*encdata));
 	encdata[encdatalen] = '\0';
 	memset(decdata, 0, encdatalen*sizeof(*encdata));


 	/*
 	 * Vigenere decoding using user key
 	 */
 	xor_decode( decdata, encdata, encdatalen, (unsigned char*) argv[2], strlen(argv[2]));
 	write(1,decdata, encdatalen);


 	return 0;
 }
