#include "xor.h"
#include "hex.h"
#include "ifreq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 *   Load the next line of the filestream
 */
size_t loadline(FILE *fstream, char* *contents, size_t *contents_size)
{
#if defined(_WIN32) || defined(WIN32) || defined (__CYGWIN__)
	char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (contents == NULL) {
    	return -1;
    }
    if (fstream == NULL) {
    	return -1;
    }
    if (contents_size == NULL) {
    	return -1;
    }
    bufptr = *contents;
    size = *contents_size;

    c = fgetc(fstream);
    if (c == EOF) {
    	return -1;
    }
    if (bufptr == NULL) {
    	bufptr = malloc(128);
    	if (bufptr == NULL) {
    		return -1;
    	}
    	size = 128;
    }
    p = bufptr;
    while(c != EOF) {
    	if ((p - bufptr) > (size - 1)) {
    		size = size + 128;
    		bufptr = realloc(bufptr, size);
    		if (bufptr == NULL) {
    			return -1;
    		}
    	}
    	*p++ = c;
    	if (c == '\n') {
    		break;
    	}
    	c = fgetc(fstream);
    }

    *p++ = '\0';
    *contents = bufptr;
    *contents_size = size;

    return p - bufptr - 1;
#elif defined(linux) /*_POSIX_C_SOURCE >= 200809L || _XOPEN_SOURCE >= 700 */
	return getline(contents, contents_size, fstream);
#else
	return 0x00;
#endif

}

/*
 *   Detect the key in a continous string (without 0xa) by simply counting letters
 *   and returning the most frequent one
 */
unsigned char detect_key_single_line(unsigned char *lencdata, size_t llen)
{
	unsigned char retv;
	int* tmp, i;

	tmp = malloc(llen*sizeof(int));
	if (NULL == tmp)
		return 0x00;

	for (i=0; i < llen; i++)
		tmp[i] = lencdata[i];

	ifreq( tmp, NULL, llen);

	retv = tmp[0];
	free(tmp);

	return (unsigned char) retv;
}


/*
 *  Decrypt ciphertext by xor'ing it against the most frequent char,
 *	assuming it's ' '.
 */
void decode_single_line(unsigned char *ldecdata, unsigned char *lencdata, size_t llen )
{
	unsigned char most_frequent_char = detect_key_single_line(lencdata, llen);
	caesar_decode(ldecdata, lencdata, llen,  ' ' ^  most_frequent_char);
}



/*
 * 	 Use : ./detect encrypted.txt > decrypted.txt
 */
int detect(const char *filename)
{
	int lidx = 0;
	FILE* edatfd = NULL;
	unsigned char *edatl = NULL,
				  *ddatl = NULL,
				  *hexencl = NULL,
				  *hexdecl= NULL;
	size_t edatllen = 0, linelength, hexlen;
	size_t i, print_char_count = 0;


	edatfd = fopen(filename, "rb");
	if (NULL == edatfd)
	{
		printf("Error when calling fopen(%s) : %s\n", filename, strerror(errno));
		return errno;
	}

	while(-1 != loadline(edatfd,(char **) &edatl, &edatllen))
	{
		if (NULL == edatl)
			goto cleanup;

		linelength = strlen((char*)edatl) - 1;
		hexlen = linelength/2;
		
		/* Fixed-length texts hypothesis here */
		if (!lidx)
		{
			hexencl = malloc(hexlen);
			if(NULL == hexencl)
				goto cleanup;

			hexdecl = malloc(hexlen);
			if(NULL == hexdecl)
				goto cleanup;

			ddatl = malloc((1+hexlen));
			if(NULL == ddatl)
				goto cleanup;
		}

		
		memset(hexencl,0, hexlen);
		memset(hexdecl,0, hexlen);
		memset(ddatl,0, 1+hexlen);

		
		/*
		 *  Decoding each line with the most probable key
		 */
		hex_decode((char*) hexencl, (char*) edatl, linelength);
		decode_single_line(hexdecl, hexencl, hexlen);
		

		/*
		 *  Convert to printable characters.
		 */
		print_char_count = 0;
		for (i = 0; i < hexlen ;i++)
		{
			ddatl[i] = (char) hexdecl[i];

			/* test if it's a printable char */
			print_char_count += (' '<=hexdecl[i] && hexdecl[i]<='}') + (hexdecl[i]=='\t') + (hexdecl[i]=='\n');
		}
		
		if (print_char_count == hexlen)
			printf("%d - %d : %s\n", lidx + 1, print_char_count, (char*) ddatl );

		
		lidx++;
	}

cleanup:
	if (NULL != edatl)
		free(edatl);
	if (NULL != ddatl)
		free(ddatl);
	if (NULL != hexencl)
		free(hexencl);
	if (NULL != hexdecl)
		free(hexdecl);

	
	return 0x0;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return 0x1;

	return detect(argv[1]);
}