#include "xor.h"
#include "hex.h"
#include "ifreq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 *   Load the next line of the filestream
 */
size_t loadline(FILE *fstream, char* *contents, size_t *contents_size)
{
#ifdef WIN32
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
#elif defined(linux) //_POSIX_C_SOURCE >= 200809L || _XOPEN_SOURCE >= 700
	return getline(contents, contents_size, fstream);
#else
	return 0;
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
	FILE* edatfd = fopen(filename/*argv[1]*/, "rb");


	unsigned char *edatl = NULL, *ddatl = NULL;
	unsigned char *hexencl = NULL, *hexdecl= NULL;
	size_t edatllen = 0, linelen, hexlen;

	unsigned int lidx = 0;

	
	while(-1 != loadline(edatfd,(char **) &edatl, &edatllen))
	{
		linelen = strlen((char*)edatl) - 1;
		hexlen = linelen/2;
		
		// Fixed-length texts hypothesis here
		if (!lidx)
		{
			hexencl = malloc(hexlen*sizeof(char));
			if(NULL == hexencl)
			{
				free(edatl);
				return 0x2;
			}

			hexdecl = malloc(hexlen*sizeof(char));
			if(NULL == hexdecl)
			{
				free(edatl);
				free(hexencl);
				return 0x2;
			}

			ddatl = malloc((1+hexlen)*sizeof(char));
			if(NULL == ddatl)
			{
				free(edatl);
				free(hexdecl);
				free(hexencl);
				return 0x2;
			}
		}

		
		memset(hexencl,0, hexlen*sizeof(char));
		memset(hexdecl,0, hexlen*sizeof(char));
		memset(ddatl,0, (1+hexlen)*sizeof(char));

		
		/*
		 *  Decoding each line with the most probable key
		 */
		hex_decode((char*) hexencl, (char*) edatl, linelen);
		decode_single_line(hexdecl, hexencl, hexlen);
		

		/*
		 *  Convert to printable characters.
		 */
		unsigned int i,j = 0;
		for (i = 0; i < hexlen ;i++)
		{
			ddatl[i] = (char) hexdecl[i];

			// test if it's a 'printable' char
			j += (' '<=hexdecl[i] && hexdecl[i]<='}') + (hexdecl[i]=='\t') + (hexdecl[i]=='\n');
		}
		
		if (j == hexlen)
			printf("%d - %d : %s\n", lidx + 1, j, (char*) ddatl );

		
		lidx++;
	}


	free(edatl);
	free(ddatl);
	free(hexencl);
	free(hexdecl);

	
	return 0x0;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return 0x1;

	return detect(argv[1]);
}