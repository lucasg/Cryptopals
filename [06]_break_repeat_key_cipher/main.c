#include "hamdist.h"
#include "xor.h"
#include "b64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* 
 *	English letter frequencies in count per ten thousand
 */
static const float en_letter_count[] = 
{ 
/*  A,         B,        C,        D,       E,        F,        G,   */
0.0651738,0.0124248,0.0217339, 0.0349835,0.1041442,0.0197881,0.0158610,

/*  H,         I,        J,        K,       L,        M,        N,    */
0.0492888,0.0558094,0.0009033,0.0050529,0.0331490,0.0202124,0.0564513,

/*   O,        P,        Q,        R,       S,        T,       U,     */
0.0596302,0.0137645,0.0008606,0.0497563,0.0515760,0.0729357,0.0225134,

/*   V,        W,        X,       Y,         Z,      Space,      Other */ 
0.0082903,0.0171272, 0.0013692,0.0145984,0.0007836, 0.1918182, 0.0651738

};

/* 
 *  Hamming distance score data structure for comparison
 */
struct key_hscore
{
	unsigned int key;
	float score;
};

/* 
 *  Comparison function used in the Hamming distance test
 */
int hscore_compare (const void *a, const void *b)
{
	/* 4-decimal 'accuracy' */
	return 1000*(((struct key_hscore*)a) -> score - ((struct key_hscore*)b ) -> score);
}

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
	(*contents)[*contents_size]=0; // Add terminating zero.

	/* Close the file */
	fclose(stream);

	return 0x1;
}

/*
 *  Estimate the single key character used to encrypt the line, 
 *  based on the ciphertexts's letters frequencies.
 */
unsigned char detect_key_single_line(char *lencdata, size_t llen)
{
	int i, c;
	unsigned char retv, img;
	float letter_count[26 + 2], score, min_score;

	min_score = 0;

	for (c = 0x00; c < 0x100; c++)
	{
		memset(letter_count, 0, sizeof(letter_count));

		/* Letter frequency */
		for (i = 0; i < llen; i++)
		{
			img = lencdata[i] ^ c;
			if ( img <= 'z' && img >= 'a') 
				letter_count[img - 'a'] += 1;
			else if (img <= 'Z' && img >= 'A') 
				letter_count[img - 'A'] += 1;
			else if (img == ' ')
				letter_count[26] += 1;
			else 
				letter_count[27] += 1;
		}

		/* min Square error */
		score = 0;
		for (i = 0; i < 28; i++)
			score += (letter_count[i] - llen*en_letter_count[i]) * (letter_count[i] - llen*en_letter_count[i]);

		if ((!min_score) || (min_score > score))
		{
			min_score = score;
			retv = c;
		}
	}

	return retv;
}


/*
 *  Detect the key length by computing hamming distance on several block
 *  lengths of encrypted data. Return the n-th keysizes with  minimal distances.
 */
unsigned int find_keysize(char* encdat, unsigned int encdatalen, unsigned int* est_keys, unsigned int est_keys_cnt, unsigned int  minkeysize, unsigned int  maxkeysize)
{
	struct key_hscore *hscores;
	hscores =  malloc((maxkeysize-minkeysize)*sizeof(struct key_hscore));
 	if (NULL == hscores)
 	{
 		free(hscores);
 		return 0x2;
 	}
 	memset(hscores, 0, (maxkeysize-minkeysize)*sizeof(struct key_hscore));

	/*
	 * 	Computing and sorting keysizes by Hamming distance scores.
	 */
	unsigned keysize_candidate;
	for(keysize_candidate = minkeysize; keysize_candidate < maxkeysize; keysize_candidate++)
	{
		float hscore = hamdist_keyscore(encdat, encdatalen ,keysize_candidate) +
		           0.5*hamdist_keyscore(encdat, encdatalen, 2*keysize_candidate) +
		           0.5*hamdist_keyscore(encdat, encdatalen, 4*keysize_candidate);
		
		hscores[keysize_candidate - minkeysize].key = keysize_candidate;
		hscores[keysize_candidate - minkeysize].score = hscore;
	}

	qsort((void*) hscores, (maxkeysize-minkeysize), sizeof(struct key_hscore), hscore_compare);


	for (keysize_candidate = 0; keysize_candidate < est_keys_cnt; keysize_candidate++)
	{
		printf("Hamming Distance score for keylen #%d : %lf\n", hscores[keysize_candidate].key, hscores[keysize_candidate].score );
		est_keys[keysize_candidate] = hscores[keysize_candidate].key;
	}

	free(hscores);

	return 0x00;
}



/* 
 *  Use : bin/06.exe encoded.txt > result.txt
 */
int main(int argc, char *argv[])
{
	
	if (argc < 2)
		return 0x1;

	/*
	 *	Contents loading
	 */
	unsigned char *encdata, *tencdata, *decdata;
	size_t b64encdatalen, encdatalen;
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
	 *	Keysize determination
	 */
	unsigned int keysizes[5];
	if (find_keysize((char*) encdata, encdatalen, keysizes, 5, 2, 50))
	{
		free(encdata);
		return 0x2;
	}


 	tencdata =  malloc(encdatalen*sizeof(*encdata));
 	if(NULL == tencdata)
 	{
 		free(encdata);
 		free(decdata);
 		return 0x2;
 	}
 	memset(tencdata, 0, encdatalen*sizeof(*encdata));


	/*
	 *	Decoding attempt
	 */
	unsigned int i,k;
	for (i = 0; i < 5; i++)
	{
		unsigned int blksize = keysizes[i];
		unsigned int blkcount = (int) (encdatalen/(float) blksize);

		printf("\n-----------\nKeylen :%d \n", blksize );
		printf("Blkcount :%d \n-----------\n", blkcount);
		
		/*
	 	 *	Transposition
	 	 */
	 	unsigned int blkidx, charidx;
	 	for(blkidx = 0; blkidx < blkcount; blkidx++)
	 		for (charidx = 0; charidx < blksize; charidx++)
	 			tencdata[charidx*blkcount + blkidx] = encdata[blkidx*blksize+charidx];
	 	

		/*
		 *  Single line detect
		 */
		unsigned char *pkey;
		pkey = malloc((blksize + 1)*sizeof(*pkey));
		if(NULL == pkey)
		{
			free(encdata);
			free(tencdata);
			free(decdata);			
		}



		printf("Key estimate : ");
		for(k = 0; k < blksize; k++)
			pkey[k] = detect_key_single_line((char*) tencdata + k*blkcount, blkcount);
		pkey[blksize] = 0x00;
		printf("%s\n", pkey);

		free(pkey);
	}


	free(tencdata);				
	free(encdata);
	free(decdata);

	return 0;
}