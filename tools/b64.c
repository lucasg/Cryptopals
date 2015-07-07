#include "b64.h"
#include <stdio.h>
#include <unistd.h>

/*
 * Compute the resulting base64 word count, with padding
 */
size_t b64_get_b64_wc(size_t ascii_wc)
{
	size_t ascii_pwc = ascii_wc;
	if (ascii_wc%3)
		ascii_pwc+=( 3 - (ascii_wc%3) );

	return ascii_pwc*4 / 3;
}


/*
 * Compute the resulting ascii word count
 */
size_t b64_get_ascii_wc(size_t b64_wc)
{
	size_t ascii_bc = b64_wc*6; 

	if (ascii_bc % 8)
		ascii_bc += (8 - (ascii_bc % 8));

	return ascii_bc / 8;
}

/* Passing from 6-bit words to 8-bit word encoding
 *  	-> deflation of symbols used to encode the same information
 */
void hex_deflate(char *dstbuf, const  char *srcbuf, size_t dst_wordcount, size_t src_wordcount)
{
	// array sizes mismatch
	if (dst_wordcount*8  < src_wordcount*6)
		return;

	unsigned int i= 0,blk = 0;

	while(blk < src_wordcount)
	{
		int32_t word = 0;
		for (i=0; i<4;i++)
			word = (word << 6) + srcbuf[i];

		for (i=0; i<3;i++)
		{
			dstbuf[2-i] = (word & 0xff);
			word >>= 8;
		}

		blk+=4;
		srcbuf += 4;
		dstbuf += 3;
	}
}

/* Passing from 8-bit words to 6-bit word encoding
 *	 -> inflation of symbols used to encode the same information
 */
void hex_inflate(char *dstbuf, const  char *srcbuf, size_t dst_wordcount, size_t src_wordcount)
{
	// array sizes mismatch
	if (dst_wordcount*6  < src_wordcount*8)
		return;


	unsigned int i,j = 0;
	while(j < src_wordcount)
	{
		int32_t word = 0;
		for (i=0; i<3;i++)
			word = (word << 8) + srcbuf[i];
		

		for (i=0; i<4;i++)
		{
			dstbuf[3-i] = (word & 0x3f);
			word >>= 6;
		}

		j +=3;
		srcbuf += 3;
		dstbuf += 4;
	}
}


/* 
 *	ascii to base64
 */
size_t b64_encode(char *b64, const char *ascii, size_t ascii_wc)
{
	size_t b64_wc = b64_get_b64_wc(ascii_wc);

	// 6-bit expand
	hex_inflate(b64, ascii, b64_wc, ascii_wc);

	
	// Convert base64 ascii representation to actual value 
	unsigned int i;
	for (i =0; i < b64_wc; i++)
	{
		unsigned short b64_val = b64[i];

		if (!b64_val) // padding
			b64[i] = '=';
		else if (b64_val < 26)
			b64[i] = b64_val + 65; // A-Z
		else if(b64_val < 52)
			b64[i] = b64_val + 71; // a-z
		else if(b64_val < 62)
			b64[i] = b64_val - 4; // 0-9
		else // specials
		{	
			if(62 == b64_val)
				b64[i] = '+';
			else if(63 == b64_val)
				b64[i] = '/';
			else // padding
				b64[i] = '=';
		}

		
	}

	return b64_wc;
}

/* 
 * base64 to ascii
 */
size_t b64_decode(char *ascii, const  char *b64, size_t b64_wc)
{
	char *b64enc_cpy;
	size_t ascii_len = 0;
	size_t ascii_wc = b64_get_ascii_wc(b64_wc);

	b64enc_cpy = malloc(b64_wc*sizeof(char));
	if(NULL == b64enc_cpy)
		return 0x00;

	// Convert symbols to base64 ascii representation
	unsigned int i;
	for (i =0; i < b64_wc; i++)
	{
		unsigned short b64_val = b64[i];

		if(b64_val < 58 && b64_val >= 48)
			b64enc_cpy[i] = b64_val + 4; // 0-9
		else if(b64_val < 91 && b64_val >= 65)
			b64enc_cpy[i] = b64_val - 65; // A-Z
		else if(b64_val < 123 && b64_val >= 97)
			b64enc_cpy[i] = b64_val - 71; // a-z
		else // specials
		{	
			if('+' == b64_val)
				b64enc_cpy[i] = 62;
			else if('/' == b64_val)
				b64enc_cpy[i] = 63;
			else  // padding
				b64enc_cpy[i] = 0x00;
		}

		if ('=' != b64_val)
			ascii_len++;
	}

	// 6-bit compression
	hex_deflate(ascii, b64enc_cpy, ascii_wc, b64_wc);

	free(b64enc_cpy);

	return b64_get_ascii_wc(ascii_len);
}


#ifdef TEST
/* 
 * Simple unit test which is here to ensure we didn't break anything.
 */
unsigned int b64_roundtrip_test()
{
	unsigned int i, err_cnt = 0;
	char src_buf[] = "aZ+b87kC9", img_buf[13]={0}, rdtrip_buf[13]={0};
	
	

	b64_encode(img_buf, src_buf, b64_get_b64_wc(9) );
	b64_decode(rdtrip_buf, img_buf, 9);

	for(i = 0; i < 9; i++)
		err_cnt += (rdtrip_buf[i] != src_buf[i]);

	if(err_cnt)
	{
		printf("src : %s\n", src_buf );
		printf("img : %s\n", img_buf );
		printf("rdtrip : %s\n", rdtrip_buf );
	}

	return err_cnt;
}
#endif /* TEST */

/*
 *	Base 64 tool. Can be used to encode and decode base64 string
 */
#ifdef B64_TOOL

#include <sys/stat.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static unsigned char manpage[] = "\n"
"Base64 codec tool. \n"
"\n"
"Usage:\n"
"   -e : specify to encode the input"
"	  eg : b64 -e INPUT\n"
"   -d : specify to decode the input"
"     eg : b64 -d INPUT\n"
"\n"
"Ex:\n"
"	b64 -e \"Hello World\" returns \"SGVsbG8gV29ybGQ=\"\n"
"	b64 -d \"SGVsbG8gV29ybGQ=\" returns \"Hello World\"\n"
"\n";

static unsigned char invalid_options[] = "encode and decode option can't be both activated";


int main (int argc, char *argv[])
{
	int c, encode = 0x00, decode = 0x00;


    /*
     *   Option Management
     */
	while ((c = getopt (argc, argv, ":de")) != -1)
	{
		switch (c)
	    {
	    case 'e':
	    	encode = 0x01;
	    	break;

	    case 'd':
	        decode = 0x01;
	        break;

	    default:
	    	printf("%s", manpage);
			return 0x00;
	    }
	}

    if (encode && decode)
    {
    	printf("%s", invalid_options);
    	return 0x01;
    }


    /*
     *   Input : either a typed string or a < stdin redirection
     */
    char *input;
    unsigned int input_len;

    if(argc > optind)
    {
        input = argv[optind];
        input_len = strlen(input);
    }
    else
    {
        int fd = STDIN_FILENO;
        struct stat st;
        if (fstat (fd, &st) != 0)
            return 0x2;
        input_len = st.st_size;
        
        input = malloc((input_len+1)*sizeof(char));
        if (NULL == input)
            return 0x3;

        fread(input, sizeof(char), input_len, stdin );
        input[input_len] = '\0';
    }



    char *output;
    /*
     *   Functions
     */
    if (encode)
    {
    	unsigned int output_len = b64_get_b64_wc(input_len);
    	
    	output = malloc((output_len + 1)*sizeof(char));
        if (NULL == output)
            return 0x3;
        memset(output, 0, (output_len + 1)*sizeof(char));

        b64_encode(output, input, input_len); 
        printf("%s\n", output);
    }
    else
    {
    	unsigned int output_len = b64_get_ascii_wc(input_len);
    	
    	output = malloc((output_len + 1)*sizeof(char));
        if (NULL == output)
            return 0x3;
        memset(output, 0, (output_len + 1)*sizeof(char));

        b64_decode(output, input, input_len); 
    	write(1, output, output_len);
    }

  


    if(argc < optind)
        free(input);
    
    free(output);
	return 0x00;
}


#endif /* B64_TOOL */