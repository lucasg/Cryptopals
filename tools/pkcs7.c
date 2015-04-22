#include "pkcs7.h"
#include <string.h>

/*
 *	Check if the input string has a valid
 *  pkcs7 padding. Return 0 (invalid) or the padding length otherwise 
 */
int pkcs7_validate(const unsigned char *input, unsigned int len)
{
    unsigned char   pad_len = input[len - 1];
    unsigned char *pad_byte = (unsigned char*) input + len - 1;
	
    while( pad_byte >= input + len - pad_len )
    {
        if (*pad_byte != pad_len)
            return 0x00;
        

        pad_byte--;
    }

    return pad_len;
}

/*
 * 	Returns the input len minus the padding
 */
int pkcs7_strip(const unsigned char *input, unsigned int in_len)
{
	unsigned int pad_len = pkcs7_validate(input, in_len);

    return (in_len - pad_len);
}

/*
 * 	If the input srting has a valid pkcs#7 padding, it strips it.
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
void pkcs7_generate(unsigned char *output, const unsigned char *input, unsigned int in_len, unsigned int pad_len)
{
	unsigned int j;
	unsigned char pad_char = pad_len - ( in_len % pad_len);

	memcpy(output, input, in_len*sizeof(char));
	for (j = 0; j < pad_char; j++)
		output[in_len+j] = pad_char;
}


/*
 *	PKCS#7 Padding tool. Can be use to generate, validate and strip pcks#7
 *  compliant paddings.
 */
#ifdef PKCS7_TOOL

#include <sys/stat.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static unsigned char manpage[] = "\n"
"PKCS#7 padding mechanism. \n"
"padding_length can take any value between 1 and 255\n"
"\n"
"Usage:\n"
"   -l : specify the padding length in order to generate the pad"
"	  eg : pcks7 -l padding_length INPUT\n"
"   -v : test if the given input is a correct pcks7 padded string"
"     eg : pcks7 -v INPUT\n"
"   -s : strip a valid input string from its padding"
"     eg : pcks7 -s INPUT\n"
"\n"
"Ex:\n"
"	pcks7 -l 20 \"YELLOW SUBMARINE\" returns \"YELLOW SUBMARINE\x04\x04\x04\x04\"\n"
"	pcks7 -s \"YELLOW SUBMARINE\x04\x04\x04\x04\" returns \"YELLOW SUBMARINE\"\n"
"\n";

static unsigned char incorrect_pcks_len[] = "Incorrect padding length. Please choose a value between 1 and 255\n";
static unsigned char valid_pcks[] = "valid pcks padding";
static unsigned char wrong_pcks[] = "Not a valid pcks padding";


int main (int argc, char *argv[])
{
	int c, validate = 0x00, strip = 0x00;
	int pad_len = 0;

    if (argc < 2)
    {
        printf("%s", manpage);
        return 0x00;
    }

    /*
     *   Option Management
     */
	while ((c = getopt (argc, argv, "vsl:")) != -1)
    {
    	switch (c)
        {
        case 'l':
        	pad_len = (int) atoi(optarg);
        	if (pad_len < 1 || pad_len > 255)
        	{
        		printf("%s\n", incorrect_pcks_len);
        		return 0x1;
        	}
        	break;

        case 'v':
            validate = 1;
            break;

        case 's':
        	strip = 1;
        	break;

        default:
        	printf("%s", manpage);
    		return 0x00;
        }
     }

    /*
     *   Input : either a typed string or a < stdin redirection
     */
    char *input = NULL;
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


    char *output = NULL;
    unsigned int output_len;
    /*
     *   Functions
     */
    if (validate)
    {
        int retval = pkcs7_validate((unsigned char*) input, input_len);
		printf("%s\n", (0!=retval) ?  valid_pcks : wrong_pcks );
    }
    else if (strip)
    {
    	output_len = pkcs7_strip((unsigned char*) input, input_len);
    	write(1, input, output_len);
    }
    else
    {
    	output = malloc((input_len+pad_len)*sizeof(char));
        if (NULL == output)
        {
            if (NULL != input)
                free(input);
            
            return 0x3;
        }
        memset(output, 0, (input_len+pad_len)*sizeof(char));


        pkcs7_generate((unsigned char*) output, (unsigned char*) input, input_len, pad_len);
        write(1, output, pad_len);
    }

    if(argc < optind)
        free(input);

    if (NULL != output)
        free(output);

	return 0x00;
}


#endif /* PKCS7_TOOL */