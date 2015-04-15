#include <sys/stat.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static unsigned char manpage[] = "\n"
"PKCS#7 padding mechanism. \n"
"padding_length can take any value between 1 and 255\n"
"\n"
"Usage:\n"
"   -i : input file"
"     eg : pcks7 -i input_file\n"
"   -l : specify the padding length in order to generate the pad"
"	  eg : pcks7 -l padding_length INPUT\n"
"   -v : test if the given input is a correct pcks7 padded string"
"     eg : pcks7 -v INPUT\n"
"\n"
"Ex:\n"
"	pcks7 -l 20 YELLOW SUBMARINE returns YELLOW SUBMARINE\x04\x04\x04\x04\n"
"\n";

static unsigned char incorrect_pcks_len[] = "Incorrect padding length. Please choose a value between 1 and 255\n";
static unsigned char valid_pcks[] = "valid pcks padding";
static unsigned char wrong_pcks[] = "Not a valid pcks padding";

int validate_pcks(const unsigned char *input)
{
    unsigned int msg_len = strlen((char*) input);
    unsigned char pad_len = input[msg_len - 1];

    unsigned char *pad_byte = ((unsigned char*)input) + msg_len - 1;
    while( pad_byte > input + msg_len - pad_len )
    {
        if (*pad_byte != pad_len)
            return 0x00;
        

        pad_byte--;
    }

    return 0x1;
}

void generate_pcks(const unsigned char *input, const unsigned char pad_len)
{
    unsigned int j, msg_len = strlen((char *) input);

    write(1, input, msg_len);

    unsigned char v = pad_len - ( msg_len % pad_len);
    for (j = 0; j < v; j++)
    {
        write(1, &v, 1);            
    }

    char null_byte = 0x00;
    write(1, &null_byte, 1);            
}

int main (int argc, char *argv[])
{
	int c, validate = 0x00;
	int pad_len = 0;


    /*
     *   Option Management
     */
	while ((c = getopt (argc, argv, "vl:")) != -1)
	switch (c)
    {
    case 'l':
    	pad_len = (int) atoi(optarg);
    	if (pad_len < 1 || pad_len > 255)
    	{
    		write(1, incorrect_pcks_len, strlen((char*)incorrect_pcks_len));
    		return 0x1;
    	}
    	break;

    case 'v':
        validate = 1;
        break;

    default:
    	printf("%s", manpage);
		return 0x00;
    }


    /*
     *   Input Management
     */
    char *input;
    if(argc > optind)
        input = argv[optind];
    else
    {
        int fd = STDIN_FILENO;
        struct stat st;
        if (fstat (fd, &st) != 0)
            return 0x2;
        
        input = malloc((st.st_size+1)*sizeof(char));
        if (NULL == input)
            return 0x3;

        fread(input, sizeof(char), st.st_size,stdin );
        input[st.st_size] = '\0';
    }


    /*
     *   Functions Management
     */
    if (validate)
    {
        int retval = validate_pcks((unsigned char*) input);

        if (retval)
            write(1, valid_pcks, strlen((char*) valid_pcks));
        else
            write(1, wrong_pcks, strlen((char*) wrong_pcks));
    }
    else
    {
        generate_pcks((unsigned char*) input, pad_len);
    }

	return 0x00;
}