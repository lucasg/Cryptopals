#include "hex.h"
#include <string.h>


// Convert a [0-9a-fA-f] char symbol into it's hex value
unsigned char hex_decode_ch(char symbol)
{
	if('0'<= symbol && symbol <= '9')
		return symbol-'0';
	else if('a'<= symbol && symbol <= 'f')
		return symbol-'a' + 10;
	else if('A'<= symbol && symbol <= 'F')
		return symbol-'A' + 10;
	else
		return 0;
}

// Convert a char into its [0-9a-fA-f] char symbol representation
unsigned char hex_encode_ch(unsigned char value)
{
	value = value & 0xf;

	if(value < 10)
		return '0' + value;
	else
		return 'a' - 10 + value;
}

/* 
 * Convert a hex-encoded string (symbol range : [0-9a-f]), bining two hex symbol into one char
 * The symstr buffer should be at least twice as long than the hexstr.
 */
void hex_decode(int *hexstr, const char *symstr, size_t size)
{
	unsigned int i;
	for(i=0; 2*i < size; i++)
		hexstr[i] = (hex_decode_ch(symstr[2*i]) << 4) + hex_decode_ch(symstr[2*i+1]);
}

/*
 * Convert a integer based string into a bi-hex symbols representation, eg 'fa10e8deedbeaf'.
 * The symstr buffer should be at least twice as long than the hexstr. 
 */
void hex_encode(char *symstr, const int *hexstr, size_t size)
{
	unsigned int i;
	for(i=0; 2*i < size; i++)
	{
		symstr[2*i  ] = (char) hex_encode_ch(hexstr[i] >> 4);
		symstr[2*i+1] = (char) hex_encode_ch(hexstr[i]) ;
 	}
}

/* 
 * Convert a hex-encoded string (symbol range : [0-9a-f]), bining two hex symbol into one char
 * The symstr buffer should be at least twice as long than the hexstr.
 */
void hex_decode_c(char *hexstr, const char *symstr, size_t hsize)
{
	unsigned int i;
	for(i=0; 2*i < hsize; i++)
		hexstr[i] = (hex_decode_ch(symstr[2*i]) << 4) + hex_decode_ch(symstr[2*i+1]);
}

/*
 * Convert a integer based string into a bi-hex symbols representation, eg 'fa10e8deedbeaf'.
 * The symstr buffer should be at least twice as long than the hexstr. 
 */
void hex_encode_c(char *symstr, const char *hexstr, size_t hsize)
{
	unsigned int i;
	for(i=0; 2*i < hsize; i++)
	{
		symstr[2*i  ] = (char) hex_encode_ch(hexstr[i] >> 4);
		symstr[2*i+1] = (char) hex_encode_ch(hexstr[i]);
 	}
}



unsigned int hex_roundtrip_test()
{
	char symbol[] = "deadbeef", output[9] = {0};
	int  intarr[4] = {0};


	hex_decode(intarr, symbol, 4);
	hex_encode(output, intarr, 4);


	return !strcmp((char*) symbol, (char*)  intarr);
}