#ifndef _HEX_H_
	#define _HEX_H_

#include <stdlib.h>


/* 
 * Convert a hex-encoded string (symbol range : [0-9a-f]), bining two hex symbol into one integer
 * The symstr buffer should be at least twice as long than the hexstr.
 */
void hex_decode(char *hexstr, const char *symstr, size_t symsize);

/*
 * Convert a integer based string into a bi-hex symbols representation, eg 'fa10e8deedbeaf'.
 * The symstr buffer should be at least twice as long than the hexstr. 
 */
void hex_encode(char *symstr, const char *hexstr, size_t symsize);

#ifdef TEST
	/*
	 * Simple Unit Test
	 */
	unsigned int hex_roundtrip_test();
#endif /* TEST */

#endif /* _HEX_H_ */