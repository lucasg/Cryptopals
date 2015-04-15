#ifndef _B_64_H_
	#define _B_64_H_

#include <stdlib.h>

/*
 * Ascii to base64 encoding
 * The wordcount param is the destination buffer wordcount
 * The b64dec buf should be at least 6/8 times bigger than b64dec
 * Return the b64 word count.
 */
size_t b64_encode(char *b64, const char *ascii, size_t ascii_wc);

/*
 * base64 to ascii
 * The wordcount param is the destination buffer wordcount
 * The b64dec buf should be at least 8/6 times bigger than b64dec
 * 
 * returns the number of "real" char, i.e. the ascii len minus the 
 * possible padding chars.
 */
size_t b64_decode(char *ascii, const  char *b64, size_t b64_wc);


/*
 * Compute the resulting base64 word count, with padding
 * This function is useful to malloc the correct amount 
 * of memory space for the output buffer.
 */
size_t b64_get_b64_wc(size_t ascii_wc);

/*
 * Compute the resulting ascii word count
 * This function is useful to malloc the correct amount 
 * of memory space for the output buffer.
 */
size_t b64_get_ascii_wc(size_t b64_wc);


#ifdef TEST
	unsigned int b64_roundtrip_test();
#endif /* TEST */

#endif /* _B_64_H_ */