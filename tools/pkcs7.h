#ifndef _PKCS_7_H_
	#define _PKCS_7_H_


/*
 *	Check if the input string has a valid
 *  pkcs7 padding. Return 0 (invalid) or 1 (valid) 
 */
int pkcs7_validate(const unsigned char *input, unsigned int len);

/*
 * 	If the input string has a valid pkcs#7 padding, it strips it.
 *  Return the input len minus the padding part.
 */
int pkcs7_strip(const unsigned char *input, unsigned int in_len);

/*
 * 	If the input srting has a valid pkcs#7 padding, it strips it.
 * 	The output string buffer should have enough memory to incorporate the padding.
 */
void pkcs7_generate(unsigned char *output, const unsigned char *input, unsigned int in_len, unsigned int pad_len);


#endif /* _PKCS_7_H_ */