#ifndef _EDIT_TARGET_H_
	#define _EDIT_TARGET_H_

#include <unistd.h>

/*
 *  Initialize the aes-ctr target by giving it the original data.
 */
unsigned int init_edit_target(const char ctext_filename[], const char secret_key[], unsigned char **ciphertext, size_t *ciphertext_len);


/*
 *
 */
unsigned int edit_ciphertext(unsigned char *ciphertext, const size_t ciphertext_len, const size_t offset, const char *newtext, const size_t newtext_len);

#endif /* _EDIT_TARGET_H_ */