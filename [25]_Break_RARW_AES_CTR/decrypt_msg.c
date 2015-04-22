#include "decrypt_msg.h"
#include "b64.h"
#include "aes_128/aes_128.h"
#include "pkcs7.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>




/*
 *   Load the whole file into memory
 */
unsigned int load_file(const char *fd_stream, unsigned char **contents, size_t *contents_size)
{
	FILE *stream;
	unsigned int file_size = 0;

	stream = fopen(fd_stream, "rb");

	fseek(stream, 0L, SEEK_END);
	file_size = ftell(stream);
	fseek(stream, 0L, SEEK_SET);

	(*contents) = malloc(file_size*sizeof(size_t));
	if( NULL == (*contents))
		return 0x01;

	*contents_size = fread( (*contents) , 1 , file_size , stream);
	fclose(stream);

	return 0x00;
}



unsigned int decrypt_msg(const char input_file[], const char key[], unsigned char **msg, size_t *msg_len)
{
	unsigned char *encrypted_msg;
	size_t encrypted_msglen;

	//
	if (load_file(input_file, &encrypted_msg, &encrypted_msglen))
		return 0x01;

	// 
	*msg_len = b64_get_ascii_wc(encrypted_msglen);
	(*msg) = malloc((*msg_len)*sizeof(size_t));
	if( NULL == (*msg))
	{
		free(encrypted_msg);
		return 0x01;
	}

	//
	b64_decode((char*) (*msg), (char*) encrypted_msg, encrypted_msglen);
	memcpy(encrypted_msg,  (*msg), *msg_len);

	memset(encrypted_msg + (*msg_len), 0, (encrypted_msglen - (*msg_len))*sizeof(size_t)); 
	memset((*msg), 0, (*msg_len)*sizeof(size_t));


	//
	aes_128_decrypt_msg((*msg), encrypted_msg, (*msg_len), (unsigned char*) key, ECB, NULL);
	*msg_len = pkcs7_strip((*msg), (*msg_len));
	(*msg)[*msg_len] = '\0';


	free(encrypted_msg);
	return 0x00;
}