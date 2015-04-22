#include "target.h"
#include "poor_man_json.h"
#include "../tools/aes_128/aes_128.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

static int rkey_init = 0x00;
static char rkey[16] = {0};



/*
 *	Generate a random key to encrypt plaintext data.
 */
void generate_rkey()
{
	unsigned int i;

	srand (time (NULL));

	for (i=0; i<4; i++)
		((int*) rkey)[i] = rand();
}

/*
 *
 */
int profile_for(char **output, const char *email_str, unsigned int email_len)
{
	char *c;
	unsigned int i, add_entry_retval, retval;
	struct poor_man_json_entry profile[3];

	struct poor_man_json_entry id = 
	{
		.c_string_key = {
			.str = "id",
			.len = 2},
		
		.c_string_payload = {
			.str = "10",
			.len = 2}
	};

	struct poor_man_json_entry role = 
	{
		.c_string_key = {
			.str = "role",
			.len = 4},
		
		.c_string_payload = {
			.str = "user",
			.len = 4}
	};



	i = 0;
	c = (char*) email_str;
	while(*c != '&' && *c != '=' && i < email_len)
	{
		c++;
		i++;
	}

	if (0 == i)
		add_entry_retval = poor_man_json_add_entry(&profile[0], "email", 5, "def@au.lt", 9);
	else
		add_entry_retval = poor_man_json_add_entry(&profile[0], "email", 5, email_str, i);	
	
	if (add_entry_retval)
		return 0x00;

	memcpy(&profile[1], &role, sizeof(struct poor_man_json_entry));
	memcpy(&profile[2], &id  , sizeof(struct poor_man_json_entry));



	retval = poor_man_json_to_string(output, profile, 3);

	free(profile[0].c_string_key.str);
	free(profile[0].c_string_payload.str);
	return retval;
}

/*
 *
 */
int profile_parse(struct poor_man_json_entry **output_table, const char *kv_input, unsigned int input_len)
{
	char *key, *next_key, *val;
	unsigned int i, and_count, eq_count, kv_entries;
	struct poor_man_json_entry *tmp;

	// Count the number of & and = in order to know the output table size
	and_count = 0;
	eq_count = 0;
	for (i = 0; i < input_len; i++)
	{
		if ('&' == kv_input[i]) and_count++;
		if ('=' == kv_input[i]) eq_count++;
	}

	kv_entries = ((and_count+1) < eq_count) ? (1+and_count) : eq_count;
	tmp = malloc(kv_entries*sizeof(struct poor_man_json_entry));
	if (NULL ==  tmp)
		return 0x00;

	key = (char*) kv_input;
	val = (char*) kv_input;
	for (i = 0; i < kv_entries; i++)
	{
		while (*val != '=')
			val++;
		val++;

		next_key = val;
		while (*next_key != '&' && ((int)(next_key - kv_input)) < input_len)
			next_key++;
		next_key++;

		poor_man_json_add_entry(&tmp[i], key, ((int)(val - key) - 1), val, ((int)(next_key - val) - 1));

		key = next_key;
	}

	*output_table = tmp;
	return kv_entries;
}

/*
 *
 */
int encrypt(unsigned char **output, const char *email, unsigned int email_len)
{
	unsigned char *tmp = NULL;
	size_t tmp_len, output_len;

	if (!rkey_init)
	{
		generate_rkey();
		rkey_init = 1;	
	}

	tmp_len = profile_for((char**) &tmp, email, email_len);
	output_len = tmp_len;
	if (output_len % aes_128_block_len)
		output_len += aes_128_block_len - (output_len % aes_128_block_len);

	if (NULL == tmp || 0 == tmp_len)
		return 0x00;

	*output = malloc(output_len*sizeof(char));
	if (NULL == output)
		return 0x01;

	aes_128_encrypt_msg(*output, tmp, tmp_len, (unsigned char*) rkey, ECB, NULL);

	free(tmp);
	return output_len;
}


/*
 *
 */
void decrypt(const unsigned char *cipher, unsigned int cipher_len)
{
	unsigned char *tmp;
	struct poor_man_json_entry *kv_table;
	unsigned int kv_table_len,i;

	if (!rkey_init)
		return;

	tmp = malloc(cipher_len*sizeof(unsigned char));
	if (NULL==tmp)
		return;

	aes_128_decrypt_msg(tmp, cipher, cipher_len, (unsigned char*) rkey, ECB, NULL);

	printf("DEBUG : decryption %s\n", tmp );
	kv_table_len = profile_parse(&kv_table, (char*) tmp, cipher_len);

	if (0 == kv_table_len || NULL == kv_table )
	{
		free(tmp);
		return;
	}

	for (i=0; i < kv_table_len; i++)
		printf("- %s : %s \n", kv_table[i].c_string_key.str, kv_table[i].c_string_payload.str);

	for (i=0; i < kv_table_len; i++)
	{
		free(kv_table[i].c_string_key.str);
		free(kv_table[i].c_string_payload.str);
	}

	
	free(tmp);
	free(kv_table);
}

