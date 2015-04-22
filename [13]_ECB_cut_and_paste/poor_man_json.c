#include "poor_man_json.h"
#include <string.h>
#include <stdlib.h>

int poor_man_json_add_entry(struct poor_man_json_entry* entry, const char *key, unsigned int klen, 
	const char *value, unsigned int vlen)
{
	// Copy key
	entry->c_string_key.str = malloc((klen+1)*sizeof(char));
	if (NULL == entry->c_string_key.str)
		return 0x1;

	memcpy(entry->c_string_key.str, key, klen*sizeof(char));
	entry->c_string_key.str[klen] = '\0';
	entry->c_string_key.len = klen;


	// Copy value
	entry->c_string_payload.str = malloc((vlen+1)*sizeof(char));
	if (NULL == entry->c_string_payload.str)
		return 0x1;

	memcpy(entry->c_string_payload.str, value, vlen*sizeof(char));
	entry->c_string_payload.str[vlen] = '\0';
	entry->c_string_payload.len = vlen;

	return 0x00;
}


int poor_man_json_to_string(char **output, const struct poor_man_json_entry json[], unsigned int entries_count)
{
	unsigned int i, idx, output_bytes = 0;
	char *tmp;

	for (i = 0; i < entries_count; i++)
	{
		output_bytes += json[i].c_string_key.len; 
		output_bytes ++;
		output_bytes += json[i].c_string_payload.len; 

		if (i!=entries_count-1)
			output_bytes++;
	}


	tmp = malloc((1+output_bytes)*sizeof(char));
	if (NULL == tmp)
		return 0x00;

	idx = 0;
	for (i = 0; i < entries_count; i++)
	{
		memcpy(tmp + idx,  json[i].c_string_key.str, json[i].c_string_key.len*sizeof(char));
		idx += json[i].c_string_key.len;

		tmp[idx] = '=';
		idx++;

		memcpy(tmp + idx,  json[i].c_string_payload.str, json[i].c_string_payload.len*sizeof(char));
		idx += json[i].c_string_payload.len;

		if (i!=entries_count-1)
		{
			tmp[idx] = '&';
			idx++;
		}
	}
	
	tmp[output_bytes] = '\0';
	*output = tmp;

	return output_bytes;
}
