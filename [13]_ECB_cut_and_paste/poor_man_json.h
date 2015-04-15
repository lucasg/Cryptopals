#ifndef _POOR_MAN_JSON_H_
	#define _POOR_MAN_JSON_H_

struct poor_man_json_entry
{
	struct
	{
		char *str;
		int len;
	} c_string_key;

	struct
	{
		char *str;
		int len;
	} c_string_payload;
};

int poor_man_json_add_entry(struct poor_man_json_entry* entry, const char *key, unsigned int klen, 
	const char *value, unsigned int vlen);

int poor_man_json_to_string(char **output, const struct poor_man_json_entry json[], unsigned int entries_count);


#endif /* _POOR_MAN_JSON_H_ */