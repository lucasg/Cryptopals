#include "server.h"
#include "srp_utils.h"
#include "mt19937.h"
#include "hex.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>

unsigned int server_init(struct server_t *s, const mpz_t N, const  mpz_t g, const  mpz_t k, const size_t entry_cnt)
{
	size_t i;

	memset(s, 0, sizeof(struct server_t));
	mpz_init_set(s -> srp.N, N);
	mpz_init_set(s -> srp.g, g);
	mpz_init_set(s -> srp.k, k);
	
	// 1. Allocate entries
	s -> entries = malloc(entry_cnt*sizeof(struct server_entry_t));
	if (NULL == s -> entries)
		return 0x00;
	s -> entries_len = entry_cnt;
	s -> entries_used = 0;

	for (i = 0; i < s -> entries_len; i++)
	{
		s -> entries[i].salt_str = NULL;
		s -> entries[i].email = NULL;
	}
	
	
	// 2. 16-bytes DH random private key
	srp_utils_gen_random_dh_id(&(s -> srp.id), 16); 

    return 0x01;

}

unsigned int server_add_entry(struct server_t *s, const char* email, size_t email_len, 
										  		  const char* password, size_t password_len)
{
	size_t cur;

	if (s -> entries_used > s -> entries_len)
		return 0x00;

	cur = (s -> entries_used)++;

	// 1. Generate 16-bytes random salt
	s -> entries[cur].salt_len = srp_utils_gen_random_salt(&(s -> entries[cur].salt_str), 16);

	
	// 2. Store the email
	s -> entries[cur].email = malloc(email_len*sizeof(char));
	if (NULL == s -> entries[cur].email)
		return 0x00;
	
	memcpy(s -> entries[cur].email, email, email_len*sizeof(char));
	s -> entries[cur].email_len = email_len;


	// 3. Generate the password verifier
	srp_utils_gen_password_verifier( &(s -> entries[cur].v), s -> srp.g, s -> srp.N,
									 password, strlen(password),
									 s->entries[cur].salt_str, strlen(s->entries[cur].salt_str));


	return 0x01;
}

char* server_init_shared(struct server_t *s, const char *email, const size_t email_len, const mpz_t client_pubkey)
{
	size_t i = 0x00;
	mpz_t u, S;

	// 0. look up the identifier
	while((i < s -> entries_used) && memcmp(email, s -> entries[i].email, s -> entries[i].email_len))
		i++;

	if (s -> entries_used == i)
		return NULL;

	// 1. B=kv + g**b % N
	srp_utils_gen_server_pubkey(&(s -> srp.pubkey), s -> srp.k, s -> entries[i].v, s -> srp.g, s -> srp.id, s -> srp.N );

	// 2. uH = SHA256(A|B)
	srp_utils_gen_shared_hash( &u, s -> srp.pubkey, client_pubkey);

	// 4. Generate S = (A * v**u) ** b % N
	srp_utils_gen_server_shared_secret(&S, client_pubkey, s -> srp.g, s -> entries[0].v, u, s -> srp.id, s -> srp.N);

	// 5. Generate K = SHA256(S)
	srp_utils_gen_shared_key(s -> entries[i].K, S);

	mpz_clear(u);
	mpz_clear(S);

	return s -> entries[i].salt_str;
}


unsigned int server_check_password(struct server_t *s, const char *email, const size_t email_len, const uint8_t password_hmac[SHA256_HASH_SIZE])
{
	size_t i = 0x00;

	// 0. look up the identifier
	while((i < s -> entries_used) && memcmp(email, s -> entries[i].email, s -> entries[i].email_len))
		i++;

	if (s -> entries_used == i)
		return 0x00;
	else
		return srp_utils_check_auth(s -> entries[i].K, s -> entries[i].salt_str, strlen(s -> entries[i].salt_str), password_hmac);
}

void server_cleanup(struct server_t *s)
{
	size_t i;

	srp_info_cleanup(&(s ->srp));

	if (NULL != s -> entries)
	{
		for (i = 0; i < s -> entries_len; i++)
		{
			if (NULL != s -> entries[i].salt_str)
				free(s -> entries[i].salt_str);
			s -> entries[i].salt_str = NULL;

			if (NULL != s -> entries[i].email)
				free(s -> entries[i].email);
			s -> entries[i].email = NULL;

			mpz_clear(s ->entries[i].v);
		}

		free(s -> entries);
		s -> entries = NULL;
	}



	memset(s, 0, sizeof(struct server_t));

}