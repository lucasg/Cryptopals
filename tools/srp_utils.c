#include "srp_utils.h"
#include "mt19937.h"
#include "hex.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>


#ifdef _DEBUG_SRP
#include <stdio.h>

/*
 *  Print the hash's hexadecimal string 
 */
void print_sha256_hash(uint8_t * hash)
{
	size_t i;

	for (i = 0; i < SHA256_HASH_SIZE; i++)
		printf(":%02x",  hash[i] );
}
#endif /* _DEBUG_SRP */


void srp_info_cleanup(struct srp_info_t *srp)
{
	mpz_clear(srp -> N);
	mpz_clear(srp -> g);
	mpz_clear(srp -> k);
	mpz_clear(srp -> id);
	mpz_clear(srp -> pubkey);
}

size_t srp_utils_gen_random_salt(char **salt, const size_t salt_len)
{
	mpz_t tmp;
	struct mt19937_t mt_gen;
	size_t i, ret_salt_len = 2*(salt_len +  ((sizeof(uint32_t) - salt_len) % sizeof(uint32_t)));

	*salt = malloc((1+ret_salt_len)*sizeof(char));
	if (NULL == *salt)
		return 0x00;

	mt19937_init(&mt_gen, time(NULL));
	for (i =0; i < ret_salt_len; i+=2*sizeof(uint32_t))
	{
		mpz_init_set_ui(tmp, mt19937_get_value(&mt_gen));
		mpz_get_str(*salt + i, 16, tmp);
		mpz_clear(tmp);
	}
	(*salt)[ret_salt_len] = 0x00;

	return ret_salt_len; 
}

 
void srp_utils_gen_random_dh_id(mpz_t *dh_id, const size_t id_len)
{
	mpz_t tmp;
	char *id;
	struct mt19937_t mt_gen;
	size_t i, id_plen = 2*(id_len +  ((sizeof(uint32_t) - id_len) % sizeof(uint32_t)));

	id = malloc((1+id_plen)*sizeof(char));
	if (NULL == id)
		return;

	mt19937_init(&mt_gen, time(NULL));
	for (i =0; i < id_plen; i+=2*sizeof(uint32_t))
	{
		mpz_init_set_ui(tmp, mt19937_get_value(&mt_gen));
		mpz_get_str(id + i, 16, tmp);
		mpz_clear(tmp);
	}

	id[id_plen] = 0x00;
	mpz_init_set_str(*dh_id, id, 16);

	free(id);
}


void srp_utils_gen_x(mpz_t *x, const char *password, const  size_t password_len,
								const char *salt,  const  size_t salt_len)
{
	char buf[SHA256_HASH_SIZE + 1], xH[2*SHA256_HASH_SIZE + 1];
	struct sha256nfo ctx;

	buf[SHA256_HASH_SIZE] = 0;
	xH[2*SHA256_HASH_SIZE] = 0;

	//Generate string xH=SHA256(salt|password)
	sha256_init(&ctx);
	sha256_write(&ctx, (uint8_t*) salt, salt_len);
	sha256_write(&ctx, (uint8_t*) password, password_len);
	sha256_result(&ctx, (uint8_t*) buf);

	// Convert xH to integer x somehow (put 0x on hexdigest)
	hex_encode(xH, buf, 2*SHA256_HASH_SIZE);
	mpz_init_set_str(*x, xH, 16 );

#ifdef _DEBUG_SRP
	printf("[SRP Debug] salt || p "); print_sha256_hash(buf); printf("\n");
#endif /* _DEBUG_SRP */
}



void srp_utils_gen_password_verifier(mpz_t *v, const  mpz_t g, const  mpz_t N,
	   										   const char *password, const  size_t password_len,
										 	   const char *salt,  const  size_t salt_len )
{
	mpz_t x;


	// 1. Generate x
	srp_utils_gen_x(&x,password, password_len, salt, salt_len);

	// 2. Generate v=g**x % N
	mpz_init(*v);
	mpz_powm(*v, g , x, N);

	mpz_clear(x);
}


void srp_utils_gen_server_pubkey(mpz_t *pubkey, const mpz_t k, const mpz_t v, const  mpz_t g, const  mpz_t dh_id, const  mpz_t N)
{
	mpz_t tmp_kv;

	mpz_init(tmp_kv);
	mpz_init(*pubkey);

	mpz_mul(tmp_kv, k, v);
	mpz_mod(tmp_kv, tmp_kv, N);

	mpz_powm(*pubkey, g , dh_id, N);
	
	mpz_add(*pubkey, *pubkey, tmp_kv);
	mpz_mod(tmp_kv, tmp_kv, N);

	mpz_clear(tmp_kv);
}


void srp_utils_gen_client_pubkey(mpz_t *pubkey, const mpz_t g, const  mpz_t dh_id, const  mpz_t N)
{
	mpz_init(*pubkey);
	mpz_powm(*pubkey, g , dh_id, N);
}


void srp_utils_gen_shared_hash(mpz_t *u, const mpz_t s_pubkey, const mpz_t c_pubkey)
{
	struct sha256nfo ctx;
	char buf[SHA256_HASH_SIZE], hex_buf[2*SHA256_HASH_SIZE + 1],
		 *spubkey_str, *cpubkey_str;

	hex_buf[2*SHA256_HASH_SIZE] = 0;
	cpubkey_str = mpz_get_str(NULL, 16, c_pubkey); 
	spubkey_str = mpz_get_str(NULL, 16, s_pubkey);

	// 2. uH = SHA256(A|B)
	sha256_init(&ctx);
	sha256_write(&ctx, (uint8_t*) cpubkey_str, strlen(cpubkey_str));
	sha256_write(&ctx, (uint8_t*) spubkey_str, strlen(spubkey_str));
	sha256_result(&ctx, (uint8_t*) buf);

	// 3. Convert uH to integer u somehow (put 0x on hexdigest)
	hex_encode(hex_buf, buf, 2*SHA256_HASH_SIZE);
	mpz_init_set_str( *u, (char*) hex_buf , 16 );
	

#ifdef _DEBUG_SRP
	printf("[SRP Debug] u "); print_sha256_hash(buf); printf("\n");
#endif /* _DEBUG_SRP */

	free(cpubkey_str);
	free(spubkey_str);
}


void srp_utils_gen_server_shared_secret(mpz_t *S, const mpz_t c_pubkey, const mpz_t g,
												  const mpz_t v, const mpz_t u,
												  const mpz_t dh_id, const mpz_t N)
{
	mpz_t tmp_A;

	mpz_init(tmp_A);
	mpz_init(*S);
	
	mpz_powm(tmp_A, v, u, N);
	mpz_mul (tmp_A, tmp_A, c_pubkey);

	mpz_powm(*S, tmp_A , dh_id, N);

	mpz_clear(tmp_A);

}

void srp_utils_gen_client_shared_secret(mpz_t *S, const mpz_t s_pubkey, const mpz_t g,
												  const mpz_t k, const mpz_t x, const mpz_t u,
												  const mpz_t dh_id, const mpz_t N)
{
	mpz_t tmp_base, tmp_e;

	mpz_init(tmp_base);
	mpz_init_set(tmp_e, u);

	mpz_powm(tmp_base, g, x, N);
	mpz_mul(tmp_base, tmp_base, k);
	mpz_mod(tmp_base, tmp_base, N);
	mpz_sub(tmp_base, s_pubkey, tmp_base);
	mpz_mod(tmp_base, tmp_base, N);

	mpz_mul(tmp_e, tmp_e, x );
	mpz_mod(tmp_e, tmp_e, N);
	mpz_add(tmp_e, tmp_e, dh_id );
	mpz_mod(tmp_e, tmp_e, N);


	mpz_init(*S);
	mpz_powm(*S, tmp_base, tmp_e, N);

	mpz_clear(tmp_base);
	mpz_clear(tmp_e);

}


void srp_utils_gen_shared_key(uint8_t K[SHA256_HASH_SIZE], const mpz_t S)
{
	struct sha256nfo ctx;
	char *S_str;

	S_str = mpz_get_str(NULL, 16, S);
	sha256_init(&ctx);
	sha256_write(&ctx, (uint8_t*) S_str, strlen(S_str));
	sha256_result(&ctx, (uint8_t*) K);

#ifdef _DEBUG_SRP
	printf("[SRP Debug] S :%s \n", S_str); 
	printf("[SRP Debug] K "); print_sha256_hash(K); printf("\n");
#endif /* _DEBUG_SRP */


	free(S_str);
}


unsigned int srp_utils_check_auth(const uint8_t sK[SHA256_HASH_SIZE], const char *salt, const size_t salt_len, const uint8_t c_hmac[SHA256_HASH_SIZE])
{
	uint8_t buf[SHA256_HASH_SIZE];
	struct sha256nfo ctx;
	

	// server verif : HMAC(K, salt)
	sha256_init_Hmac(&ctx, sK, SHA256_HASH_SIZE);
	sha256_write(&ctx, (uint8_t*) salt, salt_len);
	sha256_result_Hmac(&ctx,buf);
	

#ifdef _DEBUG_SRP
	printf("[SRP Debug] [S] : HMAC "); print_sha256_hash(buf); printf("\n");
	printf("[SRP Debug] [C] : HMAC "); print_sha256_hash(c_hmac); printf("\n");
#endif /* _DEBUG_SRP */


	return 0x00 == memcmp(buf, c_hmac, SHA256_HASH_SIZE*sizeof(uint8_t));
}

