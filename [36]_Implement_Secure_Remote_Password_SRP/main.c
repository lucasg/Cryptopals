#include "client.h"
#include "server.h"
#include "mini-gmp/mini-gmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const char NIST_g[] = "2";
static const char NIST_k[] = "3";
static const char NIST_N[] = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
"fffffffffffff";


const char manpage[] = ""
"---Secure Remote Passord--\n"
"Please provide a password to test .\n"
"\n"
"Usage :\n"
"	srp.exe 'password'\n"
"\n";


int main(int argc, char *argv[])
{
	struct server_t s;
	struct client_t c;
	mpz_t N, g, k;
	
	uint8_t buf[SHA256_HASH_SIZE];
	struct sha256nfo ctx;
	char *salt_str, *email;
	
	if (argc < 3)
	{
		printf("%s\n", manpage );
		return 0x00;
	}

	mpz_init_set_str(N, NIST_N, 16 );
	mpz_init_set_str(g, NIST_g, 0 );
	mpz_init_set_str(k, NIST_k, 0 );

	server_init(&s, N, g, k, 1);
	server_add_entry(&s, "test@example.com", 16, "password123", 11);
	
	email = argv[1];
	client_init(&c, N, g, k);
	salt_str = server_init_shared(&s, email, strlen(email), c.srp.pubkey);
	if (NULL != salt_str)
	{
		c.salt_str = malloc(strlen(salt_str)*sizeof(char));
		if (NULL != c.salt_str)
		{
			c.salt_len = strlen(salt_str);
			memcpy(c.salt_str, salt_str, strlen(salt_str));
			client_init_shared(&c, argv[2], strlen(argv[2]), s.srp.pubkey);


			// HMAC test
			sha256_init_Hmac(&ctx, c.K, SHA256_HASH_SIZE);
			sha256_write(&ctx, (uint8_t*) c.salt_str, c.salt_len);
			sha256_result_Hmac(&ctx, buf);

			if (server_check_password(&s, email, strlen(email),  buf))
				printf("We have a valid user : %s !\n", email);
			else
				printf("The following user is not registered : %s !\n", email);
		}
	}
	else
		printf("The following user is not registered : %s !\n", email);

	client_cleanup(&c);
	server_cleanup(&s);

	mpz_clear(N);
	mpz_clear(g);
	mpz_clear(k);

	return 0x00;
}