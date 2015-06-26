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

/*
 * MITM attacker : pose either as a server or a client
 */
struct SRP_mitm_t
{
	struct server_t s;
	struct client_t c;
	
};

/*
 * A list of commons passwords used to simulate an offline dictionnary attack.
 */
static char *weak_passwords[] = { "123456","password","12345678","qwerty", 
								"abc123","123456789","111111","1234567",
								"iloveyou","adobe123","123123","admin",
								"1234567890","letmein","photoshop","1234",
								"monkey","shadow","sunshine","12345",
								"password123","princess","azerty","trustno1", NULL};


/*
 *  Custom initialisation procedure for the MITM stub server : we choose B == g in order to compute the shared secret S  without
 *  knowing the private DH client id, thnaks to modular arithmetics :
 *  S = B**(a + ux) % n <==> S = (g**a).(g**ux) %n
 * 						<==> S =   A.g**ux %n
 *
 */ 
char* mitm_server_init_shared(struct server_t *s, const char *email, const size_t email_len, const mpz_t client_pubkey, mpz_t *u)
{
	size_t i = 0x00;
	mpz_t k, /*u,*/ S;

	// 0. look up the identifier
	while((i < s -> entries_used) && memcmp(email, s -> entries[i].email, s -> entries[i].email_len))
		i++;

	if (s -> entries_used == i)
		return NULL;

	// Simplified SRP : B does not depend on k
	mpz_init_set_ui(k, 0 );

	// 1. B=kv + g**b % N
	//srp_utils_gen_server_pubkey(&(s -> srp.g), k , s -> entries[i].v, s -> srp.g, s -> srp.id, s -> srp.N );
	// 1. B == g
	mpz_init_set(s -> srp.pubkey, s -> srp.g);

	// 2. uH = SHA256(A|B)
	get_128_bit_random_value(u);

	// 2. Simplified SRP :  u = 128 bit random number
	mpz_init_set_ui(k, 0 );

	// 4. Generate S = (A * v**u) ** b % N
	srp_utils_gen_server_shared_secret(&S, client_pubkey, s -> srp.g, s -> entries[0].v, *u, s -> srp.id, s -> srp.N);

	// 5. Generate K = SHA256(S)
	srp_utils_gen_shared_key(s -> entries[i].K, S);

	
	mpz_clear(S);
	mpz_clear(k);

	return s -> entries[i].salt_str;
}




int main(int argc, char *argv[])
{
	size_t i;
	unsigned int password_found;
	struct SRP_mitm_t mitm;
	struct server_t s;
	struct client_t c;
	mpz_t N, g, k, u, v, useless_u, x;
	mpz_t tmp_base, tmp_e, S;
	
	uint8_t buf[SHA256_HASH_SIZE];
	struct sha256nfo ctx;
	char *c_salt_str, *s_salt_str, *email, *candidate_p;
	
	mpz_init_set_str(N, NIST_N, 16 );
	mpz_init_set_str(g, NIST_g, 0 );
	mpz_init_set_str(k, NIST_k, 0 );

	// Init server
	server_init(&s, N, g, k, 1);
	server_add_entry(&s, "test@example.com", 16, "password123", 11);

	// Init client
	client_init(&c, N, g, k);

	// Init MITM
	server_init(&(mitm.s), N, g, k, 1);
	server_add_entry(&(mitm.s), "test@example.com", 16, "uselesspass", 11);
	client_init(&(mitm.c), N, g, k);

	/*
	 * MITM client pubkey interception	
	 *
	 *  S <--A--  MITM <--A--  C  
	 *     --u--> MITM  --u--> C 
	 */
	email = "test@example.com";
	c_salt_str = mitm_server_init_shared(&(mitm.s), email, strlen(email), c.srp.pubkey, &u);
	s_salt_str = server_init_shared(&s, email, strlen(email), mitm.c.srp.pubkey, &useless_u);
	
	if (NULL != c_salt_str)
	{
		c.salt_str = malloc(strlen(c_salt_str)*sizeof(char));
		if (NULL != c.salt_str)
		{
			/* 
			 * The MITM attacker does not know the client private DH key 'a'.
			 * However sending B == g cirumvent this unknown, since :
			 *   S = B**(a + ux) % n <==> S = (g**a).(g**ux) %n
			 * 						 <==> S =   A.g**ux %n
			 */
			c.salt_len = strlen(c_salt_str);
			memcpy(c.salt_str, c_salt_str, strlen(c_salt_str));
			client_init_shared(&c, "password123", strlen("password123") , mitm.s.srp.pubkey , u);


			/*
	 		 * MITM offline dictionnary attack
	 		 */
			i = 0x00;			
			password_found = 0x00;
			candidate_p = weak_passwords[0];

			while (NULL != candidate_p && !password_found)
			{
				srp_utils_gen_x(&x, candidate_p, strlen(candidate_p),c_salt_str, strlen(c_salt_str));

				// g**(u.x)
				mpz_init(tmp_base);
				mpz_init_set(tmp_e, u);
				mpz_mul(tmp_e, tmp_e, x );
				mpz_powm(tmp_base, g, tmp_e, N);

				mpz_init(S);
				mpz_mul(S, mitm.c.srp.pubkey, tmp_base );
				mpz_mod(S, S, N);

				srp_utils_gen_shared_key(mitm.c.K, S);

				mpz_clear(tmp_base);
				mpz_clear(tmp_e);
				mpz_clear(S);
				mpz_clear(x);
				
				if (!memcmp(mitm.c.K, c.K, sizeof(c.K)))
				{
					printf("Password successfully infered : %s !\n", candidate_p);
					password_found = 0x01;
				}
				else
				{
					i++;
					candidate_p = weak_passwords[i];
				}
			}

			/*
			 * Final server validation
			 */
			if (password_found)
			{
				mitm.c.salt_len = strlen(s_salt_str);
				mitm.c.salt_str = malloc(strlen(s_salt_str)*sizeof(char));
				if (NULL == mitm.c.salt_str)
					return 0x01;
				
				memcpy(mitm.c.salt_str, s_salt_str, strlen(s_salt_str));
				client_init_shared(&(mitm.c), candidate_p, strlen(candidate_p) , s.srp.pubkey, useless_u);


				sha256_init_Hmac(&ctx, mitm.c.K, SHA256_HASH_SIZE);
				sha256_write(&ctx, (uint8_t*) mitm.c.salt_str, mitm.c.salt_len);
				sha256_result_Hmac(&ctx, buf);

				if (server_check_password(&s, email, strlen(email),  buf))
					printf("We have a valid user : %s !\n", email);
				else
					printf("The following user is not registered : %s !\n", email);
			}
			else
				printf("The following user is not registered : %s !\n", email);
		}
	}
	else
		printf("The following user is not registered : %s !\n", email);

	client_cleanup(&c);
	server_cleanup(&s);
	server_cleanup(&(mitm.s));
	client_cleanup(&(mitm.c));

	mpz_clear(N);
	mpz_clear(g);
	mpz_clear(k);
	

	return 0x00;
}