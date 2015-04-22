#include "bot.h"
#include "sha1.h"
#include "mt19937.h"
#include <time.h>
#include <stdio.h>

const char NIST_g[] = "2";
const char NIST_p[] = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
"fffffffffffff";

/*
 * Equivalent of rand(), using the newly implemented MT19937 prng.
 */
uint64_t get_random_value()
{
	struct mt19937_t mt_single_shot;
	mt19937_init(&mt_single_shot, time(NULL));

	return mt19937_get_value(&mt_single_shot) + (((uint64_t)mt19937_get_value(&mt_single_shot)) << 32);
}

/*
 * The MITM attack use the fact that x^p = 0 [p].
 * When "fixing" the public key to p, we ensure that
 * every participant's shared secret numerical value is zero. 
 */
struct attacker_t
{	
	// The two structure are just here to use the send/recv functions easily.
	struct bot_t a, b;
};


int main( int argc, char *argv[])
{
	struct sha1nfo zero_h;
	struct attacker_t janus;
	struct bot_t alice, bob;

	mpz_t p, g, a, b;

	mpz_init_set_str(p, NIST_p, 16 );
	mpz_init_set_str(g, NIST_g, 16 );

	mpz_init_set_ui(a, get_random_value());
	mpz_init_set_ui(b, get_random_value());

	// [A->M] : Send "p", "g", "A"
	bot_init(&alice, a, p,  g );
	bot_gen_pubkey(&alice);

	// [M->B] : Send "p", "g", "p"
	bot_init(&bob, b, p,  g );

	// [B->M] : Send "B"
	bot_gen_pubkey(&bob);
	bot_gen_shared_secret(&bob, p);

	// [M->A] : Send "p"
	bot_gen_shared_secret(&alice, p);


	// MITM internal init 
	sha1_init(&zero_h);
	sha1_write(&zero_h, "0", 1);
	janus.a.msg_buffer = NULL;
	janus.b.msg_buffer = NULL;
	memcpy(janus.a.hashed_skey, sha1_result(&zero_h), sizeof(janus.a.hashed_skey));
	memcpy(janus.b.hashed_skey, janus.a.hashed_skey, sizeof(janus.b.hashed_skey));

	printf("[Alice] message sent : %s\n", (char*) "Test, please ignore" );
	if(send_msg(&alice, (uint8_t*) "Test, please ignore", 19))
	{
		/*
		 *  Message injection
		 */
		recv_msg(&janus.a, alice.msg_buffer, alice.msg_bufferlen);		
		printf("[M] message received : %s\n", (char*) janus.a.msg_buffer );

		send_msg(&janus.b, (uint8_t*) "Test, please respond", 20);
		printf("[M] message sent : %s\n", "Test, please respond" );


		recv_msg(&bob, janus.b.msg_buffer, janus.b.msg_bufferlen);
		printf("[Bob] message received : %s\n", (char*) bob.msg_buffer );
	}

	bot_cleanup(&alice);
	bot_cleanup(&bob);
	if (NULL != janus.a.msg_buffer)
		free(janus.a.msg_buffer);
	if (NULL != janus.b.msg_buffer)
		free(janus.b.msg_buffer);



	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(p);
	mpz_clear(g);

	return 0x00;
}