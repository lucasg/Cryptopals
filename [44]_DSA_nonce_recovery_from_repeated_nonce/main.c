#include "hex.h"
#include "sha1.h"
#include "dsa.h"

#include "mini-gmp/mpz_invmod.h"
#include <mini-gmp/mini-gmp.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>

const char Y_TO_CRACKED[] = "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
						    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
						    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
						    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
						    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
						    "2971c3de5084cce04a2e147821";


struct dsa_message {
	char *msg, *r, *s;
	struct dsa_signature_t signature;
};

int init_dsa_message(struct dsa_message *dm)
{
	mpz_init_set_str(dm -> signature.r, dm -> r, 10);
	mpz_init_set_str(dm -> signature.s, dm -> s, 10);
	return EXIT_SUCCESS;
}

int clear_dsa_message(struct dsa_message *dm)
{
	mpz_clear(dm -> signature.r);
	mpz_clear(dm -> signature.s);
	return EXIT_SUCCESS;
}

static struct dsa_message dsa_messages[] = {
	{.msg = "Listen for me, you better listen for me now. ",
	  .s = "1267396447369736888040262262183731677867615804316",
	  .r = "1105520928110492191417703162650245113664610474875"},
	{.msg = "Listen for me, you better listen for me now. ",
	  .s = "29097472083055673620219739525237952924429516683",
	  .r = "51241962016175933742870323080382366896234169532"},
	{.msg = "When me rockin' the microphone me rock on steady, ",
	  .s = "277954141006005142760672187124679727147013405915",
	  .r = "228998983350752111397582948403934722619745721541"},
	{.msg = "Yes a Daddy me Snow me are de article dan. ",
	  .s = "1013310051748123261520038320957902085950122277350",
	  .r = "1099349585689717635654222811555852075108857446485"},
	{.msg = "But in a in an' a out de dance em ",
	  .s = "203941148183364719753516612269608665183595279549",
	  .r = "425320991325990345751346113277224109611205133736"},
	{.msg = "Aye say where you come from a, ",
	  .s = "502033987625712840101435170279955665681605114553",
	  .r = "486260321619055468276539425880393574698069264007"},
	{.msg = "People em say ya come from Jamaica, ",
	  .s = "1133410958677785175751131958546453870649059955513",
	  .r = "537050122560927032962561247064393639163940220795"},
	{.msg = "But me born an' raised in the ghetto that I want yas to know, ",
	  .s = "559339368782867010304266546527989050544914568162",
	  .r = "826843595826780327326695197394862356805575316699"},
	{.msg = "Pure black people mon is all I mon know. ",
	  .s = "1021643638653719618255840562522049391608552714967",
	  .r = "1105520928110492191417703162650245113664610474875"},
	{.msg = "Yeah me shoes a an tear up an' now me toes is a show a ",
	  .s = "506591325247687166499867321330657300306462367256",
	  .r = "51241962016175933742870323080382366896234169532"},
	{.msg = "Where me a born in are de one Toronto, so ",
	  .s = "458429062067186207052865988429747640462282138703",
	  .r = "228998983350752111397582948403934722619745721541"}
};


int get_mpz_from_sha1_hash(mpz_t *hash_number, const char message[], const size_t message_len)
{
	struct sha1nfo  hash;
	unsigned char hexstring[2*SHA1_HASH_LENGTH + 1] = {0};

	sha1_init(&hash);
	sha1_write(&hash, (char *) message, message_len);
	hex_encode((char*) hexstring, (char*) sha1_result(&hash), 2*SHA1_HASH_LENGTH);
	mpz_init_set_str(*hash_number, (char*) hexstring, 16);
	
	return 0x00;
}

/*
 *	       (s * k) - H(msg)
 *     x = ----------------  mod q
 *                 r
 */
int compute_private_key_from_nonce(mpz_t *private_key, const struct dsa_signature_t signature, const char message[], const size_t message_len, const struct dsa_pubkey_t pubkey, const mpz_t nonce)
{
	mpz_t inv_s1, s_x_k, h_number;

	mpz_init(s_x_k);
	
	mpz_mul(s_x_k, signature.s, nonce);
	get_mpz_from_sha1_hash(&h_number, message, message_len);
	mpz_sub(s_x_k, s_x_k, h_number);
	mpz_mod(s_x_k, s_x_k, pubkey.q);

	mpz_init(inv_s1);
	if (mpz_invmod(&inv_s1, signature.r, pubkey.q))
		return -EINVAL; /* modular inverse not found */

	mpz_init(*private_key);
	mpz_mul(*private_key, s_x_k, inv_s1);
	mpz_mod(*private_key, *private_key, pubkey.q);

	mpz_clear(inv_s1);
	mpz_clear(h_number);
	mpz_clear(s_x_k);

	return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{
	struct sha1nfo  hash;
	char *cracked_pkey_hexstr;
	unsigned char *sha_result;
	struct dsa_pubkey_t pubkey;
	mpz_t hash1, hash2, hash_diff, inv_s_diff, s_diff, nonce, pkey, r_verif;
	size_t i, j, i_hash, messages_count = sizeof(dsa_messages)/sizeof(struct dsa_message);

	/* Init */
	for (i = 0; i < messages_count; i++)
		init_dsa_message(&(dsa_messages[i]));

	dsa_gen_fixed_parameters(&pubkey);
	mpz_init_set_str(pubkey.y, Y_TO_CRACKED, 16);

	/* Look for repeated nonce in two messages */
	for (i = 0; i < messages_count - 1; i++)
	{
		for (j = i + 1; j < messages_count; j++)
		{
			if (0 == strcmp(dsa_messages[i].r, dsa_messages[j].r))
			{
				/*  Now that we have two message signed with the same nonce,
				 	compute the nonce. */

				get_mpz_from_sha1_hash(&hash1, dsa_messages[i].msg, strlen(dsa_messages[i].msg));
				get_mpz_from_sha1_hash(&hash2, dsa_messages[j].msg, strlen(dsa_messages[j].msg));

		
				printf("repeated nonce in messages : \n\t%lu : %s\n\t%lu : %s\n",
								(unsigned long) i,  dsa_messages[i].msg,
								(unsigned long) j,  dsa_messages[j].msg);

				mpz_init(hash_diff);
				mpz_sub(hash_diff, hash1, hash2);
				mpz_mod(hash_diff, hash_diff, pubkey.q);

				mpz_init(s_diff);
				mpz_sub(s_diff, dsa_messages[i].signature.s, dsa_messages[j].signature.s);
				mpz_mod(s_diff, s_diff, pubkey.q);


				if (EXIT_SUCCESS == mpz_invmod(&inv_s_diff, s_diff, pubkey.q))
				{
					mpz_init(nonce);
					mpz_mul(nonce, inv_s_diff, hash_diff);
					mpz_mod(nonce, nonce, pubkey.q);

					/* verify computation */
					mpz_init(r_verif);
					mpz_powm(r_verif, pubkey.g, nonce, pubkey.p);
					mpz_mod(r_verif,r_verif, pubkey.q);

					if (0 != mpz_cmp(r_verif, dsa_messages[i].signature.r) || 0 != mpz_cmp(r_verif, dsa_messages[j].signature.r))
						printf("Reconstructed r does not match input r !\n\t r_i:%s\n\t r_j:%s\n\t r_r:%s\n",
									mpz_get_str(NULL, 10, dsa_messages[i].signature.r),
									mpz_get_str(NULL, 10, dsa_messages[j].signature.r),
									mpz_get_str(NULL, 10, r_verif));
					mpz_clear(r_verif);

					printf(" -> Nonce : %s \n", mpz_get_str(NULL, 16, nonce));

					if (EXIT_SUCCESS == compute_private_key_from_nonce(&pkey, dsa_messages[i].signature, dsa_messages[i].msg, strlen(dsa_messages[i].msg), pubkey, nonce))
					{
						cracked_pkey_hexstr = mpz_get_str(NULL, 16, pkey);
						printf(" -> Private Key : %s \n", cracked_pkey_hexstr);

						sha1_init(&hash);
						sha1_write(&hash, cracked_pkey_hexstr, strlen(cracked_pkey_hexstr));
						sha_result = sha1_result(&hash);
						printf(" -> Cracked private key sha1 hash : ");
						for (i_hash = 0; i_hash < SHA1_HASH_LENGTH; i_hash++)
							printf("%02x:", sha_result[i_hash]);
						printf("\n");

						free(cracked_pkey_hexstr);
						mpz_clear(pkey);
					}

					mpz_clear(inv_s_diff);
					mpz_init(nonce);
				}

				
				mpz_clear(s_diff);
				mpz_clear(hash_diff);
			}
		}
	}
	

	/* Cleanup */
	for (i = 0; i < messages_count; i++)
		clear_dsa_message(&(dsa_messages[i]));

	mpz_clear(pubkey.y);
	mpz_clear(pubkey.p);
	mpz_clear(pubkey.q);
	mpz_clear(pubkey.g);
	return EXIT_SUCCESS;
}


