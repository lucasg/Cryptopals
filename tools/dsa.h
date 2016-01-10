#include <mini-gmp/mini-gmp.h>
#include <stdint.h>

struct dsa_signature_t
{
	mpz_t r, s;
};

struct dsa_pubkey_t
{
	mpz_t p, q, g, y;
};

/*
 * 
 */
int dsa_gen_fixed_parameters(struct dsa_pubkey_t *pubkey);

/*
 * DSA private and public key generations.
 */
int dsa_gen_parameters(struct dsa_pubkey_t *pubkey);

/*
 * DSA private and public key generations.
 */
int dsa_gen_keys(mpz_t *priv_key, struct dsa_pubkey_t *pubkey);



/*
 * DSA sign a message using the private key.
 */
int dsa_sign(struct dsa_signature_t *signature, const char message[], const size_t message_len, const mpz_t priv_key, const struct dsa_pubkey_t pubkey);


/*
 *
 */
int dsa_verify(const struct dsa_signature_t signature, const char message[], const size_t message_len, const struct dsa_pubkey_t pubkey);