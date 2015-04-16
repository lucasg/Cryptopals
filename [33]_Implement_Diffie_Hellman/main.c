#include "mt19937.h"
#include "mini-gmp/mini-gmp.h"
#include <time.h>
#include <stdio.h>
#include <stdint.h>

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

	return mt19937_get_value(&mt_single_shot) + (mt19937_get_value(&mt_single_shot) << 32);
}

void print_bignum(mpz_ptr bignum)
{
	printf("%s", mpz_get_str(NULL, 10, bignum));
}

unsigned int check_modular_exponentiation()
{
	mpz_t a, b, c, m, r;
 
	mpz_init_set_str(a,	"2988348162058574136915891421498819466320"
				"163312926952423791023078876139", 0);
	mpz_init_set_str(b,	"2351399303373464486466122544523690094744"
				"975233415544072992656881240319", 0);
	mpz_init(m);
	mpz_ui_pow_ui(m, 10, 40);
 
	mpz_init(r);
	mpz_powm(r, a, b, m);
 

	//print_bignum((mpz_ptr) &r);
 	mpz_init_set_str(c,	"1527229998585248450016808958343740453059", 0);

 	
 	printf("Modular exponentiation %s :\n%s ^ %s %% (10e40)  == %s \n", 
 							mpz_cmp(r,c) ? "incorrect" : "correct",
 							mpz_get_str(NULL, 10, a),
 							mpz_get_str(NULL, 10, b),
 							mpz_get_str(NULL, 10, c) 					);

	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(c);
	mpz_clear(m);
	mpz_clear(r);
 
	return 0;
}

void diffie_hellman(mpz_t *pubkey, const mpz_t privkey, const mpz_t p, const mpz_t g)
{
	mpz_powm(*pubkey, g , privkey, p);
}


int main(int argc, char *argv[])
{
	mpz_t p, g, a, A, b, B, s_a, s_b;

	check_modular_exponentiation();

	mpz_init_set_str(p, NIST_p, 16 );
	mpz_init_set_str(g, NIST_g, 0 );
	mpz_init_set_ui(a, get_random_value());
	mpz_init_set_ui(b, get_random_value());
	mpz_init(A);
	mpz_init(B);
	mpz_init(s_a);
	mpz_init(s_b);

	diffie_hellman(&A, a, p, g);
	diffie_hellman(&B, b, p, g);
	diffie_hellman(&s_a, a, p, B);
	diffie_hellman(&s_b, b, p, A);

	printf("Diffie Hellman %s :\n%s  == %s \n", 
 							mpz_cmp(s_a,s_b) ? "incorrect" : "correct",
 							mpz_get_str(NULL, 10, s_a),
 							mpz_get_str(NULL, 10, s_b));

	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(A);
	mpz_clear(B);
	mpz_clear(s_a);
	mpz_clear(s_b);

	return 0x00;
}