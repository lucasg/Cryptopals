#include "mini-gmp/mini-gmp.h"
#include <stddef.h>

/* intervals viewed as a [a,b] pair */
struct mpz_interval_t {
	mpz_t lo, hi;
};

/*
 * Dynamic array
 */
struct mpz_dynarray_t {
  size_t size;      
  size_t capacity;
  
  struct mpz_interval_t *memptr;
  struct mpz_interval_t *data;  
};

/* 
 * bleichenbacher '98 intervals data structure needed
 * for the fast search algorithm
 */
struct b98_search_sets_t {
	/* intervals */
	struct mpz_dynarray_t sets;

	/* current boundaries (used to see the algorithm progression */
	mpz_t a, b;
};


/*
 * initialisation. Must always be called before others operations.
 */
int b98_search_sets_init(struct b98_search_sets_t *b98_ss, const mpz_t min, const mpz_t max);

/*
 * Add a new set to the list.
 */
int b98_search_sets_append(struct b98_search_sets_t *b98_ss, const mpz_t lo, const mpz_t hi);

/*
 * Discard the "oldest" value stored
 */
int b98_search_sets_pop(struct b98_search_sets_t *b98_ss);


/*
 * Free back any allocated resources.
 */
int b98_search_sets_free(struct b98_search_sets_t *b98_ss);