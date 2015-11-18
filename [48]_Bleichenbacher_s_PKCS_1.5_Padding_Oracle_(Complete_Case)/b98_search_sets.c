#include "b98_search_sets.h"
#include <stdlib.h>
#include <errno.h>

#define MPZ_DYNARRAY_INITIAL_CAPACITY 100

/*
 * initialisation. Must always be called before others operations.
 */
int b98_search_sets_init(struct b98_search_sets_t *b98_ss, const mpz_t min, const mpz_t max)
{
	if (NULL == b98_ss)
		return -1;

	/* initial memory allocation */
	b98_ss -> sets.memptr = malloc(sizeof(struct mpz_interval_t)*MPZ_DYNARRAY_INITIAL_CAPACITY);

	if (NULL == b98_ss -> sets.memptr)
		return -EINVAL;

	b98_ss -> sets.data = b98_ss -> sets.memptr;
	b98_ss -> sets.size = 0;
	b98_ss -> sets.capacity = MPZ_DYNARRAY_INITIAL_CAPACITY;

	mpz_init_set(b98_ss -> a , min);
	mpz_init_set(b98_ss -> b , max);

	return 0x00;
}

/*
 * Add a new set to the list, if conditions are met
 */
int b98_search_sets_append(struct b98_search_sets_t *b98_ss, const mpz_t lo, const mpz_t hi)
{
	if (NULL == b98_ss)
		return -EINVAL;

	/* check if [lo, hi] not € ]a,b[ */
	if (mpz_cmp(lo, b98_ss -> b) > 0 || mpz_cmp(hi, b98_ss -> a) < 0)
		return -EINVAL;

	/* Actual memory exhausted */
	if ((size_t) b98_ss -> sets.data + b98_ss -> sets.size == (size_t) b98_ss -> sets.memptr + b98_ss -> sets.capacity)
	{
		/* Dynamic reallocation with discarded values liberation */
		b98_ss -> sets.memptr = realloc(b98_ss -> sets.data, sizeof(struct mpz_interval_t)*(b98_ss -> sets.capacity)*2);
		if (NULL == b98_ss -> sets.memptr)
			return -EINVAL;

		b98_ss -> sets.capacity *= 2;
		b98_ss -> sets.data = b98_ss -> sets.memptr;
	}

	mpz_init_set(b98_ss -> sets.data[b98_ss -> sets.size].lo, lo);
	mpz_init_set(b98_ss -> sets.data[b98_ss -> sets.size].hi, hi);
	b98_ss -> sets.size++;

	return 0x00;
}

/*
 * Discard the "oldest" value stored
 */
int b98_search_sets_pop(struct b98_search_sets_t *b98_ss)
{
	if (NULL == b98_ss || 0 == b98_ss -> sets.size )
		return -EINVAL;

	mpz_clear(b98_ss -> sets.data[0].lo);
	mpz_clear(b98_ss -> sets.data[0].hi);

	b98_ss -> sets.data++;
	b98_ss -> sets.size--;

	return 0x00;
}


/*
 * Free back any allocated resources.
 */
int b98_search_sets_free(struct b98_search_sets_t *b98_ss)
{
	size_t i;

	if (NULL == b98_ss)
		return -EINVAL;

	if (NULL != b98_ss -> sets.memptr)
	{
		for (i = 0 ; i < b98_ss -> sets.size; i++)
		{
			mpz_clear(b98_ss -> sets.data[i].lo);
			mpz_clear(b98_ss -> sets.data[i].hi);

		}

		free(b98_ss -> sets.memptr);
		b98_ss -> sets.data = NULL;
		b98_ss -> sets.size = 0;
		b98_ss -> sets.capacity = 0;
	}

	return 0x00;

}

