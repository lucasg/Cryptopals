#include "mt19937.h"
#include <stdio.h>


static unsigned int index;
static uint32_t mt_seed; 
static uint32_t mt[MT19937_ARRAY_LEN]; 

/*
 * Mersenne Twister pseudorandom generation initialisation.
 */
void mt19937_init(struct mt19937_t *engine, uint32_t seed)
{
	unsigned int i;
	uint32_t tmp;

	index = 0;
	mt_seed = seed;
	engine -> seed = seed;
	mt[0] = seed;
	for (i = 1; i < MT19937_ARRAY_LEN; i++)
	{
		tmp = mt[i - 1] ^ (mt[i - 1] >> 30);
		mt[i] = (uint32_t) (0x6c078965*tmp + i);		
	}
}

/*
 * Mersenne Twister pseudorandom new values generation.
 * Every MT19937_ARRAY_LEN calls to mt19937_get_value, we 
 * deplete the MersenneTwister values array, so it has to
 * be regenerated regularly.
 */
void mt19937_regenerate_values(struct mt19937_t *engine)
{
	unsigned int i;

	for (i = 0; i < MT19937_ARRAY_LEN; i++)
	{
		uint32_t tmp = (mt[i] & 0x80000000) + 
		               (mt[(i+1) % MT19937_ARRAY_LEN] & 0x7fffffff);
		
		mt[i] = mt[(i+397) % MT19937_ARRAY_LEN] ^ (tmp >> 1);
		

		if (tmp % 2)
			mt[i] ^= 0x9908b0df;
	}

}

/*
 * Mersenne Twister pseudorandom next output getter
 */
uint32_t mt19937_get_value(struct mt19937_t *engine)
{
	if (!index)
		mt19937_regenerate_values(engine);

	uint32_t next_value = mt[index];
	next_value ^= (next_value >> 11);
	next_value ^= (next_value <<  7) & 0x9d2c5680;
	next_value ^= (next_value << 15) & 0xefc60000;
	next_value ^= (next_value >> 18);

	index = (index + 1) % MT19937_ARRAY_LEN;
	return (uint32_t) next_value;
}