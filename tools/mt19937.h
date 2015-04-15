#ifndef _MT19937_H_
	#define _MT19937_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MT19937_ARRAY_LEN (624)

/*
 * Mersenne Twister internal engine
 * and configuration structure
 */ 
struct mt19937_t
{
	uint32_t seed;
};


/* 
 *  Initialise a new mt19937 pseudorandom generator with the seed provided.
 */
extern void mt19937_init(struct mt19937_t *engine, uint32_t seed);

/* 
 *  Get a new random output from the mt19337 generator.
 */
extern uint32_t mt19937_get_value(struct mt19937_t *engine);


#ifdef __cplusplus
}
#endif

#endif /* _MT19937_H_ */