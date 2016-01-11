#include "mt19937.h"
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>	
#include <string.h>	
#include <stdio.h>

#define MT19937_MAGIC_A (0x9d2c5680)
#define MT19937_MAGIC_B (0xefc60000)

static uint32_t mt_output[2*MT19937_ARRAY_LEN];
static uint32_t mt_predicted[MT19937_ARRAY_LEN];

/* 
 * Little unit tester for the untempering function in order to make it work
 */
void test_untemper(const uint32_t val)
{
	size_t i;
	uint32_t temp_steps[5], untemp_steps[5];

	// Tempering steps
	temp_steps[0] = val;
	temp_steps[1] = temp_steps[0] ^ (temp_steps[0] >> 11);
	temp_steps[2] = temp_steps[1] ^ ((temp_steps[1] << 7) & MT19937_MAGIC_A);
	temp_steps[3] = temp_steps[2] ^ ((temp_steps[2] << 15) & MT19937_MAGIC_B);
	temp_steps[4] = temp_steps[3] ^ (temp_steps[3] >> 18);

	// Untempering steps
	untemp_steps[0] = temp_steps[4];
	untemp_steps[1] = untemp_steps[0] ^ (untemp_steps[0] >> 18);
	untemp_steps[2] =  (untemp_steps[1]        ) ^
					  ((untemp_steps[1] << 15) & MT19937_MAGIC_B);
	untemp_steps[3] = ( untemp_steps[2]        ) ^
	                  ((untemp_steps[2] << 7 ) &  MT19937_MAGIC_A) ^
	                  ((((untemp_steps[2] << 7) &  MT19937_MAGIC_A) << 7) &  MT19937_MAGIC_A) ^
	                  ((((((untemp_steps[2] << 7) &  MT19937_MAGIC_A) << 7) &  MT19937_MAGIC_A)  << 7) &  MT19937_MAGIC_A) ^
	                  ((((((((untemp_steps[2] << 7) &  MT19937_MAGIC_A) << 7) &  MT19937_MAGIC_A)  << 7) &  MT19937_MAGIC_A) << 7) &  MT19937_MAGIC_A);
	untemp_steps[4] = untemp_steps[3] ^ (untemp_steps[3] >> 11) ^ (untemp_steps[3] >> 22);


	for (i = 0; i < 5; i++)
		if (untemp_steps[4] != temp_steps[0])
			printf("Tempering steps %zu: 0x%02x - 0x%02x \n", i, temp_steps[i], untemp_steps[4-i]);
	
}


/* 

 * Actual untempering function. Rely on the fact that logical shifts (llr and lrr) 
 * drops (over/under)flowing bits. 
 */
uint32_t untemper_value(const uint32_t temp_val)
{
	size_t i;
	uint32_t tmp, untempered;

	// Step 4 : x ^= x >> 18
	untempered = temp_val ^ (temp_val >> 18);

	// Step 3 : x ^= (x << 15) ^ b
	untempered	^= ((untempered << 15) & MT19937_MAGIC_B);
    
	// Step 2 : x ^= (x << 7) ^ a
	tmp = ((untempered << 7 ) &  MT19937_MAGIC_A);
    for (i = 0; i < 4; i++)
    {
       untempered ^= tmp;           
       tmp = ((tmp << 7 ) &  MT19937_MAGIC_A);
    }

	// Step 1 : x ^= x >> 11
	untempered ^= (untempered >> 11) ^ (untempered >> 22);

	return untempered;
}

/*
 *  Compute the array of following untempered states, based on 
 *  the previous ones. This function is copied from the mt19337 lib.
 */
void generate_predicted_states(uint32_t mt_states[])
{
	uint32_t tmp;
	unsigned int i;

	for (i = 0; i < MT19937_ARRAY_LEN; i++)
	{
		tmp = (mt_states[i] & 0x80000000) + 
		      (mt_states[(i+1) % MT19937_ARRAY_LEN] & 0x7fffffff);
		
		mt_states[i] = mt_states[(i+397) % MT19937_ARRAY_LEN] ^ (tmp >> 1);
		

		if (tmp % 2)
			mt_states[i] ^= 0x9908b0df;
	}
}

/*
 *	Given a round of mt19937 output, predict the following values by reversing the
 *  tempering function and use the discovered internal states to generate the following ones.
 */
void predict_rng_output(uint32_t mt_predicted[], const uint32_t mt_output[], size_t pred_len)
{
	size_t i, r;
	uint32_t mt_states[MT19937_ARRAY_LEN];

	for (i = 0; i < MT19937_ARRAY_LEN; i++)
		mt_states[i] = untemper_value(mt_output[i]);		

	generate_predicted_states(mt_states);

	for (r = 0; r < pred_len; r += MT19937_ARRAY_LEN)
	{
		uint32_t cpy_len = (pred_len - r < MT19937_ARRAY_LEN) ? pred_len : MT19937_ARRAY_LEN;
		memcpy(mt_predicted + r, mt_states, cpy_len*sizeof(uint32_t));	

		// Tempering
		for (i = r; i < r + cpy_len; i++)
		{
			mt_predicted[i] ^= (mt_predicted[i] >> 11);
			mt_predicted[i] ^= (mt_predicted[i] <<  7) & MT19937_MAGIC_A;
			mt_predicted[i] ^= (mt_predicted[i] << 15) & MT19937_MAGIC_B;
			mt_predicted[i] ^= (mt_predicted[i] >> 18);
		}


		generate_predicted_states(mt_states);
	}
}

/*
 * "Clone" an MT19937 RNG from its output
 */
int main(int argc, char *argv[])
{
	size_t i;
	unsigned int result;
	uint32_t seed = time(NULL);
	struct mt19937_t mt_engine;
	mt19937_init(&mt_engine, seed);

	// Test reverse tempering
	/*for (i = 0; i < 0xffffffff; i++)
		test_untemper(0x12345678);
*/
	// Generate two rounds of rng output
	for (i = 0; i < 2* MT19937_ARRAY_LEN; i++)
		mt_output[i] = mt19937_get_value(&mt_engine);

	// Predict output from the first round values
	predict_rng_output(mt_predicted, mt_output, MT19937_ARRAY_LEN); 	

	//Verification
	result = 0x01;
	for (i = 0; i < MT19937_ARRAY_LEN; i++)
		result &= (mt_output[MT19937_ARRAY_LEN + i] == mt_predicted[i]); 

	printf("mt19973 %s cloned", (result) ? "successfully" : "unsuccessfully");

	return 0x00;
}