#include "mt19937.h"
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>	
#include <stdio.h>

int main(int argc, char *argv[])
{
	srand(time(NULL));
	uint32_t seed = time(NULL), test_seed, target_value;
	struct mt19937_t target_engine, trial_engine;
	mt19937_init(&target_engine, seed);

	target_value = mt19937_get_value(&target_engine);
	sleep( 2 + (rand() % 10) );

	uint32_t cur_time = time(NULL);
	for (test_seed = cur_time - 10000; test_seed < cur_time; test_seed++)
	{
		mt19937_init(&trial_engine, test_seed);
		if (target_value == mt19937_get_value(&trial_engine))
			break;
		
	}
	
	printf("Seed : %s", (seed == test_seed) ? "cracked" : "wrong");

	return 0x00;
}