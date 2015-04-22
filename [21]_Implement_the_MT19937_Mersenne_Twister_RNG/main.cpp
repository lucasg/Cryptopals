#include "mt19937.h"
#include <iostream>
#include <random>
#include <time.h>
#include <assert.h>
#include <stdint.h>

#define GET_RESULT_STR(ut_result) ( ut_result ? "correct" : "incorrect")

int main(int argc, char *argv[])
{
	unsigned int i, ut_result;
	uint32_t v_val, t_val;

	uint32_t seed = time(NULL);
	mt19937_t test_engine;


	mt19937_init(&test_engine, seed);
	std::mt19937 validator (seed);

	ut_result = 0x01;
	std::cout << "\t\tvalidator  \tmt19937 " << std::endl;
	std::cout << "\t\t---------  \t--------" << std::endl;
	for (i = 0; i < 10; i++)
	{	
		v_val = validator();
		t_val = mt19937_get_value(&test_engine);
		ut_result &= (v_val == t_val);

		std::cout << i << "\t\t" << v_val << "\t" << t_val << std::endl;
	}
	

	std::cout << "MT19973 Generator " << GET_RESULT_STR(ut_result)  << std::endl;
	return 0x00;
}