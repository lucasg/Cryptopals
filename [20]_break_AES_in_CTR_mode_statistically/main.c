#include "generate.h"
#include "analyze.h"

#include <stdio.h>
#include <stdlib.h>


/*
 * Encrypt every plaintext using the same keystream and save the ciphertexts in folder ctext
 */
int main(int argc, char *argv[])
{
	return generate_ciphertexts() || analyze_ciphertexts();
}