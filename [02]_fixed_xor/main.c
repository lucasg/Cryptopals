#include <stdio.h>




// usage : fixed_xor.EXEC input1 input2 > output
int main (int argc, char *argv[])
{	
	if (argc < 3)
		return 1;

	FILE *input1 = fopen(argv[1], "rb"),
	 	 *input2 = fopen(argv[2], "rb");

	if ( NULL == input1 || NULL == input2)
		return 1;

	char input1_c, input2_c; 
	while ( fread(&input1_c, 1,1, input1) && fread(&input2_c, 1,1, input2) )
		printf("%c", input1_c ^ input2_c);
	


	fclose(input1);
	fclose(input2);

	return 0;
}