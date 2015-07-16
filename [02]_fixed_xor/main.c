#include <stdio.h>
#include <errno.h>
#include <string.h>



/*
 *  usage : fixed_xor.EXEC input1 input2 > output
 */
int main (int argc, char *argv[])
{	
	char input1_c, input2_c; 
	FILE *input1, *input2;


	if (argc < 3)
		return 1;

	input1 = fopen(argv[1], "rb");
	if (NULL == input1)
	{
		printf("Error when calling fopen(%s) : %s\n", argv[1], strerror(errno));
		return errno;
	}

	input2	= fopen(argv[2], "rb");
	if (NULL == input2)
	{
		printf("Error when calling fopen(%s) : %s\n", argv[2], strerror(errno));

		fclose(input1);
		return errno;
	}

	while ((1 == fread(&input1_c, 1,1, input1)) && (1 == fread(&input2_c, 1,1, input2)))
		printf("%c", input1_c ^ input2_c);
	

	fclose(input1);
	fclose(input2);

	return 0;
}