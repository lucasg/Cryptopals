#include "../tools/b64.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>


// Usage : b64enc.EXEC < input > output
int main(int argc, char *argv[])
{
	char ascii[3]= {0}, b64[4]= {0};
	while (read(0, ascii, 3))
	{

		b64_encode(b64, ascii, 3);

		write(1, b64, 4);


		memset(b64,0, sizeof(b64));
		memset(ascii,0, sizeof(ascii));

	}

	return 0;
}