#include "aes_128_key_schedule.h"
#include "aes_128_s_box.h"
#include <stdio.h>
#include <string.h>


static const unsigned int num_rounds_128_bit = 10;



void rotate(unsigned char *in) {
    unsigned char a,c;
    a = in[0];
    for(c=0;c<3;c++) 
        in[c] = in[c + 1];
    in[3] = a;
    return;
}

/* Calculate the rcon used in key expansion */
unsigned char rcon(unsigned char in) {
    unsigned char c=1;
    if(in == 0)  
        return 0; 
    while(in != 1) {
	unsigned char b;
	b = c & 0x80;
	c <<= 1;
	if(b == 0x80) {
		c ^= 0x1b;
	}
        in--;
    }
    return c;
}

/* This is the core key expansion, which, given a 4-byte value,
 * does some scrambling */
void schedule_core(unsigned char *in, unsigned char i) {
    unsigned char a;
    /* Rotate the input 8 bits to the left */
    rotate(in);
    /* Apply Rijndael's s-box on all 4 bytes */
    for(a = 0; a < 4; a++) 
        in[a] = aes_128_s_box[in[a]];
    /* On just the first byte, add 2^i to the byte */
    in[0] ^= rcon(i);
}

// AES key expansion algorithm
void aes_128_key_expansion(unsigned char *round_keys, const unsigned char *key)
{
	unsigned char t[4];
	/* c is 16 because the first sub-key is the user-supplied key */
	unsigned char c = 16;
	unsigned char i = 1;
	unsigned char a;

	memcpy(round_keys, key, 16);

    /* We need 11 sets of sixteen bytes each for 128-bit mode */
    while(c < 176) {
        /* Copy the temporary variable over from the last 4-byte
         * block */
        for(a = 0; a < 4; a++) 
            t[a] = round_keys[a + c - 4];
        /* Every four blocks (of four bytes), 
         * do a complex calculation */
        if(c % 16 == 0) {
			schedule_core(t,i);
			i++;
		}
        for(a = 0; a < 4; a++) {
	        round_keys[c] = round_keys[c - 16] ^ t[a];
	        c++;
        }
    }
}


void aes_128_add_round_key(unsigned char *state, const unsigned char *key)
{
	unsigned int i;
	for (i = 0; i < 16; i++)
		state[i] ^= key[i];
}

