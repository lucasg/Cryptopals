#include "analyze.h"
#include "constants.h"
#include "../tools/ifreq.h"
#include "../tools/xor.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h> 
#include <sys/stat.h>

/*
 *  Loop around files in ctext folder in 
 *  order to find the minimal common length
 *  of the ciphertexts.
 */
int get_min_ciphertext_len()
{
	size_t min_ctext_size = 0; 
	DIR *d;
	struct stat st;
	struct dirent *dir_f;
	char fn[FILENAME_MAX];
	int len = strlen(ciphertext_folder);

	strcpy(fn, ciphertext_folder);
	fn[len++] = '/';

	d = opendir(ciphertext_folder);
	if (NULL != d)
	{
		
		while ((dir_f = readdir(d)) != NULL)
	    {
	    	if (!strcmp(dir_f->d_name, ".") || !strcmp(dir_f->d_name, ".."))
				continue;

	    	strncpy(fn + len, dir_f->d_name, FILENAME_MAX - len);
	    	stat(fn, &st);

	    	if (!min_ctext_size)
	    		min_ctext_size = st.st_size;

	    	if (min_ctext_size > st.st_size)
	    		min_ctext_size = st.st_size;
	    }
	}
	closedir(d);

	return min_ctext_size;
}

/*
 *  Load every ciphertext present (truncated into their common minimal length) into memory
 */
int load_ciphertext_matrix(unsigned char ctext_mat[], unsigned int ctext_len)
{
	FILE *fd;
	DIR *d;
	struct dirent *dir_f;
	char fn[FILENAME_MAX];
	int len = strlen(ciphertext_folder);

	strcpy(fn, ciphertext_folder);
	fn[len++] = '/';

	d = opendir(ciphertext_folder);
	if (NULL == d)
		return 0x01;


	while ((dir_f = readdir(d)) != NULL)
    {
    	if (!strcmp(dir_f->d_name, ".") || !strcmp(dir_f->d_name, ".."))
			continue;

    	strncpy(fn + len, dir_f->d_name, FILENAME_MAX - len);
    	
    	fd = fopen(fn, "rb");
    	if( NULL == fd )
    		continue;


    	unsigned int j = atoi(dir_f->d_name);
    	fread(ctext_mat + j*ctext_len, sizeof(char), ctext_len, fd);
    	fclose(fd);
    }

	closedir(d);

	return 0x00;
}

/*
 * Like for challenge #04 and #06, detect the most common character,
 * which is highly likely to be the space char.
 */
char detect_key_single_line(char *lencdata, size_t llen)
{
	char ret_char;
	int* tmp, i;

	tmp = malloc(llen*sizeof(int));
	if (NULL == tmp)
		return 0x00;

	for (i=0; i < llen; i++)
		tmp[i] = lencdata[i];

	ifreq( tmp, NULL, llen);

	
	ret_char = tmp[0];

	free(tmp);

	return ret_char;
}


/* 
 * Analyze the ciphertexts files in order to 
 * decrypt automatically the content.
 */
int analyze_ciphertexts()
{
	unsigned char *ctext_mat, *ctext_mat_t, *key_img, *plain;
	size_t i,k, ctxtidx, charidx;
	size_t ctext_len = get_min_ciphertext_len();
	printf(" Min ciphertext length : %d bytes\n", (int) ctext_len);

	ctext_mat = malloc((ctext_len*60)*sizeof(char));
	if (NULL == ctext_mat)
		return 0x01;
	memset(ctext_mat, 0, (ctext_len*60)*sizeof(char));

	load_ciphertext_matrix(ctext_mat, ctext_len);

	ctext_mat_t = malloc((ctext_len*60)*sizeof(char));
	if (NULL == ctext_mat_t)
	{
		free(ctext_mat);
		return 0x01;
	}
	
	/*
	 *	Transposition
	 */
	for(ctxtidx = 0; ctxtidx < 60; ctxtidx++)
		for (charidx = 0; charidx < ctext_len; charidx++)
			ctext_mat_t[charidx*60 + ctxtidx] = ctext_mat[ctxtidx*(ctext_len)+charidx];



	key_img = malloc((ctext_len)*sizeof(char));
	if (NULL == key_img)
	{
		free(ctext_mat);
		free(ctext_mat_t);
		return 0x01;
	}

	/*
	 * Single line detect
	 */
	for(k = 0; k < ctext_len; k++)
	{
		key_img[k] = ' ' ^ detect_key_single_line((char*) ctext_mat_t + k*60, 60);
	}



	plain = malloc((ctext_len+1)*sizeof(char));
	if (NULL == plain)
	{
		free(key_img);
		free(ctext_mat);
		free(ctext_mat_t);
		return 0x01;
	}
	plain[ctext_len] = 0x00;


	/*
	 * Decryption
	 */
	for (i = 0; i < 60; i++)
	{
		xor_decode(plain, ctext_mat + i*ctext_len, ctext_len, key_img, ctext_len );
		printf("%d : %s\n", i, plain );
	}



	free(plain);
	free(key_img);
	free(ctext_mat);
	free(ctext_mat_t);
	
	return 0x00;
}