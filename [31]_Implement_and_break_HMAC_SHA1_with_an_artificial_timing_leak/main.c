#include "timer.h"
#include "sha1.h"
#include "hex.h"
#include "curl/curl.h"
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>



#define BASE_URL_LEN (46)
const static char base_url[BASE_URL_LEN] = "http://localhost:8080/test?file=foo&signature=";
static char full_url[BASE_URL_LEN + 2*SHA1_HASH_LENGTH + 1] = "http://localhost:8080/test?file=foo&signature=";


/*  
 *  Disabling curl requests output (error 500, etc.)
 */
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
   return size * nmemb;
}

int main(void)
{
  CURL *curl;

  size_t i, j, c, candidate;
  long diff, max_latency = 0, http_res;

  memset(full_url + BASE_URL_LEN, '0', (2*SHA1_HASH_LENGTH)*sizeof(char));
  full_url[ BASE_URL_LEN + 2*SHA1_HASH_LENGTH ] = 0;


  printf("Warning : this exercice takes a long time to run (approx. 2000 sec or 30mins).\n");
  printf("Go grab a coffee and watch a movie in the meantime.\n");

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

    max_latency = 0x00;
    for (i = 0; i < SHA1_HASH_LENGTH; i++)
    {
      candidate = 0x00;

      /* Iterate over every possible char, looking for the one with the maximum response time */
      for (j = 0; j < 256; j++)
      {
        c = j & 0xff;
        hex_encode(full_url + BASE_URL_LEN + 2*i, (const char *) &c, 2);
        curl_easy_setopt(curl, CURLOPT_URL, full_url);

        /* Timing the request */
        start_timer();
        curl_easy_perform(curl);
        diff = end_timer();


        if (j && diff > max_latency)
        {
          max_latency = diff;
          candidate = c;
        }
      }

      printf("Char candidate for pos #%d : 0x%02x, latency=%ld ms\n", i+1, candidate, max_latency );
      hex_encode(full_url + BASE_URL_LEN + 2*i, (const char *) &candidate, 2);
    }
 

    printf("String candidate : %s\n", full_url);
    

    /* Check we have a valid string */
    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_perform(curl);
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_res);

    if(200 == http_res)
      printf("We have a valid hmac\n");
      
    
    curl_easy_cleanup(curl);
  }
  return 0;
}