

#ifdef _WIN32
#include <windows.h>
	static LARGE_INTEGER start, end, freq;
	static unsigned int query_frequency_called = 0x00;
#else
#include <time.h>
static struct timespec start, end;

// Compute the correct time difference.
struct timespec tdiff(struct timespec start, struct timespec end)
{
  struct timespec temp;
  if ((end.tv_nsec-start.tv_nsec)<0) {
    temp.tv_sec = end.tv_sec-start.tv_sec-1;
    temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
  } else {
    temp.tv_sec = end.tv_sec-start.tv_sec;
    temp.tv_nsec = end.tv_nsec-start.tv_nsec;
  }
  return temp;
}

#endif


void start_timer()
{
#ifdef _WIN32
	if (!query_frequency_called)
	{
		QueryPerformanceFrequency(&freq);
		query_frequency_called = 0x01;
	}

	QueryPerformanceCounter(&start);
#else

	clock_gettime(CLOCK_REALTIME, &start);	
#endif
}



long long end_timer()
{
#ifdef _WIN32
	if (!query_frequency_called)
	{
		QueryPerformanceFrequency(&freq);
		query_frequency_called = 0x01;
	}

	QueryPerformanceCounter(&end);

	return (end.QuadPart - start.QuadPart)*1000/freq.QuadPart;
#else

	clock_gettime(CLOCK_REALTIME, &end);

	return tdiff(start,end).tv_sec*1000 + tdiff(start,end).tv_nsec / (1000*1000);	
#endif

}