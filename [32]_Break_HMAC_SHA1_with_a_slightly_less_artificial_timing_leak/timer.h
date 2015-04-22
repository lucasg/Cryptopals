/*
 *  A nice little timing utility. Cross-platform (win, posix) to boot.
 *  However it is not reentrant (you would need a specific container to achieve that).
 */

#ifndef _TIMER_H_
	#define _TIMER_H_


// Start the timer
void start_timer();

// Stop the timer and return the time difference in ms.
long long end_timer();

#endif /* _TIMER_H_ */