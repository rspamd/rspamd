
#include <pthread.h>
#include <stdlib.h>
int main (void)
{
	pthread_mutexattr_t mattr;
	if (pthread_mutexattr_init(&mattr) != 0) return 0;
	if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) return 0;
	if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST) != 0) return 0;
	return 1;
}
