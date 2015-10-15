/* Libottery by Nick Mathewson.

   This software has been dedicated to the public domain under the CC0
   public domain dedication.

   To the extent possible under law, the person who associated CC0 with
   libottery has waived all copyright and related or neighboring rights
   to libottery.

   You should have received a copy of the CC0 legalcode along with this
   work in doc/cc0.txt.  If not, see
      <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#ifndef OTTERY_LOCKING_H_HEADER_INCLUDED_
#define OTTERY_LOCKING_H_HEADER_INCLUDED_

/* We don't need locks when building rspamd */
#ifdef BUILD_RSPAMD
#define OTTERY_NO_LOCKS
#endif

/* Locks */
#ifdef OTTERY_NO_LOCKS
/* Nothing here. */
#elif defined(__APPLE__) && !defined(OTTERY_NO_SPINLOCKS)
#define OTTERY_OSATOMIC_LOCKS
#include <libkern/OSAtomic.h>
#elif defined(_WIN32)
#define OTTERY_CRITICAL_SECTION
#include <windows.h>
#elif defined(HAVE_PTHREAD)
#define OTTERY_PTHREADS
#include <pthread.h>
#else
#define OTTERY_NO_LOCKS
#endif

#ifdef OTTERY_NO_LOCKS
#define DECL_LOCK(mutex)
#elif defined(OTTERY_OSATOMIC_LOCKS)
#define DECL_LOCK(mutex)  OSSpinLock mutex;
#elif defined(OTTERY_CRITICAL_SECTION)
#define DECL_LOCK(mutex)  CRITICAL_SECTION mutex;
#elif defined(OTTERY_PTHREADS)
#define DECL_LOCK(mutex)  pthread_mutex_t mutex;
#endif

#if defined(OTTERY_PTHREADS)
#define INIT_LOCK(mutex)                        \
  (pthread_mutex_init((mutex), NULL) != 0)
/** Acquire the lock for the state "st". */
#define ACQUIRE_LOCK(mutex) do {                \
    pthread_mutex_lock(mutex);                  \
  } while (0)
/** Release the lock for the state "st". */
#define RELEASE_LOCK(mutex) do { \
    pthread_mutex_unlock(mutex); \
  } while (0)
#define DESTROY_LOCK(mutex) do {                \
    pthread_mutex_destroy(mutex);               \
  } while (0)

#elif defined(OTTERY_CRITICAL_SECTION)
#define INIT_LOCK(mutex)                        \
  (InitializeCriticalSectionAndSpinCount((mutex), 3000) == 0)
#define ACQUIRE_LOCK(mutex) do {                                \
    EnterCriticalSection(mutex);                                \
  } while (0)
#define RELEASE_LOCK(mutex) do { \
    LeaveCriticalSection(mutex); \
  } while (0)
#define DESTROY_LOCK(mutex) do {                \
    DeleteCriticalSection(mutex);               \
  } while (0)

#elif defined(OTTERY_OSATOMIC_LOCKS)
#define INIT_LOCK(mutex)                        \
  ((*(mutex) = 0), 0)
#define ACQUIRE_LOCK(mutex) do {                \
    OSSpinLockLock(mutex);                      \
  } while (0)
#define RELEASE_LOCK(mutex) do {       \
    OSSpinLockUnlock(mutex);           \
  } while (0)
#define DESTROY_LOCK(mutex) ((void)0)

#elif defined(OTTERY_NO_LOCKS)
#define INIT_LOCK(mutex)    (0)
#define DESTROY_LOCK(mutex) ((void)0)
#define ACQUIRE_LOCK(mutex) ((void)0)
#define RELEASE_LOCK(mutex) ((void)0)
#else
#error How do I lock?
#endif

#endif
