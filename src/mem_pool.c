#include <sys/types.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include "config.h"

#ifdef HAVE_SCHED_YIELD
#include <sched.h>
#endif

#ifdef HAVE_NANOSLEEP
#include <time.h>
#endif

#include "mem_pool.h"

/* Sleep time for spin lock in nanoseconds */
#define MUTEX_SLEEP_TIME 10000000L

#ifdef _THREAD_SAFE
pthread_mutex_t stat_mtx = PTHREAD_MUTEX_INITIALIZER;
#define STAT_LOCK() do { pthread_mutex_lock (&stat_mtx); } while (0)
#define STAT_UNLOCK() do { pthread_mutex_unlock (&stat_mtx); } while (0)
#else
#define STAT_LOCK() do {} while (0)
#define STAT_UNLOCK() do {} while (0)
#endif

/* 
 * This define specify whether we should check all pools for free space for new object
 * or just begin scan from current (recently attached) pool
 * If MEMORY_GREEDY is defined, then we scan all pools to find free space (more CPU usage, slower
 * but requires less memory). If it is not defined check only current pool and if object is too large
 * to place in it allocate new one (this may cause huge CPU usage in some cases too, but generally faster than
 * greedy method)
 */
#undef MEMORY_GREEDY

/* Internal statistic */
static memory_pool_stat_t *stat = NULL;

static struct _pool_chain *
pool_chain_new (size_t size) 
{
	struct _pool_chain *chain;
	chain = g_malloc (sizeof (struct _pool_chain));
	chain->begin = g_malloc (size);
	chain->len = size;
	chain->pos = chain->begin;
	chain->next = NULL;
	STAT_LOCK ();
	stat->chunks_allocated ++;
	STAT_UNLOCK ();
	
	return chain;
}

static struct _pool_chain_shared *
pool_chain_new_shared (size_t size) 
{
	struct _pool_chain_shared *chain;

#if defined(HAVE_MMAP_ANON)
	chain = mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
	chain->begin = ((u_char *)chain) + sizeof (struct _pool_chain_shared);
	if (chain == MAP_FAILED) {
		return NULL;
	}
#elif defined(HAVE_MMAP_ZERO)
	int fd;

	fd = open ("/dev/zero", O_RDWR);
	if (fd == -1) {
		return NULL;
	}
	chain = mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	chain->begin = ((u_char *)chain) + sizeof (struct _pool_chain_shared);
	if (chain == MAP_FAILED) {
		return NULL;
	}
#else
#	error No mmap methods are defined
#endif
	chain->len = size;
	chain->pos = chain->begin;
	chain->lock = 0;
	chain->next = NULL;
	STAT_LOCK ();
	stat->shared_chunks_allocated ++;
	STAT_UNLOCK ();
	
	return chain;
}

memory_pool_t* 
memory_pool_new (size_t size)
{
	memory_pool_t *new;
	
	/* Allocate statistic structure if it is not allocated before */
	if (stat == NULL) {
#if defined(HAVE_MMAP_ANON)
		stat = mmap (NULL, sizeof (memory_pool_stat_t), PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
		g_assert (stat != MAP_FAILED);
#elif defined(HAVE_MMAP_ZERO)
		int fd;

		fd = open ("/dev/zero", O_RDWR);
		g_assert (fd != -1);
		stat = mmap (NULL, sizeof (memory_pool_stat_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		g_assert (chain != MAP_FAILED);
#else
#	error No mmap methods are defined
#endif
	}

	new = g_malloc (sizeof (memory_pool_t));
	new->cur_pool = pool_chain_new (size);
	new->shared_pool = NULL;
	new->first_pool = new->cur_pool;
	new->destructors = NULL;

	return new;
}

void *
memory_pool_alloc (memory_pool_t *pool, size_t size)
{
	u_char *tmp;
	struct _pool_chain *new, *cur;

	if (pool) {
#ifdef MEMORY_GREEDY
		cur = pool->first_pool;
#else
		cur = pool->cur_pool;
#endif
		/* Find free space in pool chain */
		while (memory_pool_free (cur) < size && cur->next) {
			cur = cur->next;
		}
		if (cur->next == NULL && memory_pool_free (cur) < size) {
			/* Allocate new pool */
			if (cur->len >= size) {
				new = pool_chain_new (cur->len);
			}
			else {
				new = pool_chain_new (size + cur->len);
			}
			/* Attach new pool to chain */
			cur->next = new;
			pool->cur_pool = new;
			new->pos += size;
			STAT_LOCK ();
			stat->bytes_allocated += size;
			STAT_UNLOCK ();
			return new->begin;
		}	
		tmp = cur->pos;
		cur->pos += size;
		STAT_LOCK ();
		stat->bytes_allocated += size;
		STAT_UNLOCK ();
		return tmp;
	}
	return NULL;
}

void *
memory_pool_alloc0 (memory_pool_t *pool, size_t size)
{
	void *pointer = memory_pool_alloc (pool, size);
	if (pointer) {
		bzero (pointer, size);
	}
	return pointer;
}

char *
memory_pool_strdup (memory_pool_t *pool, const char *src)
{
	size_t len;
	char *newstr;

	if (src == NULL) {
		return NULL;
	}

	len = strlen (src);
	newstr = memory_pool_alloc (pool, len + 1);
	memcpy (newstr, src, len + 1);
	return newstr;
}

void *
memory_pool_alloc_shared (memory_pool_t *pool, size_t size)
{
	u_char *tmp;
	struct _pool_chain_shared *new, *cur;

	if (pool) {
		cur = pool->shared_pool;
		if (!cur) {
			cur = pool_chain_new_shared (pool->first_pool->len);
			pool->shared_pool = cur;
		}

		/* Find free space in pool chain */
		while (memory_pool_free (cur) < size && cur->next) {
			cur = cur->next;
		}
		if (cur->next == NULL && memory_pool_free (cur) < size) {
			/* Allocate new pool */
			if (cur->len >= size) {
				new = pool_chain_new_shared (cur->len);
			}
			else {
				new = pool_chain_new_shared (size + cur->len);
			}
			/* Attach new pool to chain */
			cur->next = new;
			new->pos += size;
			STAT_LOCK ();
			stat->bytes_allocated += size;
			STAT_UNLOCK ();
			return new->begin;
		}
		tmp = cur->pos;
		cur->pos += size;
		STAT_LOCK ();
		stat->bytes_allocated += size;
		STAT_UNLOCK ();
		return tmp;
	}
	return NULL;
}

/* Find pool for a pointer, returns NULL if pointer is not in pool */
static struct _pool_chain_shared *
memory_pool_find_pool (memory_pool_t *pool, void *pointer)
{
	struct _pool_chain_shared *cur = pool->shared_pool;

	while (cur) {
		if ((u_char *)pointer >= cur->begin && (u_char *)pointer <= (cur->begin + cur->len)) {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}

static inline void
__mutex_spin (gint *mutex)
{
		/* lock was aqquired */
#ifdef HAVE_NANOSLEEP
		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = MUTEX_SLEEP_TIME;
		/* Spin */
		while (nanosleep (&ts, &ts) == -1 && errno == EINTR);
#endif
#ifdef HAVE_SCHED_YIELD
		(void)sched_yield ();
#endif
#if !defined(HAVE_NANOSLEEP) && !defined(HAVE_SCHED_YIELD)
#	error No methods to spin are defined
#endif

}

static void
memory_pool_mutex_spin (gint *mutex)
{
	while (!g_atomic_int_compare_and_exchange (mutex, 0, 1)) {
		__mutex_spin (mutex);
	}
}

/* Simple implementation of spinlock */
void
memory_pool_lock_shared (memory_pool_t *pool, void *pointer)
{
	struct _pool_chain_shared *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	
	memory_pool_mutex_spin (&chain->lock);
}

void memory_pool_unlock_shared (memory_pool_t *pool, void *pointer)
{
	struct _pool_chain_shared *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	
	(void)g_atomic_int_dec_and_test (&chain->lock);
}

void
memory_pool_add_destructor (memory_pool_t *pool, pool_destruct_func func, void *data)
{
	struct _pool_destructors *cur;

	cur = memory_pool_alloc (pool, sizeof (struct _pool_destructors));
	if (cur) {
		cur->func = func;
		cur->data = data;
		cur->prev = pool->destructors;
		pool->destructors = cur;
	}
}

void
memory_pool_delete (memory_pool_t *pool)
{
	struct _pool_chain *cur = pool->first_pool, *tmp;
	struct _pool_chain_shared *cur_shared = pool->shared_pool, *tmp_shared;
	struct _pool_destructors *destructor = pool->destructors;
	
	/* Call all pool destructors */
	while (destructor) {
		destructor->func (destructor->data);
		destructor = destructor->prev;
	}

	while (cur) {
		tmp = cur;
		cur = cur->next;
		g_free (tmp->begin);
		g_free (tmp);
		STAT_LOCK ();
		stat->chunks_freed ++;
		STAT_UNLOCK ();
	}
	/* Unmap shared memory */
	while (cur_shared) {
		tmp_shared = cur_shared;
		cur_shared = cur_shared->next;
		munmap (tmp_shared, tmp_shared->len + sizeof (struct _pool_chain_shared));
		STAT_LOCK ();
		stat->chunks_freed ++;
		STAT_UNLOCK ();
	}

	g_free (pool);
}

void
memory_pool_stat (memory_pool_stat_t *st)
{
	if (stat) {
		st->bytes_allocated = stat->bytes_allocated;
		st->chunks_allocated = stat->chunks_allocated;
		st->shared_chunks_allocated = stat->shared_chunks_allocated;
		st->chunks_freed = stat->chunks_freed;
	}
}

#define FIXED_POOL_SIZE 4095
size_t
memory_pool_get_size ()
{
#ifdef HAVE_GETPAGESIZE
	return getpagesize () - 1;
#else
	return FIXED_POOL_SIZE;
#endif
}

gint* 
memory_pool_get_mutex (memory_pool_t *pool)
{
	gint *res;
	if (pool != NULL) {
		res = memory_pool_alloc_shared (pool, sizeof (gint));
		/* Initialize unlocked */
		*res = 0;
		return res;
	}
	return NULL;
}

void 
memory_pool_lock_mutex (gint *mutex)
{
	memory_pool_mutex_spin (mutex);
}

void 
memory_pool_unlock_mutex (gint *mutex)
{
	(void)g_atomic_int_dec_and_test (mutex);
}

memory_pool_rwlock_t* 
memory_pool_get_rwlock (memory_pool_t *pool)
{
	memory_pool_rwlock_t *lock;

	lock = memory_pool_alloc_shared (pool, sizeof (memory_pool_rwlock_t));
	lock->__r_lock = memory_pool_get_mutex (pool);
	lock->__w_lock = memory_pool_get_mutex (pool);

	return lock;
}

void 
memory_pool_rlock_rwlock (memory_pool_rwlock_t *lock)
{
	/* Spin on write lock */
	while (g_atomic_int_get (lock->__w_lock)) {
		__mutex_spin (lock->__w_lock);
	}
	
	g_atomic_int_inc (lock->__r_lock);
}

void 
memory_pool_wlock_rwlock (memory_pool_rwlock_t *lock)
{
	/* Spin on write lock first */
	memory_pool_mutex_spin (lock->__w_lock);
	/* Now we have write lock set up */
	/* Wait all readers */
	while (g_atomic_int_get (lock->__r_lock)) {
		__mutex_spin (lock->__r_lock);
	}
}

void 
memory_pool_runlock_rwlock (memory_pool_rwlock_t *lock)
{
	(void)g_atomic_int_dec_and_test (lock->__r_lock);
}

void 
memory_pool_wunlock_rwlock (memory_pool_rwlock_t *lock)
{
	(void)g_atomic_int_dec_and_test (lock->__w_lock);
}

/*
 * vi:ts=4
 */
