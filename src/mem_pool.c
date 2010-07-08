/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"

/* Sleep time for spin lock in nanoseconds */
#define MUTEX_SLEEP_TIME 10000000L
#define MUTEX_SPIN_COUNT 100

#ifdef _THREAD_SAFE
pthread_mutex_t                 stat_mtx = PTHREAD_MUTEX_INITIALIZER;
#   define STAT_LOCK() do { pthread_mutex_lock (&stat_mtx); } while (0)
#   define STAT_UNLOCK() do { pthread_mutex_unlock (&stat_mtx); } while (0)
#else
#   define STAT_LOCK() do {} while (0)
#   define STAT_UNLOCK() do {} while (0)
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
static memory_pool_stat_t      *mem_pool_stat = NULL;

static struct _pool_chain      *
pool_chain_new (memory_pool_ssize_t size)
{
	struct _pool_chain             *chain;

	g_assert (size > 0);

	chain = g_slice_alloc (sizeof (struct _pool_chain));

	g_assert (chain != NULL);

	chain->begin = g_slice_alloc (size);

	g_assert (chain->begin != NULL);

	chain->len = size;
	chain->pos = chain->begin;
	chain->next = NULL;
	STAT_LOCK ();
	mem_pool_stat->chunks_allocated++;
	STAT_UNLOCK ();

	return chain;
}

static struct _pool_chain_shared *
pool_chain_new_shared (memory_pool_ssize_t size)
{
	struct _pool_chain_shared      *chain;

#if defined(HAVE_MMAP_ANON)
	chain = (struct _pool_chain_shared *)mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	g_assert (chain != MAP_FAILED);
	chain->begin = ((u_char *) chain) + sizeof (struct _pool_chain_shared);
#elif defined(HAVE_MMAP_ZERO)
	int                             fd;

	fd = open ("/dev/zero", O_RDWR);
	if (fd == -1) {
		return NULL;
	}
	chain = (struct _pool_chain_shared *)mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	g_assert (chain != MAP_FAILED);
	chain->begin = ((u_char *) chain) + sizeof (struct _pool_chain_shared);
#else
#   	error No mmap methods are defined
#endif
	chain->len = size;
	chain->pos = chain->begin;
	chain->lock = NULL;
	chain->next = NULL;
	STAT_LOCK ();
	mem_pool_stat->shared_chunks_allocated++;
	STAT_UNLOCK ();

	return chain;
}


/**
 * Allocate new memory poll 
 * @param size size of pool's page
 * @return new memory pool object
 */
memory_pool_t                  *
memory_pool_new (memory_pool_ssize_t size)
{
	memory_pool_t                  *new;

	g_assert (size > 0);
	/* Allocate statistic structure if it is not allocated before */
	if (mem_pool_stat == NULL) {
#if defined(HAVE_MMAP_ANON)
		mem_pool_stat = (memory_pool_stat_t *)mmap (NULL, sizeof (memory_pool_stat_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		g_assert (stat != MAP_FAILED);
#elif defined(HAVE_MMAP_ZERO)
		int                             fd;

		fd = open ("/dev/zero", O_RDWR);
		g_assert (fd != -1);
		mem_pool_stat = (memory_pool_stat_t *)mmap (NULL, sizeof (memory_pool_stat_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		g_assert (chain != MAP_FAILED);
#else
#   	error No mmap methods are defined
#endif
	}

	new = g_slice_alloc (sizeof (memory_pool_t));
	g_assert (new != NULL);

	new->cur_pool = pool_chain_new (size);
	new->shared_pool = NULL;
	new->first_pool = new->cur_pool;
	new->destructors = NULL;
	/* Set it upon first call of set variable */
	new->variables = NULL;

	mem_pool_stat->pools_allocated++;

	return new;
}

void                           *
memory_pool_alloc (memory_pool_t * pool, memory_pool_ssize_t size)
{
	u_char                         *tmp;
	struct _pool_chain             *new, *cur;

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
				mem_pool_stat->oversized_chunks++;
				new = pool_chain_new (size + cur->len);
			}
			/* Attach new pool to chain */
			cur->next = new;
			pool->cur_pool = new;
			new->pos += size;
			STAT_LOCK ();
			mem_pool_stat->bytes_allocated += size;
			STAT_UNLOCK ();
			return new->begin;
		}
		tmp = cur->pos;
		cur->pos += size;
		STAT_LOCK ();
		mem_pool_stat->bytes_allocated += size;
		STAT_UNLOCK ();
		return tmp;
	}
	return NULL;
}

void                           *
memory_pool_alloc0 (memory_pool_t * pool, memory_pool_ssize_t size)
{
	void                           *pointer = memory_pool_alloc (pool, size);
	if (pointer) {
		bzero (pointer, size);
	}
	return pointer;
}

void                           *
memory_pool_alloc0_shared (memory_pool_t * pool, memory_pool_ssize_t size)
{
	void                           *pointer = memory_pool_alloc_shared (pool, size);
	if (pointer) {
		bzero (pointer, size);
	}
	return pointer;
}

char                           *
memory_pool_strdup (memory_pool_t * pool, const char *src)
{
	memory_pool_ssize_t             len;
	char                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	len = strlen (src);
	newstr = memory_pool_alloc (pool, len + 1);
	memcpy (newstr, src, len);
	newstr[len] = '\0';
	return newstr;
}

char                           *
memory_pool_fstrdup (memory_pool_t * pool, const struct f_str_s *src)
{
	char                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	newstr = memory_pool_alloc (pool, src->len + 1);
	memcpy (newstr, src->begin, src->len);
	newstr[src->len] = '\0';
	return newstr;
}


char                           *
memory_pool_strdup_shared (memory_pool_t * pool, const char *src)
{
	memory_pool_ssize_t             len;
	char                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	len = strlen (src);
	newstr = memory_pool_alloc_shared (pool, len + 1);
	memcpy (newstr, src, len);
	newstr[len] = '\0';
	return newstr;
}


void                           *
memory_pool_alloc_shared (memory_pool_t * pool, memory_pool_ssize_t size)
{
	u_char                         *tmp;
	struct _pool_chain_shared      *new, *cur;

	if (pool) {
		g_assert (size > 0);
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
				mem_pool_stat->oversized_chunks++;
				new = pool_chain_new_shared (size + cur->len);
			}
			/* Attach new pool to chain */
			cur->next = new;
			new->pos += size;
			STAT_LOCK ();
			mem_pool_stat->bytes_allocated += size;
			STAT_UNLOCK ();
			return new->begin;
		}
		tmp = cur->pos;
		cur->pos += size;
		STAT_LOCK ();
		mem_pool_stat->bytes_allocated += size;
		STAT_UNLOCK ();
		return tmp;
	}
	return NULL;
}

/* Find pool for a pointer, returns NULL if pointer is not in pool */
static struct _pool_chain_shared *
memory_pool_find_pool (memory_pool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *cur = pool->shared_pool;

	while (cur) {
		if ((u_char *) pointer >= cur->begin && (u_char *) pointer <= (cur->begin + cur->len)) {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}

static inline int
__mutex_spin (memory_pool_mutex_t * mutex)
{
	/* check spin count */
	if (g_atomic_int_dec_and_test (&mutex->spin)) {
		/* This may be deadlock, so check owner of this lock */
		if (mutex->owner == getpid ()) {
			/* This mutex was locked by calling process, so it is just double lock and we can easily unlock it */
			g_atomic_int_set (&mutex->spin, MUTEX_SPIN_COUNT);
			return 0;
		}
		else if (kill (0, mutex->owner) == -1) {
			/* Owner process was not found, so release lock */
			g_atomic_int_set (&mutex->spin, MUTEX_SPIN_COUNT);
			return 0;
		}
		/* Spin again */
		g_atomic_int_set (&mutex->spin, MUTEX_SPIN_COUNT);
	}
#ifdef HAVE_ASM_PAUSE
	__asm                           __volatile ("pause");
#elif defined(HAVE_SCHED_YIELD)
	(void)sched_yield ();
#elif defined(HAVE_NANOSLEEP)
	struct timespec                 ts;
	ts.tv_sec = 0;
	ts.tv_nsec = MUTEX_SLEEP_TIME;
	/* Spin */
	while (nanosleep (&ts, &ts) == -1 && errno == EINTR);
#else
#   	error No methods to spin are defined
#endif
	return 1;
}

static void
memory_pool_mutex_spin (memory_pool_mutex_t * mutex)
{
	while (!g_atomic_int_compare_and_exchange (&mutex->lock, 0, 1)) {
		if (!__mutex_spin (mutex)) {
			return;
		}
	}
}

/* Simple implementation of spinlock */
void
memory_pool_lock_shared (memory_pool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	if (chain->lock == NULL) {
		chain->lock = memory_pool_get_mutex (pool);
	}
	memory_pool_lock_mutex (chain->lock);
}

void
memory_pool_unlock_shared (memory_pool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	if (chain->lock == NULL) {
		chain->lock = memory_pool_get_mutex (pool);
		return;
	}

	memory_pool_unlock_mutex (chain->lock);
}

void
memory_pool_add_destructor (memory_pool_t * pool, pool_destruct_func func, void *data)
{
	struct _pool_destructors       *cur, *tmp;

	cur = memory_pool_alloc (pool, sizeof (struct _pool_destructors));
	if (cur) {
		/* Check whether we have identical destructor in pool */
		tmp = pool->destructors;
		while (tmp) {
			if (tmp->func == func && tmp->data == data) {
				/* Do not add identical destructors, they must be unique */
				return;
			}
			tmp = tmp->prev;
		}

		cur->func = func;
		cur->data = data;
		cur->prev = pool->destructors;
		pool->destructors = cur;
	}
}

void
memory_pool_replace_destructor (memory_pool_t * pool, pool_destruct_func func, void *old_data, void *new_data)
{
	struct _pool_destructors       *tmp;

	tmp = pool->destructors;
	while (tmp) {
		if (tmp->func == func && tmp->data == old_data) {
			tmp->func = func;
			tmp->data = new_data;
			break;
		}
		tmp = tmp->prev;
	}

}

void
memory_pool_delete (memory_pool_t * pool)
{
	struct _pool_chain             *cur = pool->first_pool, *tmp;
	struct _pool_chain_shared      *cur_shared = pool->shared_pool, *tmp_shared;
	struct _pool_destructors       *destructor = pool->destructors;

	/* Call all pool destructors */
	while (destructor) {
		/* Avoid calling destructors for NULL pointers */
		if (destructor->data != NULL) {
			destructor->func (destructor->data);
		}
		destructor = destructor->prev;
	}

	while (cur) {
		tmp = cur;
		cur = cur->next;
		g_slice_free1 (tmp->len, tmp->begin);
		g_slice_free (struct _pool_chain, tmp);
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		STAT_UNLOCK ();
	}
	/* Unmap shared memory */
	while (cur_shared) {
		tmp_shared = cur_shared;
		cur_shared = cur_shared->next;
		munmap ((void *)tmp_shared, tmp_shared->len + sizeof (struct _pool_chain_shared));
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		STAT_UNLOCK ();
	}
	if (pool->variables) {
		g_hash_table_destroy (pool->variables);
	}

	mem_pool_stat->pools_freed++;
	g_slice_free (memory_pool_t, pool);
}

void
memory_pool_stat (memory_pool_stat_t * st)
{
	st->pools_allocated = mem_pool_stat->pools_allocated;
	st->pools_freed = mem_pool_stat->pools_freed;
	st->shared_chunks_allocated = mem_pool_stat->shared_chunks_allocated;
	st->bytes_allocated = mem_pool_stat->bytes_allocated;
	st->chunks_allocated = mem_pool_stat->chunks_allocated;
	st->shared_chunks_allocated = mem_pool_stat->shared_chunks_allocated;
	st->chunks_freed = mem_pool_stat->chunks_freed;
	st->oversized_chunks = mem_pool_stat->oversized_chunks;
}

/* By default allocate 8Kb chunks of memory */
#define FIXED_POOL_SIZE 8192
memory_pool_ssize_t
memory_pool_get_size ()
{
#ifdef HAVE_GETPAGESIZE
	return MAX (getpagesize (), FIXED_POOL_SIZE);
#else
	return MAX (sysconf (_SC_PAGESIZE), FIXED_POOL_SIZE);
#endif
}

memory_pool_mutex_t            *
memory_pool_get_mutex (memory_pool_t * pool)
{
	memory_pool_mutex_t            *res;
	if (pool != NULL) {
		res = memory_pool_alloc_shared (pool, sizeof (memory_pool_mutex_t));
		res->lock = 0;
		res->owner = 0;
		res->spin = MUTEX_SPIN_COUNT;
		return res;
	}
	return NULL;
}

void
memory_pool_lock_mutex (memory_pool_mutex_t * mutex)
{
	memory_pool_mutex_spin (mutex);
	mutex->owner = getpid ();
}

void
memory_pool_unlock_mutex (memory_pool_mutex_t * mutex)
{
	mutex->owner = 0;
	(void)g_atomic_int_compare_and_exchange (&mutex->lock, 1, 0);
}

memory_pool_rwlock_t           *
memory_pool_get_rwlock (memory_pool_t * pool)
{
	memory_pool_rwlock_t           *lock;

	lock = memory_pool_alloc_shared (pool, sizeof (memory_pool_rwlock_t));
	lock->__r_lock = memory_pool_get_mutex (pool);
	lock->__w_lock = memory_pool_get_mutex (pool);

	return lock;
}

void
memory_pool_rlock_rwlock (memory_pool_rwlock_t * lock)
{
	/* Spin on write lock */
	while (g_atomic_int_get (&lock->__w_lock->lock)) {
		if (!__mutex_spin (lock->__w_lock)) {
			break;
		}
	}

	g_atomic_int_inc (&lock->__r_lock->lock);
	lock->__r_lock->owner = getpid ();
}

void
memory_pool_wlock_rwlock (memory_pool_rwlock_t * lock)
{
	/* Spin on write lock first */
	memory_pool_lock_mutex (lock->__w_lock);
	/* Now we have write lock set up */
	/* Wait all readers */
	while (g_atomic_int_get (&lock->__r_lock->lock)) {
		__mutex_spin (lock->__r_lock);
	}
}

void
memory_pool_runlock_rwlock (memory_pool_rwlock_t * lock)
{
	if (g_atomic_int_get (&lock->__r_lock->lock)) {
		(void)g_atomic_int_dec_and_test (&lock->__r_lock->lock);
	}
}

void
memory_pool_wunlock_rwlock (memory_pool_rwlock_t * lock)
{
	memory_pool_unlock_mutex (lock->__w_lock);
}

void 
memory_pool_set_variable (memory_pool_t *pool, const gchar *name, gpointer value, pool_destruct_func destructor)
{
	if (pool->variables == NULL) {
		pool->variables = g_hash_table_new (g_str_hash, g_str_equal);
	}

	g_hash_table_insert (pool->variables, memory_pool_strdup (pool, name), value);
	if (destructor != NULL) {
		memory_pool_add_destructor (pool, destructor, value);
	}
}

gpointer
memory_pool_get_variable (memory_pool_t *pool, const gchar *name)
{
	if (pool->variables == NULL) {
		return NULL;
	}

	return g_hash_table_lookup (pool->variables, name);
}


/*
 * vi:ts=4
 */
