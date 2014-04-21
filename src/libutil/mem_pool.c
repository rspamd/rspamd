/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
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
#include "logger.h"
#include "util.h"
#include "main.h"

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

#define POOL_MTX_LOCK()	do { rspamd_mutex_lock (pool->mtx); } while (0)
#define POOL_MTX_UNLOCK()	do { rspamd_mutex_unlock (pool->mtx); } while (0)

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
static rspamd_mempool_stat_t      *mem_pool_stat = NULL;

/**
 * Function that return free space in pool page
 * @param x pool page struct
 */
static gint
pool_chain_free (struct _pool_chain *chain)
{
	return (gint)chain->len - (chain->pos - chain->begin + MEM_ALIGNMENT);
}

static struct _pool_chain      *
pool_chain_new (gsize size)
{
	struct _pool_chain             *chain;

	g_return_val_if_fail (size > 0, NULL);

	chain = g_slice_alloc (sizeof (struct _pool_chain));

	if (chain == NULL) {
		msg_err ("cannot allocate %z bytes, aborting", sizeof (struct _pool_chain));
		abort ();
	}

	chain->begin = g_slice_alloc (size);
	if (chain->begin == NULL) {
		msg_err ("cannot allocate %z bytes, aborting", size);
		abort ();
	}

	chain->pos = align_ptr (chain->begin, MEM_ALIGNMENT);
	chain->len = size;
	chain->next = NULL;
	STAT_LOCK ();
	mem_pool_stat->bytes_allocated += size;
	mem_pool_stat->chunks_allocated++;
	STAT_UNLOCK ();

	return chain;
}

static struct _pool_chain_shared *
pool_chain_new_shared (gsize size)
{
	struct _pool_chain_shared      *chain;
	gpointer                        map;


#if defined(HAVE_MMAP_ANON)
	map = mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (map == MAP_FAILED) {
		msg_err ("cannot allocate %z bytes, aborting", size + sizeof (struct _pool_chain));
		abort ();
	}
	chain = (struct _pool_chain_shared *)map;
	chain->begin = ((guint8 *) chain) + sizeof (struct _pool_chain_shared);
#elif defined(HAVE_MMAP_ZERO)
	gint                            fd;

	fd = open ("/dev/zero", O_RDWR);
	if (fd == -1) {
		return NULL;
	}
	map = mmap (NULL, size + sizeof (struct _pool_chain_shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		msg_err ("cannot allocate %z bytes, aborting", size + sizeof (struct _pool_chain));
		abort ();
	}
	chain = (struct _pool_chain_shared *)map;
	chain->begin = ((guint8 *) chain) + sizeof (struct _pool_chain_shared);
#else
#   	error No mmap methods are defined
#endif
	chain->pos = align_ptr (chain->begin, MEM_ALIGNMENT);
	chain->len = size;
	chain->lock = NULL;
	chain->next = NULL;
	STAT_LOCK ();
	mem_pool_stat->shared_chunks_allocated++;
	mem_pool_stat->bytes_allocated += size;
	STAT_UNLOCK ();

	return chain;
}


/**
 * Allocate new memory poll 
 * @param size size of pool's page
 * @return new memory pool object
 */
rspamd_mempool_t                  *
rspamd_mempool_new (gsize size)
{
	rspamd_mempool_t                  *new;
	gpointer                        map;

	g_return_val_if_fail (size > 0, NULL);
	/* Allocate statistic structure if it is not allocated before */
	if (mem_pool_stat == NULL) {
#if defined(HAVE_MMAP_ANON)
		map = mmap (NULL, sizeof (rspamd_mempool_stat_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		if (map == MAP_FAILED) {
			msg_err ("cannot allocate %z bytes, aborting", sizeof (rspamd_mempool_stat_t));
			abort ();
		}
		mem_pool_stat = (rspamd_mempool_stat_t *)map;
#elif defined(HAVE_MMAP_ZERO)
		gint                            fd;

		fd = open ("/dev/zero", O_RDWR);
		g_assert (fd != -1);
		map = mmap (NULL, sizeof (rspamd_mempool_stat_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (map == MAP_FAILED) {
			msg_err ("cannot allocate %z bytes, aborting", sizeof (rspamd_mempool_stat_t));
			abort ();
		}
		mem_pool_stat = (rspamd_mempool_stat_t *)map;
#else
#   	error No mmap methods are defined
#endif
		memset (map, 0, sizeof (rspamd_mempool_stat_t));
	}

	new = g_slice_alloc (sizeof (rspamd_mempool_t));
	if (new == NULL) {
		msg_err ("cannot allocate %z bytes, aborting", sizeof (rspamd_mempool_t));
		abort ();
	}

	new->cur_pool = pool_chain_new (size);
	new->shared_pool = NULL;
	new->first_pool = new->cur_pool;
	new->cur_pool_tmp = NULL;
	new->first_pool_tmp = NULL;
	new->destructors = NULL;
	/* Set it upon first call of set variable */
	new->variables = NULL;
	new->mtx = rspamd_mutex_new ();

	mem_pool_stat->pools_allocated++;

	return new;
}

static void                           *
memory_pool_alloc_common (rspamd_mempool_t * pool, gsize size, gboolean is_tmp)
{
	guint8                         *tmp;
	struct _pool_chain             *new, *cur;
	gint                            free;

	if (pool) {
		POOL_MTX_LOCK ();
#ifdef MEMORY_GREEDY
		if (is_tmp) {
			cur = pool->first_pool_tmp;
		}
		else {
			cur = pool->first_pool;
		}
#else
		if (is_tmp) {
			cur = pool->cur_pool_tmp;
		}
		else {
			cur = pool->cur_pool;
		}
#endif
		/* Find free space in pool chain */
		while (cur != NULL &&
				(free = pool_chain_free (cur)) < (gint)size &&
				cur->next != NULL) {
			cur = cur->next;
		}

		if (cur == NULL || (free < (gint)size && cur->next == NULL)) {
			/* Allocate new pool */
			if (cur == NULL) {
				if (pool->first_pool->len >= size + MEM_ALIGNMENT) {
					new = pool_chain_new (pool->first_pool->len);
				}
				else {
					new = pool_chain_new (size + pool->first_pool->len + MEM_ALIGNMENT);
				}
				/* Connect to pool subsystem */
				if (is_tmp) {
					pool->first_pool_tmp = new;
				}
				else {
					pool->first_pool = new;
				}
			}
			else {
				if (cur->len >= size + MEM_ALIGNMENT) {
					new = pool_chain_new (cur->len);
				}
				else {
					mem_pool_stat->oversized_chunks++;
					new = pool_chain_new (size + pool->first_pool->len + MEM_ALIGNMENT);
				}
				/* Attach new pool to chain */
				cur->next = new;
			}
			if (is_tmp) {
				pool->cur_pool_tmp = new;
			}
			else {
				pool->cur_pool = new;
			}
			/* No need to align again */
			tmp = new->pos;
			new->pos = tmp + size;
			POOL_MTX_UNLOCK ();
			return tmp;
		}
		/* No need to allocate page */
		tmp = align_ptr (cur->pos, MEM_ALIGNMENT);
		cur->pos = tmp + size;
		POOL_MTX_UNLOCK ();
		return tmp;
	}
	return NULL;
}


void                           *
rspamd_mempool_alloc (rspamd_mempool_t * pool, gsize size)
{
	return memory_pool_alloc_common (pool, size, FALSE);
}

void                           *
rspamd_mempool_alloc_tmp (rspamd_mempool_t * pool, gsize size)
{
	return memory_pool_alloc_common (pool, size, TRUE);
}

void                           *
rspamd_mempool_alloc0 (rspamd_mempool_t * pool, gsize size)
{
	void                           *pointer = rspamd_mempool_alloc (pool, size);
	if (pointer) {
		memset (pointer, 0, size);
	}
	return pointer;
}

void                           *
rspamd_mempool_alloc0_tmp (rspamd_mempool_t * pool, gsize size)
{
	void                           *pointer = rspamd_mempool_alloc_tmp (pool, size);
	if (pointer) {
		memset (pointer, 0, size);
	}
	return pointer;
}

void                           *
rspamd_mempool_alloc0_shared (rspamd_mempool_t * pool, gsize size)
{
	void                           *pointer = rspamd_mempool_alloc_shared (pool, size);
	if (pointer) {
		memset (pointer, 0, size);
	}
	return pointer;
}

void *
rspamd_mempool_alloc_shared (rspamd_mempool_t * pool, gsize size)
{
	guint8 *tmp;
	struct _pool_chain_shared *new, *cur;
	gint free;

	if (pool) {
		g_return_val_if_fail(size > 0, NULL);

		POOL_MTX_LOCK ()
		;
		cur = pool->shared_pool;
		if (!cur) {
			cur = pool_chain_new_shared (pool->first_pool->len);
			pool->shared_pool = cur;
		}

		/* Find free space in pool chain */
		while ((free = pool_chain_free ((struct _pool_chain *) cur))
				< (gint) size && cur->next) {
			cur = cur->next;
		}
		if (free < (gint) size && cur->next == NULL) {
			/* Allocate new pool */

			if (cur->len >= size + MEM_ALIGNMENT) {
				new = pool_chain_new_shared (cur->len);
			}
			else {
				mem_pool_stat->oversized_chunks++;
				new = pool_chain_new_shared (
						size + pool->first_pool->len + MEM_ALIGNMENT);
			}
			/* Attach new pool to chain */
			cur->next = new;
			new->pos += size;
			STAT_LOCK ();
			mem_pool_stat->bytes_allocated += size;
			STAT_UNLOCK ();
			POOL_MTX_UNLOCK ()
			;
			return new->begin;
		}
		tmp = align_ptr(cur->pos, MEM_ALIGNMENT);
		cur->pos = tmp + size;
		POOL_MTX_UNLOCK ()
		;
		return tmp;
	}
	return NULL;
}


gchar                           *
rspamd_mempool_strdup (rspamd_mempool_t * pool, const gchar *src)
{
	gsize             len;
	gchar                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	len = strlen (src);
	newstr = rspamd_mempool_alloc (pool, len + 1);
	memcpy (newstr, src, len);
	newstr[len] = '\0';
	return newstr;
}

gchar                           *
rspamd_mempool_fstrdup (rspamd_mempool_t * pool, const struct f_str_s *src)
{
	gchar                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	newstr = rspamd_mempool_alloc (pool, src->len + 1);
	memcpy (newstr, src->begin, src->len);
	newstr[src->len] = '\0';
	return newstr;
}


gchar                           *
rspamd_mempool_strdup_shared (rspamd_mempool_t * pool, const gchar *src)
{
	gsize             len;
	gchar                           *newstr;

	if (src == NULL) {
		return NULL;
	}

	len = strlen (src);
	newstr = rspamd_mempool_alloc_shared (pool, len + 1);
	memcpy (newstr, src, len);
	newstr[len] = '\0';
	return newstr;
}

/* Find pool for a pointer, returns NULL if pointer is not in pool */
static struct _pool_chain_shared *
memory_pool_find_pool (rspamd_mempool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *cur = pool->shared_pool;

	while (cur) {
		if ((guint8 *) pointer >= cur->begin && (guint8 *) pointer <= (cur->begin + cur->len)) {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}

static inline gint
__mutex_spin (rspamd_mempool_mutex_t * mutex)
{
	/* check spin count */
	if (g_atomic_int_dec_and_test (&mutex->spin)) {
		/* This may be deadlock, so check owner of this lock */
		if (mutex->owner == getpid ()) {
			/* This mutex was locked by calling process, so it is just double lock and we can easily unlock it */
			g_atomic_int_set (&mutex->spin, MUTEX_SPIN_COUNT);
			return 0;
		}
		else if (kill (mutex->owner, 0) == -1) {
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
#endif

#if defined(HAVE_NANOSLEEP)
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
memory_pool_mutex_spin (rspamd_mempool_mutex_t * mutex)
{
	while (!g_atomic_int_compare_and_exchange (&mutex->lock, 0, 1)) {
		if (!__mutex_spin (mutex)) {
			return;
		}
	}
}

/* Simple implementation of spinlock */
void
rspamd_mempool_lock_shared (rspamd_mempool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	if (chain->lock == NULL) {
		chain->lock = rspamd_mempool_get_mutex (pool);
	}
	rspamd_mempool_lock_mutex (chain->lock);
}

void
rspamd_mempool_unlock_shared (rspamd_mempool_t * pool, void *pointer)
{
	struct _pool_chain_shared      *chain;

	chain = memory_pool_find_pool (pool, pointer);
	if (chain == NULL) {
		return;
	}
	if (chain->lock == NULL) {
		chain->lock = rspamd_mempool_get_mutex (pool);
		return;
	}

	rspamd_mempool_unlock_mutex (chain->lock);
}

void
rspamd_mempool_add_destructor_full (rspamd_mempool_t * pool, rspamd_mempool_destruct_t func, void *data,
		const gchar *function, const gchar *line)
{
	struct _pool_destructors       *cur;

	cur = rspamd_mempool_alloc (pool, sizeof (struct _pool_destructors));
	if (cur) {
		POOL_MTX_LOCK ();
		cur->func = func;
		cur->data = data;
		cur->function = function;
		cur->loc = line;
		cur->prev = pool->destructors;
		pool->destructors = cur;
		POOL_MTX_UNLOCK ();
	}
}

void
rspamd_mempool_replace_destructor (rspamd_mempool_t * pool, rspamd_mempool_destruct_t func, void *old_data, void *new_data)
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
rspamd_mempool_delete (rspamd_mempool_t * pool)
{
	struct _pool_chain             *cur = pool->first_pool, *tmp;
	struct _pool_chain_shared      *cur_shared = pool->shared_pool, *tmp_shared;
	struct _pool_destructors       *destructor = pool->destructors;

	POOL_MTX_LOCK ();
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
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		mem_pool_stat->bytes_allocated -= tmp->len;
		STAT_UNLOCK ();
		g_slice_free1 (tmp->len, tmp->begin);
		g_slice_free (struct _pool_chain, tmp);
	}
	/* Clean temporary pools */
	cur = pool->first_pool_tmp;
	while (cur) {
		tmp = cur;
		cur = cur->next;
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		mem_pool_stat->bytes_allocated -= tmp->len;
		STAT_UNLOCK ();
		g_slice_free1 (tmp->len, tmp->begin);
		g_slice_free (struct _pool_chain, tmp);
	}
	/* Unmap shared memory */
	while (cur_shared) {
		tmp_shared = cur_shared;
		cur_shared = cur_shared->next;
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		mem_pool_stat->bytes_allocated -= tmp_shared->len;
		STAT_UNLOCK ();
		munmap ((void *)tmp_shared, tmp_shared->len + sizeof (struct _pool_chain_shared));
	}
	if (pool->variables) {
		g_hash_table_destroy (pool->variables);
	}

	mem_pool_stat->pools_freed++;
	POOL_MTX_UNLOCK ();
	rspamd_mutex_free (pool->mtx);
	g_slice_free (rspamd_mempool_t, pool);
}

void
rspamd_mempool_cleanup_tmp (rspamd_mempool_t* pool)
{
	struct _pool_chain             *cur = pool->first_pool, *tmp;

	POOL_MTX_LOCK ();
	cur = pool->first_pool_tmp;
	while (cur) {
		tmp = cur;
		cur = cur->next;
		STAT_LOCK ();
		mem_pool_stat->chunks_freed++;
		mem_pool_stat->bytes_allocated -= tmp->len;
		STAT_UNLOCK ();
		g_slice_free1 (tmp->len, tmp->begin);
		g_slice_free (struct _pool_chain, tmp);
	}
	mem_pool_stat->pools_freed++;
	POOL_MTX_UNLOCK ();
}

void
rspamd_mempool_stat (rspamd_mempool_stat_t * st)
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
gsize
rspamd_mempool_suggest_size (void)
{
#ifdef HAVE_GETPAGESIZE
	return MAX (getpagesize (), FIXED_POOL_SIZE);
#else
	return MAX (sysconf (_SC_PAGESIZE), FIXED_POOL_SIZE);
#endif
}

rspamd_mempool_mutex_t            *
rspamd_mempool_get_mutex (rspamd_mempool_t * pool)
{
	rspamd_mempool_mutex_t            *res;
	if (pool != NULL) {
		res = rspamd_mempool_alloc_shared (pool, sizeof (rspamd_mempool_mutex_t));
		res->lock = 0;
		res->owner = 0;
		res->spin = MUTEX_SPIN_COUNT;
		return res;
	}
	return NULL;
}

void
rspamd_mempool_lock_mutex (rspamd_mempool_mutex_t * mutex)
{
	memory_pool_mutex_spin (mutex);
	mutex->owner = getpid ();
}

void
rspamd_mempool_unlock_mutex (rspamd_mempool_mutex_t * mutex)
{
	mutex->owner = 0;
	(void)g_atomic_int_compare_and_exchange (&mutex->lock, 1, 0);
}

rspamd_mempool_rwlock_t           *
rspamd_mempool_get_rwlock (rspamd_mempool_t * pool)
{
	rspamd_mempool_rwlock_t           *lock;

	lock = rspamd_mempool_alloc_shared (pool, sizeof (rspamd_mempool_rwlock_t));
	lock->__r_lock = rspamd_mempool_get_mutex (pool);
	lock->__w_lock = rspamd_mempool_get_mutex (pool);

	return lock;
}

void
rspamd_mempool_rlock_rwlock (rspamd_mempool_rwlock_t * lock)
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
rspamd_mempool_wlock_rwlock (rspamd_mempool_rwlock_t * lock)
{
	/* Spin on write lock first */
	rspamd_mempool_lock_mutex (lock->__w_lock);
	/* Now we have write lock set up */
	/* Wait all readers */
	while (g_atomic_int_get (&lock->__r_lock->lock)) {
		__mutex_spin (lock->__r_lock);
	}
}

void
rspamd_mempool_runlock_rwlock (rspamd_mempool_rwlock_t * lock)
{
	if (g_atomic_int_get (&lock->__r_lock->lock)) {
		(void)g_atomic_int_dec_and_test (&lock->__r_lock->lock);
	}
}

void
rspamd_mempool_wunlock_rwlock (rspamd_mempool_rwlock_t * lock)
{
	rspamd_mempool_unlock_mutex (lock->__w_lock);
}

void 
rspamd_mempool_set_variable (rspamd_mempool_t *pool, const gchar *name, gpointer value, rspamd_mempool_destruct_t destructor)
{
	if (pool->variables == NULL) {
		pool->variables = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	}

	g_hash_table_insert (pool->variables, rspamd_mempool_strdup (pool, name), value);
	if (destructor != NULL) {
		rspamd_mempool_add_destructor (pool, destructor, value);
	}
}

gpointer
rspamd_mempool_get_variable (rspamd_mempool_t *pool, const gchar *name)
{
	if (pool->variables == NULL) {
		return NULL;
	}

	return g_hash_table_lookup (pool->variables, name);
}


/*
 * vi:ts=4
 */
