#include <sys/types.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include "mem_pool.h"

#ifdef _THREAD_SAFE
pthread_mutex_t stat_mtx = PTHREAD_MUTEX_INITIALIZER;
#define STAT_LOCK() do { pthread_mutex_lock (&stat_mtx); } while (0)
#define STAT_UNLOCK() do { pthread_mutex_unlock (&stat_mtx); } while (0)
#else
#define STAT_LOCK() do {} while (0)
#define STAT_UNLOCK() do {} while (0)
#endif

/* Internal statistic */
static size_t bytes_allocated = 0;
static size_t chunks_allocated = 0;
static size_t chunks_freed = 0;

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
	chunks_allocated ++;
	STAT_UNLOCK ();
	
	return chain;
}

memory_pool_t* 
memory_pool_new (size_t size)
{
	memory_pool_t *new;

	new = g_malloc (sizeof (memory_pool_t));
	new->cur_pool = pool_chain_new (size);
	new->first_pool = new->cur_pool;

	return new;
}

void *
memory_pool_alloc (memory_pool_t *pool, size_t size)
{
	u_char *tmp;
	struct _pool_chain *new, *cur;

	if (pool) {
		cur = pool->cur_pool;
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
			bytes_allocated += size;
			STAT_UNLOCK ();
			return new->begin;
		}	
		tmp = cur->pos;
		cur->pos += size;
		STAT_LOCK ();
		bytes_allocated += size;
		STAT_UNLOCK ();
		return tmp;
	}
	return NULL;
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

void
memory_pool_delete (memory_pool_t *pool)
{
	struct _pool_chain *cur = pool->first_pool, *tmp;
	while (cur) {
		tmp = cur;
		cur = cur->next;
		g_free (tmp->begin);
		g_free (tmp);
		STAT_LOCK ();
		chunks_freed ++;
		STAT_UNLOCK ();
	}
	g_free (pool);
}

void
memory_pool_stat (memory_pool_stat_t *st)
{
	st->bytes_allocated = bytes_allocated;
	st->chunks_allocated = chunks_allocated;
	st->chunks_freed = chunks_freed;
}

/*
 * vi:ts=4
 */
