#include <sys/types.h>
#include <glib.h>
#include "mem_pool.h"

memory_pool_t* 
memory_pool_new (size_t size)
{
	memory_pool_t *new;

	new = g_malloc (sizeof (memory_pool_t));
	new->begin = g_malloc (size);
	new->len = size;
	new->pos = new->begin;

	return new;
}

void *
memory_pool_alloc (memory_pool_t *pool, size_t size)
{
	u_char *tmp; 
	if (pool) {
		if (pool->len < (pool->pos - pool->begin) + size) {
			/* Grow pool */
			if (pool->len > size) {
				pool->len *= 2;
			}
			else {
				pool->len += size + pool->len;
			}
			pool->begin = g_realloc (pool->begin, pool->len);
			return memory_pool_alloc (pool, size);
		}	
		tmp = pool->pos;
		pool->pos += size;
		return tmp;
	}
	return NULL;
}

void memory_pool_free (memory_pool_t *pool)
{
	if (pool) {
		g_free (pool->begin);
		g_free (pool);
	}
}

/*
 * vi:ts=4
 */
