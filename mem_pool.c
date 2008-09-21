#include <sys/types.h>
#include <glib.h>
#include "mem_pool.h"

static struct _pool_chain *
pool_chain_new (size_t size) 
{
	struct _pool_chain *chain;
	chain = g_malloc (sizeof (struct _pool_chain));
	chain->begin = g_malloc (size);
	chain->len = size;
	chain->pos = chain->begin;
	chain->next = NULL;

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
		if (cur->next == NULL) {
			/* Allocate new pool */
			if (cur->len > size) {
				new = pool_chain_new (cur->len);
			}
			else {
				new = pool_chain_new (size + cur->len);
			}
			/* Attach new pool to chain */
			cur->next = new;
			pool->cur_pool = new;
			new->pos += size;
			return new->begin;
		}	
		tmp = cur->pos;
		cur->pos += size;
		return tmp;
	}
	return NULL;
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
	}
	g_free (pool);
}

/*
 * vi:ts=4
 */
