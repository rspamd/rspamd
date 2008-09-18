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
	new->next = NULL;

	return new;
}

void *
memory_pool_alloc (memory_pool_t *pool, size_t size)
{
	u_char *tmp;
	memory_pool_t *new, *cur;

	if (pool) {
		cur = pool;
		/* Find free space in pool chain */
		while (memory_pool_free (cur) < size && cur->next) {
			cur = cur->next;
		}
		if (cur->next == NULL) {
			/* Allocate new pool */
			if (cur->len > size) {
				new = memory_pool_new (cur->len);
			}
			else {
				new = memory_pool_new (size + cur->len);
			}
			cur->next = new;
			new->pos += size;
			return new->begin;
		}	
		tmp = cur->pos;
		cur->pos += size;
		return tmp;
	}
	return NULL;
}

void memory_pool_delete (memory_pool_t *pool)
{
	memory_pool_t *cur = pool, *tmp;
	while (cur) {
		tmp = cur;
		cur = cur->next;
		g_free (tmp->begin);
		g_free (tmp);
	}
}

/*
 * vi:ts=4
 */
