#ifndef RSPAMD_MEM_POOL_H
#define RSPAMD_MEM_POOL_H

#include <sys/types.h>
#include <glib.h>
struct _pool_chain {
		u_char *begin;
		u_char *pos;
		size_t len;
		struct _pool_chain *next;
};
typedef struct memory_pool_s {
	struct _pool_chain *cur_pool;
	struct _pool_chain *first_pool;
} memory_pool_t;

typedef struct memory_pool_stat_s {
	size_t bytes_allocated;
	size_t chunks_allocated;
	size_t chunks_freed;
} memory_pool_stat_t;

memory_pool_t* memory_pool_new (size_t size);
void* memory_pool_alloc (memory_pool_t* pool, size_t size);
void* memory_pool_alloc0 (memory_pool_t* pool, size_t size);
char* memory_pool_strdup (memory_pool_t* pool, const char *src);
void memory_pool_delete (memory_pool_t* pool);

void memory_pool_stat (memory_pool_stat_t *st);

#define memory_pool_free(x) ((x)->len - ((x)->pos - (x)->begin))

#endif
