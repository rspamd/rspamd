#ifndef RSPAMD_MEM_POOL_H
#define RSPAMD_MEM_POOL_H

#include <sys/types.h>
#include <glib.h>

typedef void (*pool_destruct_func)(void *ptr);

struct _pool_chain {
	u_char *begin;
	u_char *pos;
	size_t len;
	struct _pool_chain *next;
};

struct _pool_chain_shared {
	u_char *begin;
	u_char *pos;
	size_t len;
	gint lock;
	struct _pool_chain_shared *next;
};

struct _pool_destructors {
	pool_destruct_func func;
	void *data;
	struct _pool_destructors *prev;
};

typedef struct memory_pool_s {
	struct _pool_chain *cur_pool;
	struct _pool_chain *first_pool;
	struct _pool_chain_shared *shared_pool;
	struct _pool_destructors *destructors;
} memory_pool_t;

typedef struct memory_pool_stat_s {
	size_t bytes_allocated;
	size_t chunks_allocated;
	size_t shared_chunks_allocated;
	size_t chunks_freed;
} memory_pool_stat_t;

typedef struct memory_pool_rwlock_s {
	gint *__r_lock;
	gint *__w_lock;
} memory_pool_rwlock_t;

/* Allocate new memory poll */
memory_pool_t* memory_pool_new (size_t size);

/* Get memory from pool */
void* memory_pool_alloc (memory_pool_t* pool, size_t size);
/* Get memory and set it to zero */
void* memory_pool_alloc0 (memory_pool_t* pool, size_t size);
/* Make a copy of string in pool */
char* memory_pool_strdup (memory_pool_t* pool, const char *src);

/* Allocate piece of shared memory */
void* memory_pool_alloc_shared (memory_pool_t *pool, size_t size);
/* Lock and unlock chunk of shared memory in which pointer is placed */
void memory_pool_lock_shared (memory_pool_t *pool, void *pointer);
void memory_pool_unlock_shared (memory_pool_t *pool, void *pointer);

/* Add destructor callback to pool */
void memory_pool_add_destructor (memory_pool_t *pool, pool_destruct_func func, void *data);
/* Delete pool, free all its chunks and call destructors chain */
void memory_pool_delete (memory_pool_t *pool);

/* Mutexes operations */
gint* memory_pool_get_mutex (memory_pool_t *pool);
void memory_pool_lock_mutex (gint *mutex);
void memory_pool_unlock_mutex (gint *mutex);

/* Simple rwlock implementation */
memory_pool_rwlock_t* memory_pool_get_rwlock (memory_pool_t *pool);
void memory_pool_rlock_rwlock (memory_pool_rwlock_t *lock);
void memory_pool_wlock_rwlock (memory_pool_rwlock_t *lock);
void memory_pool_runlock_rwlock (memory_pool_rwlock_t *lock);
void memory_pool_wunlock_rwlock (memory_pool_rwlock_t *lock);

void memory_pool_stat (memory_pool_stat_t *st);

/* Get optimal pool size based on page size for this system */
size_t memory_pool_get_size ();

#define memory_pool_free(x) ((x)->len - ((x)->pos - (x)->begin))

#endif
