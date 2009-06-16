/**
 * @file mem_pool.h
 * \brief Memory pools library.
 *
 * Memory pools library. Library is designed to implement efficient way to
 * store data in memory avoiding calling of many malloc/free. It has overhead
 * because of fact that objects live in pool for rather long time and are not freed
 * immediately after use, but if we know certainly when these objects can be used, we
 * can use pool for them
 */

#ifndef RSPAMD_MEM_POOL_H
#define RSPAMD_MEM_POOL_H

#include "config.h"


struct f_str_s;

/** 
 * Destructor type definition 
 */
typedef void (*pool_destruct_func)(void *ptr);

/**
 * Type that represents allocating size
 */
typedef long int memory_pool_ssize_t;

/**
 * Pool mutex structure
 */
typedef struct memory_pool_mutex_s {
	gint lock;
	pid_t owner;
	guint spin;
} memory_pool_mutex_t;

/**
 * Pool page structure
 */
struct _pool_chain {
	u_char *begin;					/**< begin of pool chain block 				*/
	u_char *pos;					/**< current start of free space in block 	*/
	memory_pool_ssize_t len;		/**< length of block 						*/
	struct _pool_chain *next;		/**< chain link 							*/
};

/**
 * Shared pool page
 */
struct _pool_chain_shared {
	u_char *begin;
	u_char *pos;
	memory_pool_ssize_t len;
	memory_pool_mutex_t *lock;
	struct _pool_chain_shared *next;
};

/**
 * Destructors list item structure
 */
struct _pool_destructors {
	pool_destruct_func func;				/**< pointer to destructor					*/
	void *data;								/**< data to free							*/
	struct _pool_destructors *prev;			/**< chain link								*/
};

/**
 * Memory pool type
 */
typedef struct memory_pool_s {
	struct _pool_chain *cur_pool;			/**< currently used page					*/
	struct _pool_chain *first_pool;			/**< first page								*/
	struct _pool_chain_shared *shared_pool;	/**< shared chain							*/
	struct _pool_destructors *destructors;	/**< destructors chain						*/
} memory_pool_t;

/**
 * Statistics structure
 */
typedef struct memory_pool_stat_s {
	memory_pool_ssize_t pools_allocated;				/**< total number of allocated pools					*/
	memory_pool_ssize_t pools_freed;					/**< number of freed pools								*/
	memory_pool_ssize_t bytes_allocated;				/**< bytes that are allocated with pool allocator		*/
	memory_pool_ssize_t chunks_allocated;				/**< number of chunks that are allocated				*/
	memory_pool_ssize_t shared_chunks_allocated;		/**< shared chunks allocated							*/
	memory_pool_ssize_t chunks_freed;					/**< chunks freed										*/
	memory_pool_ssize_t oversized_chunks;				/**< oversized chunks									*/
} memory_pool_stat_t;

/**
 * Rwlock for locking shared memory regions
 */
typedef struct memory_pool_rwlock_s {
	memory_pool_mutex_t *__r_lock;							/**< read mutex (private)								*/
	memory_pool_mutex_t *__w_lock;							/**< write mutex (private)								*/
} memory_pool_rwlock_t;

/**
 * Allocate new memory poll 
 * @param size size of pool's page
 * @return new memory pool object
 */
memory_pool_t* memory_pool_new (memory_pool_ssize_t size);

/** 
 * Get memory from pool
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* memory_pool_alloc (memory_pool_t* pool, memory_pool_ssize_t size);

/**
 * Get memory and set it to zero
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* memory_pool_alloc0 (memory_pool_t* pool, memory_pool_ssize_t size);

/**
 * Make a copy of string in pool
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
char* memory_pool_strdup (memory_pool_t* pool, const char *src);

/**
 * Make a copy of fixed string in pool as null terminated string
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
char* memory_pool_fstrdup (memory_pool_t* pool, const struct f_str_s *src);

/**
 * Allocate piece of shared memory
 * @param pool memory pool object
 * @param size bytes to allocate
 */
void* memory_pool_alloc_shared (memory_pool_t *pool, memory_pool_ssize_t size);
void* memory_pool_alloc0_shared (memory_pool_t *pool, memory_pool_ssize_t size);
char* memory_pool_strdup_shared (memory_pool_t* pool, const char *src);

/**
 * Lock chunk of shared memory in which pointer is placed
 * @param pool memory pool object
 * @param pointer pointer of shared memory object that is to be locked (the whole page that contains that object is locked)
 */
void memory_pool_lock_shared (memory_pool_t *pool, void *pointer);

/**
 * Unlock chunk of shared memory in which pointer is placed
 * @param pool memory pool object
 * @param pointer pointer of shared memory object that is to be unlocked (the whole page that contains that object is locked)
 */
void memory_pool_unlock_shared (memory_pool_t *pool, void *pointer);

/**
 * Add destructor callback to pool
 * @param pool memory pool object
 * @param func pointer to function-destructor
 * @param data pointer to data that would be passed to destructor
 */
void memory_pool_add_destructor (memory_pool_t *pool, pool_destruct_func func, void *data);

/**
 * Delete pool, free all its chunks and call destructors chain
 * @param pool memory pool object
 */
void memory_pool_delete (memory_pool_t *pool);

/** 
 * Get new mutex from pool (allocated in shared memory)
 * @param pool memory pool object
 * @return mutex object
 */
memory_pool_mutex_t* memory_pool_get_mutex (memory_pool_t *pool);

/**
 * Lock mutex
 * @param mutex mutex to lock
 */
void memory_pool_lock_mutex (memory_pool_mutex_t *mutex);

/**
 * Unlock mutex
 * @param mutex mutex to unlock
 */
void memory_pool_unlock_mutex (memory_pool_mutex_t *mutex);

/**
 * Create new rwlock and place it in shared memory
 * @param pool memory pool object
 * @return rwlock object
 */
memory_pool_rwlock_t* memory_pool_get_rwlock (memory_pool_t *pool);

/**
 * Aquire read lock
 * @param lock rwlock object
 */
void memory_pool_rlock_rwlock (memory_pool_rwlock_t *lock);

/**
 * Aquire write lock
 * @param lock rwlock object
 */
void memory_pool_wlock_rwlock (memory_pool_rwlock_t *lock);

/**
 * Release read lock
 * @param lock rwlock object
 */
void memory_pool_runlock_rwlock (memory_pool_rwlock_t *lock);

/**
 * Release write lock
 * @param lock rwlock object
 */
void memory_pool_wunlock_rwlock (memory_pool_rwlock_t *lock);

/**
 * Get pool allocator statistics
 * @param st stat pool struct
 */
void memory_pool_stat (memory_pool_stat_t *st);

/**
 * Get optimal pool size based on page size for this system
 * @return size of memory page in system
 */
memory_pool_ssize_t memory_pool_get_size ();

/**
 * Macro that return free space in pool page
 * @param x pool page struct
 */
#define memory_pool_free(x) ((x)->len - ((x)->pos - (x)->begin))

#endif
