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

#define MEM_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#define align_ptr(p, a)                                                   \
    (guint8 *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

/** 
 * Destructor type definition 
 */
typedef void (*rspamd_mempool_destruct_t)(void *ptr);

/**
 * Pool mutex structure
 */
typedef struct memory_pool_mutex_s {
	gint lock;
	pid_t owner;
	guint spin;
} rspamd_mempool_mutex_t;

/**
 * Pool page structure
 */
struct _pool_chain {
	guint8 *begin;					/**< begin of pool chain block 				*/
	guint8 *pos;					/**< current start of free space in block 	*/
	gsize len;		/**< length of block 						*/
	struct _pool_chain *next;		/**< chain link 							*/
};

/**
 * Shared pool page
 */
struct _pool_chain_shared {
	guint8 *begin;
	guint8 *pos;
	gsize len;
	struct _pool_chain_shared *next;
	rspamd_mempool_mutex_t *lock;
};

/**
 * Destructors list item structure
 */
struct _pool_destructors {
	rspamd_mempool_destruct_t func;				/**< pointer to destructor					*/
	void *data;								/**< data to free							*/
	const gchar *function;					/**< function from which this destructor was added */
	const gchar *loc;						/**< line number                            */
	struct _pool_destructors *prev;			/**< chain link								*/
};

/**
 * Memory pool type
 */
struct rspamd_mutex_s;
typedef struct memory_pool_s {
	struct _pool_chain *cur_pool;			/**< currently used page					*/
	struct _pool_chain *first_pool;			/**< first page								*/
	struct _pool_chain *cur_pool_tmp;		/**< currently used temporary page			*/
	struct _pool_chain *first_pool_tmp;		/**< first temporary page					*/
	struct _pool_chain_shared *shared_pool;	/**< shared chain							*/
	struct _pool_destructors *destructors;	/**< destructors chain						*/
	GHashTable *variables;					/**< private memory pool variables			*/
	struct rspamd_mutex_s *mtx;				/**< threads lock							*/
} rspamd_mempool_t;

/**
 * Statistics structure
 */
typedef struct memory_pool_stat_s {
	gsize pools_allocated;				/**< total number of allocated pools					*/
	gsize pools_freed;					/**< number of freed pools								*/
	gsize bytes_allocated;				/**< bytes that are allocated with pool allocator		*/
	gsize chunks_allocated;				/**< number of chunks that are allocated				*/
	gsize shared_chunks_allocated;		/**< shared chunks allocated							*/
	gsize chunks_freed;					/**< chunks freed										*/
	gsize oversized_chunks;				/**< oversized chunks									*/
} rspamd_mempool_stat_t;

/**
 * Rwlock for locking shared memory regions
 */
typedef struct memory_pool_rwlock_s {
	rspamd_mempool_mutex_t *__r_lock;							/**< read mutex (private)								*/
	rspamd_mempool_mutex_t *__w_lock;							/**< write mutex (private)								*/
} rspamd_mempool_rwlock_t;

/**
 * Allocate new memory poll 
 * @param size size of pool's page
 * @return new memory pool object
 */
rspamd_mempool_t* rspamd_mempool_new (gsize size);

/** 
 * Get memory from pool
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* rspamd_mempool_alloc (rspamd_mempool_t* pool, gsize size);

/**
 * Get memory from temporary pool
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* rspamd_mempool_alloc_tmp (rspamd_mempool_t* pool, gsize size);

/**
 * Get memory and set it to zero
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* rspamd_mempool_alloc0 (rspamd_mempool_t* pool, gsize size);

/**
 * Get memory and set it to zero
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void* rspamd_mempool_alloc0_tmp (rspamd_mempool_t* pool, gsize size);

/**
 * Cleanup temporary data in pool
 */
void rspamd_mempool_cleanup_tmp (rspamd_mempool_t* pool);

/**
 * Make a copy of string in pool
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
gchar* rspamd_mempool_strdup (rspamd_mempool_t* pool, const gchar *src);

/**
 * Make a copy of fixed string in pool as null terminated string
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
gchar* rspamd_mempool_fstrdup (rspamd_mempool_t* pool, const struct f_str_s *src);

/**
 * Allocate piece of shared memory
 * @param pool memory pool object
 * @param size bytes to allocate
 */
void* rspamd_mempool_alloc_shared (rspamd_mempool_t* pool, gsize size);
void* rspamd_mempool_alloc0_shared (rspamd_mempool_t *pool, gsize size);
gchar* rspamd_mempool_strdup_shared (rspamd_mempool_t* pool, const gchar *src);

/**
 * Lock chunk of shared memory in which pointer is placed
 * @param pool memory pool object
 * @param pointer pointer of shared memory object that is to be locked (the whole page that contains that object is locked)
 */
void rspamd_mempool_lock_shared (rspamd_mempool_t *pool, void *pointer);

/**
 * Unlock chunk of shared memory in which pointer is placed
 * @param pool memory pool object
 * @param pointer pointer of shared memory object that is to be unlocked (the whole page that contains that object is locked)
 */
void rspamd_mempool_lock_shared (rspamd_mempool_t *pool, void *pointer);

/**
 * Add destructor callback to pool
 * @param pool memory pool object
 * @param func pointer to function-destructor
 * @param data pointer to data that would be passed to destructor
 */
void rspamd_mempool_add_destructor_full (rspamd_mempool_t *pool, rspamd_mempool_destruct_t func, void *data,
		const gchar *function, const gchar *line);

/* Macros for common usage */
#define rspamd_mempool_add_destructor(pool, func, data) \
	rspamd_mempool_add_destructor_full(pool, func, data, G_STRFUNC, G_STRLOC)

/**
 * Replace destructor callback to pool for specified pointer
 * @param pool memory pool object
 * @param func pointer to function-destructor
 * @param old_data pointer to old data
 * @param new_data pointer to data that would be passed to destructor
 */
void rspamd_mempool_replace_destructor (rspamd_mempool_t *pool,
		rspamd_mempool_destruct_t func, void *old_data, void *new_data);

/**
 * Delete pool, free all its chunks and call destructors chain
 * @param pool memory pool object
 */
void rspamd_mempool_delete (rspamd_mempool_t *pool);

/** 
 * Get new mutex from pool (allocated in shared memory)
 * @param pool memory pool object
 * @return mutex object
 */
rspamd_mempool_mutex_t* rspamd_mempool_get_mutex (rspamd_mempool_t *pool);

/**
 * Lock mutex
 * @param mutex mutex to lock
 */
void rspamd_mempool_lock_mutex (rspamd_mempool_mutex_t *mutex);

/**
 * Unlock mutex
 * @param mutex mutex to unlock
 */
void rspamd_mempool_unlock_mutex (rspamd_mempool_mutex_t *mutex);

/**
 * Create new rwlock and place it in shared memory
 * @param pool memory pool object
 * @return rwlock object
 */
rspamd_mempool_rwlock_t* rspamd_mempool_get_rwlock (rspamd_mempool_t *pool);

/**
 * Aquire read lock
 * @param lock rwlock object
 */
void rspamd_mempool_rlock_rwlock (rspamd_mempool_rwlock_t *lock);

/**
 * Aquire write lock
 * @param lock rwlock object
 */
void rspamd_mempool_wlock_rwlock (rspamd_mempool_rwlock_t *lock);

/**
 * Release read lock
 * @param lock rwlock object
 */
void rspamd_mempool_runlock_rwlock (rspamd_mempool_rwlock_t *lock);

/**
 * Release write lock
 * @param lock rwlock object
 */
void rspamd_mempool_wunlock_rwlock (rspamd_mempool_rwlock_t *lock);

/**
 * Get pool allocator statistics
 * @param st stat pool struct
 */
void rspamd_mempool_stat (rspamd_mempool_stat_t *st);

/**
 * Get optimal pool size based on page size for this system
 * @return size of memory page in system
 */
gsize rspamd_mempool_suggest_size (void);

/**
 * Set memory pool variable
 * @param pool memory pool object
 * @param name name of variable
 * @param gpointer value value of variable
 * @param destructor pointer to function-destructor
 */
void rspamd_mempool_set_variable (rspamd_mempool_t *pool, const gchar *name,
		gpointer value, rspamd_mempool_destruct_t destructor);

/**
 * Get memory pool variable
 * @param pool memory pool object
 * @param name name of variable
 * @return NULL or pointer to variable data
 */
gpointer rspamd_mempool_get_variable (rspamd_mempool_t *pool, const gchar *name);


#endif
