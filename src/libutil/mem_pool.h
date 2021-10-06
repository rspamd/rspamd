/*-
 * Copyright 2019 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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


#if defined(HAVE_PTHREAD_PROCESS_SHARED) && !defined(DISABLE_PTHREAD_MUTEX)
#include <pthread.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

struct f_str_s;

#ifdef __has_attribute
#  if __has_attribute(alloc_size)
#    define RSPAMD_ATTR_ALLOC_SIZE(pos) __attribute__((alloc_size(pos)))
#  else
#    define RSPAMD_ATTR_ALLOC_SIZE(pos)
#  endif

#  if __has_attribute(assume_aligned)
#    define RSPAMD_ATTR_ALLOC_ALIGN(al) __attribute__((assume_aligned(al)))
#  else
#    define RSPAMD_ATTR_ALLOC_ALIGN(al)
#  endif
#  if __has_attribute(returns_nonnull)
#    define RSPAMD_ATTR_RETURNS_NONNUL __attribute__((returns_nonnull))
#  else
#    define RSPAMD_ATTR_RETURNS_NONNUL
#  endif
#else
#define RSPAMD_ATTR_ALLOC_SIZE(pos)
#define RSPAMD_ATTR_ALLOC_ALIGN(al)
#define RSPAMD_ATTR_RETURNS_NONNUL
#endif

#define MEMPOOL_TAG_LEN 20
#define MEMPOOL_UID_LEN 20
/* All pointers are aligned as this variable */
#define MIN_MEM_ALIGNMENT   sizeof (guint64)
/**
 * Destructor type definition
 */
typedef void (*rspamd_mempool_destruct_t) (void *ptr);

/**
 * Pool mutex structure
 */
#if !defined(HAVE_PTHREAD_PROCESS_SHARED) || defined(DISABLE_PTHREAD_MUTEX)
typedef struct memory_pool_mutex_s {
	gint lock;
	pid_t owner;
	guint spin;
} rspamd_mempool_mutex_t;
/**
 * Rwlock for locking shared memory regions
 */
typedef struct memory_pool_rwlock_s {
	rspamd_mempool_mutex_t *__r_lock;                           /**< read mutex (private)								*/
	rspamd_mempool_mutex_t *__w_lock;                           /**< write mutex (private)								*/
} rspamd_mempool_rwlock_t;
#else
typedef pthread_mutex_t rspamd_mempool_mutex_t;
typedef pthread_rwlock_t rspamd_mempool_rwlock_t;
#endif

/**
 * Tag to use for logging purposes
 */
struct rspamd_mempool_tag {
	gchar tagname[MEMPOOL_TAG_LEN];         /**< readable name							*/
	gchar uid[MEMPOOL_UID_LEN];             /**< unique id								*/
};

enum rspamd_mempool_flags {
	RSPAMD_MEMPOOL_DEBUG = (1u << 0u),
};

/**
 * Memory pool type
 */
struct rspamd_mempool_entry_point;
struct rspamd_mutex_s;
struct rspamd_mempool_specific;
typedef struct memory_pool_s {
	struct rspamd_mempool_specific *priv;
	struct rspamd_mempool_tag tag;          /**< memory pool tag						*/
} rspamd_mempool_t;

/**
 * Statistics structure
 */
typedef struct memory_pool_stat_s {
	guint pools_allocated;              /**< total number of allocated pools					*/
	guint pools_freed;                  /**< number of freed pools								*/
	guint bytes_allocated;              /**< bytes that are allocated with pool allocator		*/
	guint chunks_allocated;             /**< number of chunks that are allocated				*/
	guint shared_chunks_allocated;      /**< shared chunks allocated							*/
	guint chunks_freed;                 /**< chunks freed										*/
	guint oversized_chunks;             /**< oversized chunks									*/
	guint fragmented_size;                /**< fragmentation size								*/
} rspamd_mempool_stat_t;


/**
 * Allocate new memory poll
 * @param size size of pool's page
 * @return new memory pool object
 */
rspamd_mempool_t *rspamd_mempool_new_ (gsize size, const gchar *tag, gint flags,
		const gchar *loc);

#define rspamd_mempool_new(size, tag, flags) \
	rspamd_mempool_new_((size), (tag), (flags), G_STRLOC)
#define rspamd_mempool_new_default(tag, flags) \
	rspamd_mempool_new_(rspamd_mempool_suggest_size_(G_STRLOC), (tag), (flags), G_STRLOC)

/**
 * Get memory from pool
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void *rspamd_mempool_alloc_ (rspamd_mempool_t *pool, gsize size, const gchar *loc)
	RSPAMD_ATTR_ALLOC_SIZE(2) RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT) RSPAMD_ATTR_RETURNS_NONNUL;
#define rspamd_mempool_alloc(pool, size) \
	rspamd_mempool_alloc_((pool), (size), (G_STRLOC))
#define rspamd_mempool_alloc_type(pool, type) \
	(type *)(rspamd_mempool_alloc_((pool), sizeof(type), (G_STRLOC)))
#define rspamd_mempool_alloc_buffer(pool, buflen) \
	(char *)(rspamd_mempool_alloc_((pool), sizeof(char) * (buflen), (G_STRLOC)))
/**
 * Notify external memory usage for memory pool
 * @param pool
 * @param size
 * @param loc
 */
void rspamd_mempool_notify_alloc_ (rspamd_mempool_t *pool, gsize size, const gchar *loc);
#define rspamd_mempool_notify_alloc(pool, size) \
	rspamd_mempool_notify_alloc_((pool), (size), (G_STRLOC))

/**
 * Get memory and set it to zero
 * @param pool memory pool object
 * @param size bytes to allocate
 * @return pointer to allocated object
 */
void *rspamd_mempool_alloc0_ (rspamd_mempool_t *pool, gsize size, const gchar *loc)
	RSPAMD_ATTR_ALLOC_SIZE(2) RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT) RSPAMD_ATTR_RETURNS_NONNUL;
#define rspamd_mempool_alloc0(pool, size) \
	rspamd_mempool_alloc0_((pool), (size), (G_STRLOC))
#define rspamd_mempool_alloc0_type(pool, type) \
	(type *)(rspamd_mempool_alloc0_((pool), sizeof(type), (G_STRLOC)))

/**
 * Make a copy of string in pool
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
gchar *rspamd_mempool_strdup_ (rspamd_mempool_t *pool, const gchar *src, const gchar *loc)
	RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT);
#define rspamd_mempool_strdup(pool, src) \
	rspamd_mempool_strdup_ ((pool), (src), (G_STRLOC))

/**
 * Make a copy of fixed string in pool as null terminated string
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
gchar *rspamd_mempool_fstrdup_ (rspamd_mempool_t *pool,
								const struct f_str_s *src,
								const gchar *loc)
RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT);
#define rspamd_mempool_fstrdup(pool, src) \
	rspamd_mempool_fstrdup_ ((pool), (src), G_STRLOC)

struct f_str_tok;

/**
 * Make a copy of fixed string token in pool as null terminated string
 * @param pool memory pool object
 * @param src source string
 * @return pointer to newly created string that is copy of src
 */
gchar *rspamd_mempool_ftokdup_ (rspamd_mempool_t *pool,
								const struct f_str_tok *src,
								const gchar *loc)
RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT);
#define rspamd_mempool_ftokdup(pool, src) \
	rspamd_mempool_ftokdup_ ((pool), (src), (G_STRLOC))

/**
 * Allocate piece of shared memory
 * @param pool memory pool object
 * @param size bytes to allocate
 */
void *rspamd_mempool_alloc_shared_ (rspamd_mempool_t *pool, gsize size, const gchar *loc)
	RSPAMD_ATTR_ALLOC_SIZE(2) RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT) RSPAMD_ATTR_RETURNS_NONNUL;
#define rspamd_mempool_alloc_shared(pool, size) \
	rspamd_mempool_alloc_shared_((pool), (size), (G_STRLOC))

void *rspamd_mempool_alloc0_shared_ (rspamd_mempool_t *pool, gsize size, const gchar *loc)
	RSPAMD_ATTR_ALLOC_SIZE(2) RSPAMD_ATTR_ALLOC_ALIGN(MIN_MEM_ALIGNMENT) RSPAMD_ATTR_RETURNS_NONNUL;
#define rspamd_mempool_alloc0_shared(pool, size) \
	rspamd_mempool_alloc0_shared_((pool), (size), (G_STRLOC))

/**
 * Add destructor callback to pool
 * @param pool memory pool object
 * @param func pointer to function-destructor
 * @param data pointer to data that would be passed to destructor
 */
void rspamd_mempool_add_destructor_full (rspamd_mempool_t *pool,
										 rspamd_mempool_destruct_t func,
										 void *data,
										 const gchar *function,
										 const gchar *line);

/* Macros for common usage */
#define rspamd_mempool_add_destructor(pool, func, data) \
    rspamd_mempool_add_destructor_full (pool, func, data, (G_STRFUNC), (G_STRLOC))

/**
 * Replace destructor callback to pool for specified pointer
 * @param pool memory pool object
 * @param func pointer to function-destructor
 * @param old_data pointer to old data
 * @param new_data pointer to data that would be passed to destructor
 */
void rspamd_mempool_replace_destructor (rspamd_mempool_t *pool,
										rspamd_mempool_destruct_t func,
										void *old_data, void *new_data);

/**
 * Calls all destructors associated with the specific memory pool without removing
 * of the pool itself
 * @param pool
 */
void rspamd_mempool_destructors_enforce (rspamd_mempool_t *pool);

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
rspamd_mempool_mutex_t *rspamd_mempool_get_mutex (rspamd_mempool_t *pool);

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
rspamd_mempool_rwlock_t *rspamd_mempool_get_rwlock (rspamd_mempool_t *pool);

/**
 * Acquire read lock
 * @param lock rwlock object
 */
void rspamd_mempool_rlock_rwlock (rspamd_mempool_rwlock_t *lock);

/**
 * Acquire write lock
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
 * Reset memory pool stat
 */
void rspamd_mempool_stat_reset (void);

/**
 * Get optimal pool size based on page size for this system
 * @return size of memory page in system
 */
#define rspamd_mempool_suggest_size() rspamd_mempool_suggest_size_(G_STRLOC)

gsize rspamd_mempool_suggest_size_ (const char *loc);

gsize rspamd_mempool_get_used_size (rspamd_mempool_t *pool);
gsize rspamd_mempool_get_wasted_size (rspamd_mempool_t *pool);

/**
 * Set memory pool variable
 * @param pool memory pool object
 * @param name name of variable
 * @param gpointer value value of variable
 * @param destructor pointer to function-destructor
 */
void rspamd_mempool_set_variable (rspamd_mempool_t *pool,
								  const gchar *name,
								  gpointer value,
								  rspamd_mempool_destruct_t destructor);

/**
 * Get memory pool variable
 * @param pool memory pool object
 * @param name name of variable
 * @return NULL or pointer to variable data
 */
gpointer rspamd_mempool_get_variable (rspamd_mempool_t *pool,
									  const gchar *name);

/**
 * Removes variable from memory pool
 * @param pool memory pool object
 * @param name name of variable
 */
void rspamd_mempool_remove_variable (rspamd_mempool_t *pool,
									 const gchar *name);

/**
 * Prepend element to a list creating it in the memory pool
 * @param l
 * @param p
 * @return
 */
GList *rspamd_mempool_glist_prepend (rspamd_mempool_t *pool,
									 GList *l, gpointer p) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Append element to a list creating it in the memory pool
 * @param l
 * @param p
 * @return
 */
GList *rspamd_mempool_glist_append (rspamd_mempool_t *pool,
									GList *l, gpointer p) G_GNUC_WARN_UNUSED_RESULT;

#ifdef  __cplusplus
}
#endif

#ifdef  __cplusplus
#include <stdexcept> /* For std::runtime_error */

namespace rspamd {

template<class T>
class mempool_allocator {
public:
	typedef T value_type;

	mempool_allocator() = delete;
	template<class U>
	mempool_allocator(const mempool_allocator<U> &other) : pool(other.pool) {}
	mempool_allocator(rspamd_mempool_t *_pool) : pool(_pool) {}
	[[nodiscard]] constexpr T* allocate(std::size_t n)
	{
		if (G_MAXSIZE / 2 / sizeof(T) > n) {
			throw std::runtime_error("integer overflow");
		}
		return reinterpret_cast<T*>(rspamd_mempool_alloc(pool, n * sizeof(T)));
	}
	constexpr void deallocate(T* p, std::size_t n) {
		/* Do nothing */
	}
private:
	rspamd_mempool_t *pool;
};

}
#endif

#endif
