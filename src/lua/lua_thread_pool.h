#ifndef LUA_THREAD_POOL_H_
#define LUA_THREAD_POOL_H_

#include <lua.h>
#include "ref.h"

#ifdef __cplusplus
extern "C" {
#endif

struct thread_entry;
struct lua_thread_pool;

typedef void (*lua_thread_finish_t)(struct thread_entry *thread, int ret);

typedef void (*lua_thread_error_t)(struct thread_entry *thread, int ret, const char *msg);

/*
 * Lifecycle of a pooled Lua coroutine. Transitions are enforced by the
 * thread pool so that a thread can never be resumed twice, returned while
 * suspended, or reused after it has been recycled into another task.
 */
enum thread_entry_state {
	LUA_THREAD_FREE = 0, /* idle in the pool or freshly created */
	LUA_THREAD_RUNNING,  /* currently executing Lua on the C stack */
	LUA_THREAD_YIELDED,  /* suspended at an async yield point */
	LUA_THREAD_DEAD,     /* errored/terminated, must not be reused */
};

struct thread_entry {
	lua_State *lua_state;
	/* Main VM state that owns the registry slot below; used to unref on free */
	lua_State *pool_state;
	int thread_index;
	gpointer cd;

	/* function to handle result of called method, can be NULL */
	lua_thread_finish_t finish_callback;

	/* function to log result, i.e. if you want to modify error logging message or somehow process this state, can be NUL */
	lua_thread_error_t error_callback;
	struct rspamd_task *task;
	struct rspamd_config *cfg;

	/*
	 * Bumped on every acquire and release. Async libraries snapshot it at the
	 * yield point and pass it back to lua_thread_resume_checked(): a mismatch
	 * means the entry was recycled while a stale completion was in flight, so
	 * the resume is refused instead of corrupting another task's coroutine.
	 */
	guint64 generation;
	enum thread_entry_state state;

	/*
	 * Lifetime is refcounted. The pool holds one reference for as long as the
	 * entry is managed by it; an async library that stashes the entry for a
	 * later completion must take its own reference (lua_thread_pool_retain_entry)
	 * and drop it when done (lua_thread_pool_release_entry). This guarantees the
	 * struct outlives any in-flight completion even if the owning task is torn
	 * down, so the generation/state guards never read freed memory.
	 */
	ref_entry_t ref;
};

struct lua_callback_state {
	lua_State *L;
	struct thread_entry *my_thread;
	struct thread_entry *previous_thread;
	struct lua_thread_pool *thread_pool;
};

/**
 * Allocates new thread pool on state L. Pre-creates number of lua-threads to use later on
 *
 * @param L
 * @return
 */
struct lua_thread_pool *
lua_thread_pool_new(lua_State *L);

/**
 * Destroys the pool
 * @param pool
 */
void lua_thread_pool_free(struct lua_thread_pool *pool);

/**
 * Extracts a thread from the list of available ones.
 * It immediately becomes the running one and should be used to run a Lua script/function straight away.
 * as soon as the code is finished, it should be either returned into list of available threads by
 * calling lua_thread_pool_return() or terminated by calling lua_thread_pool_terminate_entry()
 * if the code finished with error.
 *
 * If the code performed YIELD, the thread is still running and it's live should be controlled by the callee
 *
 * @param task
 * @return
 */
struct thread_entry *
lua_thread_pool_get_for_task(struct rspamd_task *task);

/**
 * The same, but used when task is not available
 *
 * @param cfg
 * @return
 */
struct thread_entry *
lua_thread_pool_get_for_config(struct rspamd_config *cfg);

/**
 * Return thread into the list of available ones. It can't be done with yielded or dead threads.
 *
 * @param pool
 * @param thread_entry
 */
void lua_thread_pool_return_full(struct lua_thread_pool *pool,
								 struct thread_entry *thread_entry,
								 const char *loc);

#define lua_thread_pool_return(pool, thread_entry) \
	lua_thread_pool_return_full(pool, thread_entry, G_STRLOC)

/**
 * Currently running thread. Typically needed in yielding point - to fill-up continuation.
 *
 * @param pool
 * @return
 */
struct thread_entry *
lua_thread_pool_get_running_entry_full(struct lua_thread_pool *pool,
									   const char *loc);

#define lua_thread_pool_get_running_entry(pool) \
	lua_thread_pool_get_running_entry_full(pool, G_STRLOC)

/**
 * Updates currently running thread
 *
 * @param pool
 * @param thread_entry
 */
void lua_thread_pool_set_running_entry_full(struct lua_thread_pool *pool,
											struct thread_entry *thread_entry,
											const char *loc);

#define lua_thread_pool_set_running_entry(pool, thread_entry) \
	lua_thread_pool_set_running_entry_full(pool, thread_entry, G_STRLOC)

/**
 * Prevents yielded thread to be used for callback execution. lua_thread_pool_restore_callback() should be called afterwards.
 *
 * @param pool
 * @param cbs
 */
void lua_thread_pool_prepare_callback_full(struct lua_thread_pool *pool,
										   struct lua_callback_state *cbs, const char *loc);

#define lua_thread_pool_prepare_callback(pool, cbs) \
	lua_thread_pool_prepare_callback_full(pool, cbs, G_STRLOC)

/**
 * Restores state after lua_thread_pool_prepare_callback () usage
 *
 * @param cbs
 */
void lua_thread_pool_restore_callback_full(struct lua_callback_state *cbs,
										   const char *loc);

#define lua_thread_pool_restore_callback(cbs) \
	lua_thread_pool_restore_callback_full(cbs, G_STRLOC)

/**
 * Acts like lua_call but the tread is able to suspend execution.
 * As soon as the call is over, call either thread_entry::finish_callback or thread_entry::error_callback.
 *
 * @param thread_entry
 * @param narg
 */
void lua_thread_call_full(struct thread_entry *thread_entry,
						  int narg,
						  const char *loc);

#define lua_thread_call(thread_entry, narg) \
	lua_thread_call_full(thread_entry, narg, G_STRLOC)

/**
 * Yields thread. should be only called in return statement
 * @param thread_entry
 * @param nresults
 * @return
 */
int lua_thread_yield_full(struct thread_entry *thread_entry, int nresults,
						  const char *loc);

#define lua_thread_yield(thread_entry, narg) \
	lua_thread_yield_full(thread_entry, narg, G_STRLOC)

/**
 * Resumes suspended by lua_yield_thread () thread
 * @param task
 * @param thread_entry
 * @param narg
 */
void lua_thread_resume_full(struct thread_entry *thread_entry,
							int narg,
							const char *loc);

#define lua_thread_resume(thread_entry, narg) \
	lua_thread_resume_full(thread_entry, narg, G_STRLOC)

/**
 * Like lua_thread_resume(), but additionally verifies that the entry has not
 * been recycled since the caller snapshotted its generation at the yield
 * point. If the generation does not match, or the thread is not suspended,
 * the resume is refused (logged, no-op) rather than risking memory
 * corruption. Returns true if the thread was actually resumed.
 *
 * @param thread_entry
 * @param expected_generation value of thread_entry->generation captured at yield
 * @param narg
 */
bool lua_thread_resume_checked_full(struct thread_entry *thread_entry,
									guint64 expected_generation,
									int narg,
									const char *loc);

#define lua_thread_resume_checked(thread_entry, expected_generation, narg) \
	lua_thread_resume_checked_full(thread_entry, expected_generation, narg, G_STRLOC)

/**
 * Take a reference on a thread entry. An async library that stashes an entry
 * for a later completion must call this so the struct cannot be freed (e.g. by
 * task teardown) while the completion pointer is still live. Pair with
 * lua_thread_pool_release_entry(). NULL-safe.
 */
void lua_thread_pool_retain_entry(struct thread_entry *thread_entry);

/**
 * Drop a reference taken by lua_thread_pool_retain_entry(). When the last
 * reference goes away the entry is destroyed. NULL-safe.
 */
void lua_thread_pool_release_entry(struct thread_entry *thread_entry);

/**
 * Terminates thread pool entry and fill the pool with another thread entry if needed
 * @param pool
 * @param thread_entry
 * @param loc
 */
void lua_thread_pool_terminate_entry_full(struct lua_thread_pool *pool,
										  struct thread_entry *thread_entry,
										  const char *loc, bool enforce);
#define lua_thread_pool_terminate_entry(pool, thread_entry) \
	lua_thread_pool_terminate_entry_full(pool, thread_entry, G_STRLOC, false)

#ifdef __cplusplus
}
#endif

#endif /* LUA_THREAD_POOL_H_ */
