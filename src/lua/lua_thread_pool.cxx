/*-
 * Copyright 2018 Mikhail Galanin
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

#include "config.h"

#include "lua_common.h"
#include "lua_thread_pool.h"
#include "libserver/rspamd_symcache.h"

#include <vector>

#define msg_debug_lua_threads(...) rspamd_conditional_debug_fast(NULL, NULL,                                     \
																 rspamd_lua_threads_log_id, "lua_threads", NULL, \
																 RSPAMD_LOG_FUNC,                                \
																 __VA_ARGS__)

INIT_LOG_MODULE(lua_threads)

static struct thread_entry *thread_entry_new(lua_State *L);
static void thread_entry_free(lua_State *L, struct thread_entry *ent);

#define CFG_POOL_GET(cfg) (reinterpret_cast<lua_thread_pool *>((cfg)->lua_thread_pool))

struct lua_thread_pool {
	std::vector<struct thread_entry *> available_items;
	lua_State *L;
	int max_items;
	struct thread_entry *running_entry;
	static const int default_max_items = 100;

	lua_thread_pool(lua_State *L, int max_items = default_max_items)
		: L(L), max_items(max_items)
	{
		running_entry = nullptr;
		available_items.reserve(max_items);

		for (auto i = 0; i < MAX(2, max_items / 10); i++) {
			auto *ent = thread_entry_new(L);
			available_items.push_back(ent);
		}
	}

	~lua_thread_pool()
	{
		for (auto *ent: available_items) {
			/* Drop the pool's reference; freed once nothing else holds it */
			REF_RELEASE(ent);
		}
	}

	auto get_thread() -> struct thread_entry *
	{
		struct thread_entry *ent;

		if (!available_items.empty()) {
			ent = available_items.back();
			available_items.pop_back();
		}
		else {
			ent = thread_entry_new(L);
		}

		/* Only idle threads may be handed out */
		g_assert(ent->state == LUA_THREAD_FREE);
		ent->state = LUA_THREAD_RUNNING;
		ent->generation++;
		ent->pool = this;
		/* Whoever runs now gets the slot back when this thread stops */
		ent->prev_running = running_entry;

		running_entry = ent;

		return ent;
	}

	auto return_thread(struct thread_entry *thread_entry, const char *loc) -> void
	{
		/* we can't return a running/yielded thread into the pool */
		g_assert(lua_status(thread_entry->lua_state) == 0);
		/*
		 * A thread is only returnable right after it finished executing, i.e.
		 * while it is still the RUNNING one. Hitting this assert means someone
		 * returned a suspended (YIELDED) or already recycled (FREE/DEAD)
		 * thread - a classic source of coroutine corruption.
		 */
		g_assert(thread_entry->state == LUA_THREAD_RUNNING);

		if (running_entry == thread_entry) {
			running_entry = NULL;
		}

		thread_entry->state = LUA_THREAD_FREE;
		thread_entry->generation++;
		thread_entry->item = NULL;
		thread_entry->prev_running = NULL;

		if (available_items.size() <= max_items) {
			thread_entry->cd = NULL;
			thread_entry->finish_callback = NULL;
			thread_entry->error_callback = NULL;
			thread_entry->terminate_callback = NULL;
			thread_entry->task = NULL;
			thread_entry->cfg = NULL;

			msg_debug_lua_threads("%s: returned thread to the threads pool %z items",
								  loc,
								  available_items.size());

			available_items.push_back(thread_entry);
		}
		else {
			msg_debug_lua_threads("%s: removed thread as thread pool has %z items",
								  loc,
								  available_items.size());
			/* Drop the pool's reference; freed once nothing else holds it */
			REF_RELEASE(thread_entry);
		}
	}

	auto terminate_thread(struct thread_entry *thread_entry,
						  const char *loc,
						  bool enforce) -> void
	{
		struct thread_entry *ent = NULL;
		/*
		 * A suspended thread stopped from the outside gets neither its finish
		 * nor its error callback. A failed thread can be marked as suspended
		 * too (lua_yield() has raised an error where lua_isyieldable() is not
		 * available), but its error callback has been called
		 */
		lua_thread_terminate_t terminate_cb = enforce && thread_entry->state == LUA_THREAD_YIELDED
												  ? thread_entry->terminate_callback
												  : nullptr;

		if (!enforce) {
			/* we should only terminate failed threads */
			g_assert(lua_status(thread_entry->lua_state) != 0 &&
					 lua_status(thread_entry->lua_state) != LUA_YIELD);
		}

		if (running_entry == thread_entry) {
			running_entry = NULL;
		}

		thread_entry->state = LUA_THREAD_DEAD;
		thread_entry->prev_running = NULL;
		thread_entry->terminate_callback = NULL;

		msg_debug_lua_threads("%s: terminated thread entry", loc);

		if (terminate_cb != nullptr) {
			/*
			 * The entry is dead already, so the code run by the callback cannot
			 * resume it, and the reference of the pool keeps it alive
			 */
			terminate_cb(thread_entry);
		}

		/*
		 * Drop the pool's reference. If an async completion still holds the
		 * entry (e.g. the owning task is being torn down while a request is in
		 * flight), the struct stays alive until that completion releases it, so
		 * the late callback can safely observe the DEAD state instead of
		 * dereferencing freed memory.
		 */
		REF_RELEASE(thread_entry);

		if (available_items.size() <= max_items) {
			ent = thread_entry_new(L);
			available_items.push_back(ent);
		}
	}

	auto get_running_entry(void) -> struct thread_entry *
	{
		return running_entry;
	};

	auto set_running_entry(struct thread_entry *ent) -> struct thread_entry *
	{
		auto *old_entry = running_entry;
		running_entry = ent;
		return old_entry;
	};
};

static void
thread_entry_dtor(void *p)
{
	auto *ent = reinterpret_cast<struct thread_entry *>(p);

	/*
	 * Registry slot is owned by the main VM state, unref it there. The last
	 * reference can be dropped by a late completion after the state is closed.
	 */
	if (rspamd_lua_is_initialised()) {
		luaL_unref(ent->pool_state, LUA_REGISTRYINDEX, ent->thread_index);
	}

	g_free(ent);
}

static struct thread_entry *
thread_entry_new(lua_State *L)
{
	struct thread_entry *ent;
	ent = g_new0(struct thread_entry, 1);
	ent->lua_state = lua_newthread(L);
	ent->pool_state = L;
	ent->thread_index = luaL_ref(L, LUA_REGISTRYINDEX);
	ent->state = LUA_THREAD_FREE;
	ent->generation = 0;
	/*
	 * The pool holds the initial reference. Async libraries that stash the
	 * entry take their own via lua_thread_pool_retain_entry(); the struct is
	 * freed (thread_entry_dtor) only once the last reference is dropped.
	 */
	REF_INIT_RETAIN(ent, thread_entry_dtor);

	return ent;
}

struct lua_thread_pool *
lua_thread_pool_new(lua_State *L)
{
	auto *pool = new lua_thread_pool(L);
	return pool;
}

void lua_thread_pool_free(struct lua_thread_pool *pool)
{
	delete pool;
}

void lua_thread_pool_retain_entry(struct thread_entry *thread_entry)
{
	REF_RETAIN(thread_entry);
}

void lua_thread_pool_release_entry(struct thread_entry *thread_entry)
{
	REF_RELEASE(thread_entry);
}


/*
 * Ties a coroutine to the task it runs for. A task can be destroyed while its
 * coroutine is suspended (timeout, client disconnect, a request that is not
 * bound to the task session): after that nothing may resume the coroutine, as
 * its Lua code and its finish callback would use the freed task.
 */
struct lua_thread_task_guard {
	struct thread_entry *entry;
	guint64 generation;
};

static void
lua_thread_task_guard_dtor(void *p)
{
	auto *guard = reinterpret_cast<struct lua_thread_task_guard *>(p);
	auto *ent = guard->entry;

	/* Otherwise that run is over and the entry serves somebody else */
	if (ent->generation == guard->generation) {
		if (ent->state == LUA_THREAD_YIELDED) {
			msg_debug_lua_threads("terminate a suspended thread: its task is destroyed");
			/*
			 * The pool is not used here: the config can be gone by now. A
			 * suspended entry is not in the pool anyway, so it is enough to
			 * drop the reference the pool holds. The entry itself lives until
			 * the last pending completion lets it go, and that completion is
			 * refused as the entry is dead.
			 */
			ent->state = LUA_THREAD_DEAD;
			ent->task = NULL;
			ent->item = NULL;
			ent->cd = NULL;
			/* Nobody waits for the coroutine of a destroyed task */
			ent->terminate_callback = NULL;
			REF_RELEASE(ent);
		}
		else if (ent->state == LUA_THREAD_RUNNING) {
			/* The task is destroyed from the inside of its own coroutine */
			ent->task = NULL;
			ent->item = NULL;
			ent->terminate_callback = NULL;
		}
	}

	/* The guard's own reference */
	REF_RELEASE(ent);
}

struct thread_entry *
lua_thread_pool_get_for_task(struct rspamd_task *task)
{
	struct thread_entry *ent = CFG_POOL_GET(task->cfg)->get_thread();

	ent->task = task;

	auto *guard = rspamd_mempool_alloc_type(task->task_pool, struct lua_thread_task_guard);
	guard->entry = ent;
	guard->generation = ent->generation;
	REF_RETAIN(ent);
	rspamd_mempool_add_destructor(task->task_pool, lua_thread_task_guard_dtor, guard);

	return ent;
}

struct thread_entry *
lua_thread_pool_get_for_config(struct rspamd_config *cfg)
{
	struct thread_entry *ent = CFG_POOL_GET(cfg)->get_thread();

	ent->cfg = cfg;

	return ent;
}

void lua_thread_pool_return_full(struct lua_thread_pool *pool,
								 struct thread_entry *thread_entry, const char *loc)
{
	pool->return_thread(thread_entry, loc);
}

void lua_thread_pool_terminate_entry_full(struct lua_thread_pool *pool,
										  struct thread_entry *thread_entry, const char *loc,
										  bool enforce)
{
	pool->terminate_thread(thread_entry, loc, enforce);
}

struct thread_entry *
lua_thread_pool_get_running_entry_full(struct lua_thread_pool *pool,
									   const char *loc)
{
	msg_debug_lua_threads("%s: lua_thread_pool_get_running_entry_full", loc);
	return pool->get_running_entry();
}

/*
 * A yield is possible only if nothing but Lua code (and resumable frames) is
 * between lua_resume() and the caller: lua_yield() raises an error otherwise.
 */
static inline bool
lua_thread_state_is_yieldable(lua_State *L)
{
#if LUA_VERSION_NUM >= 503 || \
	(defined(WITH_LUAJIT) && (!defined(LUAJIT_VERSION_NUM) || LUAJIT_VERSION_NUM >= 20100))
	return lua_isyieldable(L);
#else
	/*
	 * LuaJIT 2.0 and Lua 5.1/5.2 cannot tell: a sync call made by a Lua function
	 * that is called from a C function (table.sort, string.gsub) is not caught
	 */
	return true;
#endif
}

/*
 * Only a thread started by lua_thread_call() can be suspended, and such a
 * thread always has a task or a config. Neither of them means that this is:
 * - a thread that runs a plain callback under lua_pcall()
 *   (lua_thread_pool_prepare_callback): there is no lua_resume() to yield to;
 * - a thread whose task has been destroyed while it runs: nothing could
 *   resume it safely afterwards.
 */
static inline bool
lua_thread_entry_is_resumable(const struct thread_entry *ent)
{
	return ent->task != nullptr || ent->cfg != nullptr;
}

struct thread_entry *
lua_thread_pool_get_yieldable_entry_full(struct lua_thread_pool *pool,
										 lua_State *L,
										 const char *loc)
{
	auto *ent = pool->get_running_entry();

	if (ent == nullptr || ent->lua_state != L ||
		ent->state != LUA_THREAD_RUNNING) {
		msg_debug_lua_threads("%s: caller is not a running pooled thread", loc);

		return nullptr;
	}

	if (!lua_thread_entry_is_resumable(ent)) {
		msg_debug_lua_threads("%s: pooled thread runs a callback or has lost its task", loc);

		return nullptr;
	}

	if (lua_status(L) != 0 || !lua_thread_state_is_yieldable(L)) {
		msg_debug_lua_threads("%s: pooled thread cannot yield here", loc);

		return nullptr;
	}

	return ent;
}

void lua_thread_pool_set_running_entry_full(struct lua_thread_pool *pool,
											struct thread_entry *thread_entry,
											const char *loc)
{
	msg_debug_lua_threads("%s: lua_thread_pool_set_running_entry_full", loc);
	pool->set_running_entry(thread_entry);
}

static struct lua_thread_pool *
lua_thread_entry_get_pool(struct thread_entry *thread_entry)
{
	/* Not taken from the task or the config: both can be gone by now */
	return thread_entry->pool;
}

void lua_thread_pool_prepare_callback_full(struct lua_thread_pool *pool,
										   struct lua_callback_state *cbs,
										   const char *loc)
{
	msg_debug_lua_threads("%s: lua_thread_pool_prepare_callback_full", loc);
	cbs->thread_pool = pool;
	cbs->previous_thread = lua_thread_pool_get_running_entry_full(pool, loc);

	if (cbs->previous_thread != nullptr) {
		/* Stays valid until lua_thread_pool_restore_callback() */
		REF_RETAIN(cbs->previous_thread);
	}

	cbs->my_thread = pool->get_thread();
	cbs->L = cbs->my_thread->lua_state;
}

void lua_thread_pool_restore_callback_full(struct lua_callback_state *cbs,
										   const char *loc)
{
	auto *prev = cbs->previous_thread;

	lua_thread_pool_return_full(cbs->thread_pool, cbs->my_thread, loc);

	if (prev != nullptr && prev->state == LUA_THREAD_RUNNING) {
		lua_thread_pool_set_running_entry_full(cbs->thread_pool, prev, loc);
	}
	else {
		/* Nobody was running, or that thread has been stopped by the callback */
		lua_thread_pool_set_running_entry_full(cbs->thread_pool, nullptr, loc);
	}

	if (prev != nullptr) {
		cbs->previous_thread = nullptr;
		REF_RELEASE(prev);
	}
}

static int
lua_do_resume_full(lua_State *L, int narg, const char *loc)
{
#if LUA_VERSION_NUM >= 504
	int nres;
#endif
	msg_debug_lua_threads("%s: lua_do_resume_full", loc);
#if LUA_VERSION_NUM < 502
	return lua_resume(L, narg);
#else
#if LUA_VERSION_NUM >= 504
	return lua_resume(L, NULL, narg, &nres);
#else
	return lua_resume(L, NULL, narg);
#endif
#endif
}

static void
lua_resume_thread_internal_full(struct thread_entry *thread_entry,
								struct thread_entry *prev_running,
								int narg, const char *loc)
{
	int ret;
	struct rspamd_task *task;
	/* Taken now: the task of this thread can be gone when the thread stops */
	auto *pool = lua_thread_entry_get_pool(thread_entry);
	bool had_task = thread_entry->task != nullptr;

	msg_debug_lua_threads("%s: lua_resume_thread_internal_full", loc);

	if (prev_running == thread_entry) {
		prev_running = nullptr;
	}

	/* Neither entry may be freed under our feet while Lua code runs */
	REF_RETAIN(thread_entry);

	if (prev_running != nullptr) {
		REF_RETAIN(prev_running);
	}

	pool->set_running_entry(thread_entry);

	if (thread_entry->task != nullptr && thread_entry->item != nullptr) {
		/* Whoever resumes us, the code that follows works for this symbol */
		rspamd_symcache_set_cur_item(thread_entry->task, thread_entry->item);
	}

	ret = lua_do_resume_full(thread_entry->lua_state, narg, loc);

	/* A task-bound thread whose task has been destroyed while it was running */
	bool orphaned = had_task && thread_entry->task == nullptr;

	if (ret == LUA_YIELD) {
		/*
		 * A proper yield is made by lua_thread_yield(): the thread initiated
		 * an asynchronous event and will be resumed as soon as it is finished.
		 * Any other yield (e.g. coroutine.yield() called by the Lua code) has
		 * nobody to resume it, so such a thread would be lost forever.
		 */
		if (thread_entry->state != LUA_THREAD_YIELDED) {
			static const char *yield_err = "unexpected yield: the code is "
										   "suspended by something that is not an asynchronous rspamd call";

			if (thread_entry->error_callback && !orphaned) {
				thread_entry->error_callback(thread_entry, ret, yield_err);
			}
			else {
				task = thread_entry->task;
				msg_err_task_check("lua call failed (%d): %s", ret, yield_err);
			}

			pool->terminate_thread(thread_entry, loc, true);
		}
	}
	else if (ret == 0) {
		if (thread_entry->finish_callback && !orphaned) {
			thread_entry->finish_callback(thread_entry, ret);
		}

		pool->return_thread(thread_entry, loc);
	}
	else {
		rspamd_lua_traceback(thread_entry->lua_state);

		if (thread_entry->error_callback && !orphaned) {
			thread_entry->error_callback(thread_entry, ret,
										 lua_tostring(thread_entry->lua_state, -1));
		}
		else {
			task = thread_entry->task;
			msg_err_task_check("lua call failed (%d): %s", ret,
							   lua_tostring(thread_entry->lua_state, -1));
		}

		/*
		 * Maybe there is a way to recover here.
		 * For now, just remove faulty thread
		 */
		pool->terminate_thread(thread_entry, loc, false);
	}

	/*
	 * The thread has stopped (finished, failed or suspended), so it does not
	 * run any more: give the slot back to the one that was running before, if
	 * we were started from inside of it. A suspended thread must never stay
	 * here, as the next caller of a yielding API would take it for itself.
	 */
	if (prev_running != nullptr && prev_running->state == LUA_THREAD_RUNNING) {
		pool->set_running_entry(prev_running);
	}
	else {
		pool->set_running_entry(nullptr);
	}

	if (prev_running != nullptr) {
		REF_RELEASE(prev_running);
	}

	REF_RELEASE(thread_entry);
}

/*
 * Shared by lua_thread_resume_full()/lua_thread_resume_checked_full(): refuse
 * to resume anything that is not currently suspended. This makes a duplicate
 * or stale async completion (double-fired event, completion racing task
 * teardown, recycled entry) a logged no-op instead of memory corruption.
 * Returns true if the thread is safe to resume.
 */
static bool
lua_thread_resume_guard(struct thread_entry *thread_entry, const char *loc)
{
	struct rspamd_task *task = thread_entry->task;

	if (thread_entry->state == LUA_THREAD_DEAD) {
		/* Expected: e.g. the task was destroyed while its thread was waiting */
		msg_debug_lua_threads("%s: do not resume a terminated coroutine", loc);

		return false;
	}

	if (thread_entry->state != LUA_THREAD_YIELDED) {
		msg_err_task_check("%s: refusing to resume a coroutine that is not "
						   "suspended (state=%d, lua_status=%d): likely a "
						   "duplicate or stale async completion",
						   loc, (int) thread_entry->state,
						   lua_status(thread_entry->lua_state));

		return false;
	}

	/*
	 * State and lua status must stay in lockstep: a YIELDED entry always has a
	 * suspended lua_State underneath it.
	 */
	g_assert(lua_status(thread_entry->lua_state) == LUA_YIELD);

	return true;
}

void lua_thread_resume_full(struct thread_entry *thread_entry, int narg,
							const char *loc)
{
	/*
	 * The only state where we can resume from is LUA_YIELD
	 * Another acceptable status is OK (0) but in that case we should push function on stack
	 * to start the thread from, which is happening in lua_thread_call(), not in this function.
	 */
	msg_debug_lua_threads("%s: lua_thread_resume_full", loc);

	if (!lua_thread_resume_guard(thread_entry, loc)) {
		return;
	}

	thread_entry->state = LUA_THREAD_RUNNING;
	lua_resume_thread_internal_full(thread_entry,
									lua_thread_entry_get_pool(thread_entry)->get_running_entry(),
									narg, loc);
}

bool lua_thread_resume_checked_full(struct thread_entry *thread_entry,
									guint64 expected_generation,
									int narg,
									const char *loc)
{
	struct rspamd_task *task;

	msg_debug_lua_threads("%s: lua_thread_resume_checked_full", loc);

	if (thread_entry->state == LUA_THREAD_DEAD) {
		/* Its task can be freed by now, so it must not be even looked at */
		msg_debug_lua_threads("%s: do not resume a terminated coroutine", loc);

		return false;
	}

	task = thread_entry->task;

	if (thread_entry->generation != expected_generation) {
		/*
		 * The entry was recycled (returned to the pool and handed out again)
		 * between the yield and this completion. The coroutine we captured is
		 * gone; resuming now would clobber whoever owns the entry now.
		 */
		msg_err_task_check("%s: refusing stale coroutine resume: generation "
						   "mismatch (expected %uL, got %uL)",
						   loc, expected_generation,
						   thread_entry->generation);

		return false;
	}

	if (!lua_thread_resume_guard(thread_entry, loc)) {
		return false;
	}

	thread_entry->state = LUA_THREAD_RUNNING;
	lua_resume_thread_internal_full(thread_entry,
									lua_thread_entry_get_pool(thread_entry)->get_running_entry(),
									narg, loc);

	return true;
}

void lua_thread_call_full(struct thread_entry *thread_entry,
						  int narg, const char *loc)
{
	g_assert(lua_status(thread_entry->lua_state) == 0);                /* we can't call running/yielded thread */
	g_assert(thread_entry->state == LUA_THREAD_RUNNING);               /* must be freshly acquired */
	g_assert(thread_entry->task != NULL || thread_entry->cfg != NULL); /* we can't call without pool */

	/* Who was running when this thread was acquired: it runs again after us */
	auto *prev_running = thread_entry->prev_running;
	thread_entry->prev_running = NULL;

	lua_resume_thread_internal_full(thread_entry, prev_running, narg, loc);
}

int lua_thread_yield_full(struct thread_entry *thread_entry,
						  int nresults,
						  const char *loc)
{
	g_assert(lua_status(thread_entry->lua_state) == 0);
	g_assert(thread_entry->state == LUA_THREAD_RUNNING);

	msg_debug_lua_threads("%s: lua_thread_yield_full", loc);

	if (!lua_thread_entry_is_resumable(thread_entry) ||
		!lua_thread_state_is_yieldable(thread_entry->lua_state)) {
		/*
		 * lua_yield() would raise this error itself, but only after the entry
		 * is marked as suspended, and the entry would keep that mark while its
		 * thread goes on running. Callers must not get here: they are expected
		 * to take the entry from lua_thread_pool_get_yieldable_entry() before
		 * they start anything.
		 */
		return luaL_error(thread_entry->lua_state,
						  "%s: attempt to yield from a context that cannot be suspended",
						  loc);
	}

	thread_entry->state = LUA_THREAD_YIELDED;

	return lua_yield(thread_entry->lua_state, nresults);
}
