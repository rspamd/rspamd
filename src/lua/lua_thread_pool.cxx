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
			thread_entry_free(L, ent);
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

		if (available_items.size() <= max_items) {
			thread_entry->cd = NULL;
			thread_entry->finish_callback = NULL;
			thread_entry->error_callback = NULL;
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
			thread_entry_free(L, thread_entry);
		}
	}

	auto terminate_thread(struct thread_entry *thread_entry,
						  const char *loc,
						  bool enforce) -> void
	{
		struct thread_entry *ent = NULL;

		if (!enforce) {
			/* we should only terminate failed threads */
			g_assert(lua_status(thread_entry->lua_state) != 0 &&
					 lua_status(thread_entry->lua_state) != LUA_YIELD);
		}

		if (running_entry == thread_entry) {
			running_entry = NULL;
		}

		thread_entry->state = LUA_THREAD_DEAD;

		msg_debug_lua_threads("%s: terminated thread entry", loc);
		thread_entry_free(L, thread_entry);

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

static struct thread_entry *
thread_entry_new(lua_State *L)
{
	struct thread_entry *ent;
	ent = g_new0(struct thread_entry, 1);
	ent->lua_state = lua_newthread(L);
	ent->thread_index = luaL_ref(L, LUA_REGISTRYINDEX);
	ent->state = LUA_THREAD_FREE;
	ent->generation = 0;

	return ent;
}

static void
thread_entry_free(lua_State *L, struct thread_entry *ent)
{
	luaL_unref(L, LUA_REGISTRYINDEX, ent->thread_index);
	g_free(ent);
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


struct thread_entry *
lua_thread_pool_get_for_task(struct rspamd_task *task)
{
	struct thread_entry *ent = CFG_POOL_GET(task->cfg)->get_thread();

	ent->task = task;

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

void lua_thread_pool_set_running_entry_full(struct lua_thread_pool *pool,
											struct thread_entry *thread_entry,
											const char *loc)
{
	msg_debug_lua_threads("%s: lua_thread_pool_set_running_entry_full", loc);
	pool->set_running_entry(thread_entry);
}

static void
lua_thread_pool_set_running_entry_for_thread(struct thread_entry *thread_entry,
											 const char *loc)
{
	struct lua_thread_pool *pool;

	if (thread_entry->task) {
		pool = CFG_POOL_GET(thread_entry->task->cfg);
	}
	else {
		pool = CFG_POOL_GET(thread_entry->cfg);
	}

	lua_thread_pool_set_running_entry_full(pool, thread_entry, loc);
}

void lua_thread_pool_prepare_callback_full(struct lua_thread_pool *pool,
										   struct lua_callback_state *cbs,
										   const char *loc)
{
	msg_debug_lua_threads("%s: lua_thread_pool_prepare_callback_full", loc);
	cbs->thread_pool = pool;
	cbs->previous_thread = lua_thread_pool_get_running_entry_full(pool, loc);
	cbs->my_thread = pool->get_thread();
	cbs->L = cbs->my_thread->lua_state;
}

void lua_thread_pool_restore_callback_full(struct lua_callback_state *cbs,
										   const char *loc)
{
	lua_thread_pool_return_full(cbs->thread_pool, cbs->my_thread, loc);
	lua_thread_pool_set_running_entry_full(cbs->thread_pool,
										   cbs->previous_thread, loc);
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
								int narg, const char *loc)
{
	int ret;
	struct lua_thread_pool *pool;
	struct rspamd_task *task;

	msg_debug_lua_threads("%s: lua_resume_thread_internal_full", loc);
	ret = lua_do_resume_full(thread_entry->lua_state, narg, loc);

	if (ret != LUA_YIELD) {
		/*
		 LUA_YIELD state should not be handled here.
		 It should only happen when the thread initiated a asynchronous event and it will be restored as soon
		 the event is finished
		 */

		if (thread_entry->task) {
			pool = CFG_POOL_GET(thread_entry->task->cfg);
		}
		else {
			pool = CFG_POOL_GET(thread_entry->cfg);
		}

		if (ret == 0) {
			if (thread_entry->finish_callback) {
				thread_entry->finish_callback(thread_entry, ret);
			}

			pool->return_thread(thread_entry, loc);
		}
		else {
			rspamd_lua_traceback(thread_entry->lua_state);
			if (thread_entry->error_callback) {
				thread_entry->error_callback(thread_entry, ret,
											 lua_tostring(thread_entry->lua_state, -1));
			}
			else if (thread_entry->task) {
				task = thread_entry->task;
				msg_err_task("lua call failed (%d): %s", ret,
							 lua_tostring(thread_entry->lua_state, -1));
			}
			else {
				msg_err("lua call failed (%d): %s", ret,
						lua_tostring(thread_entry->lua_state, -1));
			}

			/*
			 * Maybe there is a way to recover here.
			 * For now, just remove faulty thread
			 */
			pool->terminate_thread(thread_entry, loc, false);
		}
	}
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
	lua_thread_pool_set_running_entry_for_thread(thread_entry, loc);
	lua_resume_thread_internal_full(thread_entry, narg, loc);
}

bool lua_thread_resume_checked_full(struct thread_entry *thread_entry,
									guint64 expected_generation,
									int narg,
									const char *loc)
{
	struct rspamd_task *task = thread_entry->task;

	msg_debug_lua_threads("%s: lua_thread_resume_checked_full", loc);

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
	lua_thread_pool_set_running_entry_for_thread(thread_entry, loc);
	lua_resume_thread_internal_full(thread_entry, narg, loc);

	return true;
}

void lua_thread_call_full(struct thread_entry *thread_entry,
						  int narg, const char *loc)
{
	g_assert(lua_status(thread_entry->lua_state) == 0);                /* we can't call running/yielded thread */
	g_assert(thread_entry->state == LUA_THREAD_RUNNING);               /* must be freshly acquired */
	g_assert(thread_entry->task != NULL || thread_entry->cfg != NULL); /* we can't call without pool */

	lua_resume_thread_internal_full(thread_entry, narg, loc);
}

int lua_thread_yield_full(struct thread_entry *thread_entry,
						  int nresults,
						  const char *loc)
{
	g_assert(lua_status(thread_entry->lua_state) == 0);
	g_assert(thread_entry->state == LUA_THREAD_RUNNING);

	msg_debug_lua_threads("%s: lua_thread_yield_full", loc);
	thread_entry->state = LUA_THREAD_YIELDED;

	return lua_yield(thread_entry->lua_state, nresults);
}
