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

#define msg_debug_lua_threads(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_lua_threads_log_id, "lua_threads", NULL, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(lua_threads)

static struct thread_entry *thread_entry_new(lua_State *L);
static void thread_entry_free(lua_State *L, struct thread_entry *ent);

#define CFG_POOL_GET(cfg) (reinterpret_cast<lua_thread_pool*>((cfg)->lua_thread_pool))

struct lua_thread_pool {
	std::vector<struct thread_entry *> available_items;
	lua_State *L;
	gint max_items;
	struct thread_entry *running_entry;
	static const int default_max_items = 100;

	lua_thread_pool(lua_State *L, gint max_items = default_max_items) :
			L(L), max_items(max_items) {
		running_entry = nullptr;
		available_items.reserve(max_items);

		for (auto i = 0; i < MAX(2, max_items / 10); i++) {
			auto *ent = thread_entry_new(L);
			available_items.push_back(ent);
		}
	}

	~lua_thread_pool() {
		for (auto *ent : available_items) {
			thread_entry_free(L, ent);
		}
	}

	auto get_thread() -> struct thread_entry * {
		struct thread_entry *ent;

		if (!available_items.empty()) {
			ent = available_items.back();
			available_items.pop_back();
		}
		else {
			ent = thread_entry_new(L);
		}

		running_entry = ent;

		return ent;
	}

	auto return_thread(struct thread_entry *thread_entry, const gchar *loc) -> void {
		/* we can't return a running/yielded thread into the pool */
		g_assert (lua_status(thread_entry->lua_state) == 0);

		if (running_entry == thread_entry) {
			running_entry = NULL;
		}

		if (available_items.size() <= max_items) {
			thread_entry->cd = NULL;
			thread_entry->finish_callback = NULL;
			thread_entry->error_callback = NULL;
			thread_entry->task = NULL;
			thread_entry->cfg = NULL;

			msg_debug_lua_threads ("%s: returned thread to the threads pool %ud items",
					loc,
					available_items.size());

			available_items.push_back(thread_entry);
		}
		else {
			msg_debug_lua_threads ("%s: removed thread as thread pool has %ud items",
					loc,
					available_items.size());
			thread_entry_free(L, thread_entry);
		}
	}

	auto terminate_thread(struct thread_entry *thread_entry,
						  const gchar *loc,
						  bool enforce) -> void {
		struct thread_entry *ent = NULL;

		if (!enforce) {
			/* we should only terminate failed threads */
			g_assert (lua_status(thread_entry->lua_state) != 0 &&
					  lua_status(thread_entry->lua_state) != LUA_YIELD);
		}

		if (running_entry == thread_entry) {
			running_entry = NULL;
		}

		msg_debug_lua_threads ("%s: terminated thread entry", loc);
		thread_entry_free(L, thread_entry);

		if (available_items.size() <= max_items) {
			ent = thread_entry_new(L);
			available_items.push_back(ent);
		}
	}

	auto get_running_entry(void) -> struct thread_entry * {
		return running_entry;
	};

	auto set_running_entry(struct thread_entry *ent) -> struct thread_entry * {
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

void
lua_thread_pool_free(struct lua_thread_pool *pool)
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

void
lua_thread_pool_return_full(struct lua_thread_pool *pool,
							struct thread_entry *thread_entry, const gchar *loc)
{
	pool->return_thread(thread_entry, loc);
}

void
lua_thread_pool_terminate_entry_full(struct lua_thread_pool *pool,
									 struct thread_entry *thread_entry, const gchar *loc,
									 bool enforce)
{
	pool->terminate_thread(thread_entry, loc, enforce);
}

struct thread_entry *
lua_thread_pool_get_running_entry_full(struct lua_thread_pool *pool,
									   const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_get_running_entry_full", loc);
	return pool->get_running_entry();
}

void
lua_thread_pool_set_running_entry_full(struct lua_thread_pool *pool,
									   struct thread_entry *thread_entry,
									   const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_set_running_entry_full", loc);
	pool->set_running_entry(thread_entry);
}

static void
lua_thread_pool_set_running_entry_for_thread(struct thread_entry *thread_entry,
											 const gchar *loc)
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

void
lua_thread_pool_prepare_callback_full(struct lua_thread_pool *pool,
									  struct lua_callback_state *cbs,
									  const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_prepare_callback_full", loc);
	cbs->thread_pool = pool;
	cbs->previous_thread = lua_thread_pool_get_running_entry_full(pool, loc);
	cbs->my_thread = pool->get_thread();
	cbs->L = cbs->my_thread->lua_state;
}

void
lua_thread_pool_restore_callback_full(struct lua_callback_state *cbs,
									  const gchar *loc)
{
	lua_thread_pool_return_full(cbs->thread_pool, cbs->my_thread, loc);
	lua_thread_pool_set_running_entry_full(cbs->thread_pool,
			cbs->previous_thread, loc);
}

static gint
lua_do_resume_full(lua_State *L, gint narg, const gchar *loc) {
#if LUA_VERSION_NUM >= 504
	int nres;
#endif
	msg_debug_lua_threads ("%s: lua_do_resume_full", loc);
#if LUA_VERSION_NUM < 502
	return lua_resume(L, narg);
#else
#if LUA_VERSION_NUM >= 504
	return lua_resume (L, NULL, narg, &nres);
#else
	return lua_resume (L, NULL, narg);
#endif
#endif
}

static void
lua_resume_thread_internal_full(struct thread_entry *thread_entry,
								gint narg, const gchar *loc) {
	gint ret;
	struct lua_thread_pool *pool;
	struct rspamd_task *task;

	msg_debug_lua_threads ("%s: lua_resume_thread_internal_full", loc);
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
						lua_tostring (thread_entry->lua_state, -1));
			}
			else if (thread_entry->task) {
				task = thread_entry->task;
				msg_err_task ("lua call failed (%d): %s", ret,
						lua_tostring(thread_entry->lua_state, -1));
			}
			else {
				msg_err ("lua call failed (%d): %s", ret,
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

void
lua_thread_resume_full(struct thread_entry *thread_entry, gint narg,
					   const gchar *loc)
{
	/*
	 * The only state where we can resume from is LUA_YIELD
	 * Another acceptable status is OK (0) but in that case we should push function on stack
	 * to start the thread from, which is happening in lua_thread_call(), not in this function.
	 */
	g_assert (lua_status(thread_entry->lua_state) == LUA_YIELD);
	msg_debug_lua_threads ("%s: lua_thread_resume_full", loc);
	lua_thread_pool_set_running_entry_for_thread(thread_entry, loc);
	lua_resume_thread_internal_full(thread_entry, narg, loc);
}

void
lua_thread_call_full(struct thread_entry *thread_entry,
					 int narg, const gchar *loc)
{
	g_assert (lua_status(thread_entry->lua_state) == 0); /* we can't call running/yielded thread */
	g_assert (thread_entry->task != NULL || thread_entry->cfg != NULL); /* we can't call without pool */

	lua_resume_thread_internal_full(thread_entry, narg, loc);
}

gint
lua_thread_yield_full(struct thread_entry *thread_entry,
					  gint nresults,
					  const gchar *loc) {
	g_assert (lua_status(thread_entry->lua_state) == 0);

	msg_debug_lua_threads ("%s: lua_thread_yield_full", loc);
	return lua_yield(thread_entry->lua_state, nresults);
}
