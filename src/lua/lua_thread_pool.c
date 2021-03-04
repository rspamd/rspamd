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

#define msg_debug_lua_threads(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_lua_threads_log_id, "lua_threads", NULL, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(lua_threads)

struct lua_thread_pool {
	GQueue *available_items;
	lua_State *L;
	gint max_items;
	struct thread_entry *running_entry;
};

static struct thread_entry *
thread_entry_new (lua_State * L)
{
	struct thread_entry *ent;
	ent = g_new0(struct thread_entry, 1);
	ent->lua_state = lua_newthread (L);
	ent->thread_index = luaL_ref (L, LUA_REGISTRYINDEX);

	return ent;
}

static void
thread_entry_free (lua_State * L, struct thread_entry *ent)
{
	luaL_unref (L, LUA_REGISTRYINDEX, ent->thread_index);
	g_free (ent);
}

struct lua_thread_pool *
lua_thread_pool_new (lua_State * L)
{
	struct lua_thread_pool * pool = g_new0 (struct lua_thread_pool, 1);

	pool->L = L;
	pool->max_items = 100;

	pool->available_items = g_queue_new ();
	int i;

	struct thread_entry *ent;
	for (i = 0; i < MAX(2, pool->max_items / 10); i ++) {
		ent = thread_entry_new (pool->L);
		g_queue_push_head (pool->available_items, ent);
	}

	return pool;
}

void
lua_thread_pool_free (struct lua_thread_pool *pool)
{
	struct thread_entry *ent = NULL;
	while (!g_queue_is_empty (pool->available_items)) {
		ent = g_queue_pop_head (pool->available_items);
		thread_entry_free (pool->L, ent);
	}
	g_queue_free (pool->available_items);
	g_free (pool);
}

static struct thread_entry *lua_thread_pool_get (struct lua_thread_pool *pool);

struct thread_entry *
lua_thread_pool_get_for_task (struct rspamd_task *task)
{
	struct thread_entry *ent = lua_thread_pool_get (task->cfg->lua_thread_pool);

	ent->task = task;

	return ent;
}

struct thread_entry *
lua_thread_pool_get_for_config (struct rspamd_config *cfg)
{
	struct thread_entry *ent = lua_thread_pool_get (cfg->lua_thread_pool);

	ent->cfg = cfg;

	return ent;
}

static struct thread_entry *
lua_thread_pool_get (struct lua_thread_pool *pool)
{
	gpointer cur;
	struct thread_entry *ent = NULL;
	cur = g_queue_pop_head (pool->available_items);

	if (cur) {
		ent = cur;
	}
	else {
		ent = thread_entry_new (pool->L);
	}

	pool->running_entry = ent;

	return ent;
}

void
lua_thread_pool_return_full (struct lua_thread_pool *pool,
		struct thread_entry *thread_entry, const gchar *loc)
{
	/* we can't return a running/yielded thread into the pool */
	g_assert (lua_status (thread_entry->lua_state) == 0);

	if (pool->running_entry == thread_entry) {
		pool->running_entry = NULL;
	}

	if (g_queue_get_length (pool->available_items) <= pool->max_items) {
		thread_entry->cd = NULL;
		thread_entry->finish_callback = NULL;
		thread_entry->error_callback = NULL;
		thread_entry->task = NULL;
		thread_entry->cfg = NULL;

		msg_debug_lua_threads ("%s: returned thread to the threads pool %ud items",
				loc,
				g_queue_get_length (pool->available_items));

		g_queue_push_head (pool->available_items, thread_entry);
	}
	else {
		msg_debug_lua_threads ("%s: removed thread as thread pool has %ud items",
				loc,
				g_queue_get_length (pool->available_items));
		thread_entry_free (pool->L, thread_entry);
	}
}

static void
lua_thread_pool_terminate_entry (struct lua_thread_pool *pool,
		struct thread_entry *thread_entry, const gchar *loc)
{
	struct thread_entry *ent = NULL;

	/* we should only terminate failed threads */
	g_assert (lua_status (thread_entry->lua_state) != 0 && lua_status (thread_entry->lua_state) != LUA_YIELD);

	if (pool->running_entry == thread_entry) {
		pool->running_entry = NULL;
	}

	msg_debug_lua_threads ("%s: terminated thread entry", loc);
	thread_entry_free (pool->L, thread_entry);

	if (g_queue_get_length (pool->available_items) <= pool->max_items) {
		ent = thread_entry_new (pool->L);
		g_queue_push_head (pool->available_items, ent);
	}
}

struct thread_entry *
lua_thread_pool_get_running_entry_full (struct lua_thread_pool *pool,
		const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_get_running_entry_full", loc);
	return pool->running_entry;
}

void
lua_thread_pool_set_running_entry_full (struct lua_thread_pool *pool,
										struct thread_entry *thread_entry,
										const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_set_running_entry_full", loc);
	pool->running_entry = thread_entry;
}

static void
lua_thread_pool_set_running_entry_for_thread (struct thread_entry *thread_entry,
		const gchar *loc)
{
	struct lua_thread_pool *pool;

	if (thread_entry->task) {
		pool = thread_entry->task->cfg->lua_thread_pool;
	}
	else {
		pool = thread_entry->cfg->lua_thread_pool;
	}

	lua_thread_pool_set_running_entry_full (pool, thread_entry, loc);
}

void
lua_thread_pool_prepare_callback_full (struct lua_thread_pool *pool,
		struct lua_callback_state *cbs, const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_thread_pool_prepare_callback_full", loc);
	cbs->thread_pool = pool;
	cbs->previous_thread = lua_thread_pool_get_running_entry_full (pool, loc);
	cbs->my_thread = lua_thread_pool_get (pool);
	cbs->L = cbs->my_thread->lua_state;
}

void
lua_thread_pool_restore_callback_full (struct lua_callback_state *cbs,
									   const gchar *loc)
{
	lua_thread_pool_return_full (cbs->thread_pool, cbs->my_thread, loc);
	lua_thread_pool_set_running_entry_full (cbs->thread_pool,
			cbs->previous_thread, loc);
}

static gint
lua_do_resume_full (lua_State *L, gint narg, const gchar *loc)
{
	msg_debug_lua_threads ("%s: lua_do_resume_full", loc);
#if LUA_VERSION_NUM < 502
	return lua_resume (L, narg);
#else
	#if LUA_VERSION_NUM >= 504
	return lua_resume (L, NULL, narg, NULL);
	#else
	return lua_resume (L, NULL, narg);
	#endif
#endif
}

static void lua_resume_thread_internal_full (struct thread_entry *thread_entry,
		gint narg, const gchar *loc);

void
lua_thread_call_full (struct thread_entry *thread_entry,
					  int narg, const gchar *loc)
{
	g_assert (lua_status (thread_entry->lua_state) == 0); /* we can't call running/yielded thread */
	g_assert (thread_entry->task != NULL || thread_entry->cfg != NULL); /* we can't call without pool */

	lua_resume_thread_internal_full (thread_entry, narg, loc);
}

void
lua_thread_resume_full (struct thread_entry *thread_entry, gint narg,
		const gchar *loc)
{
	/*
	 * The only state where we can resume from is LUA_YIELD
	 * Another acceptable status is OK (0) but in that case we should push function on stack
	 * to start the thread from, which is happening in lua_thread_call(), not in this function.
	 */
	g_assert (lua_status (thread_entry->lua_state) == LUA_YIELD);
	msg_debug_lua_threads ("%s: lua_thread_resume_full", loc);
	lua_thread_pool_set_running_entry_for_thread (thread_entry, loc);

	lua_resume_thread_internal_full (thread_entry, narg, loc);
}

static void
lua_resume_thread_internal_full (struct thread_entry *thread_entry,
		gint narg, const gchar *loc)
{
	gint ret;
	struct lua_thread_pool *pool;
	struct rspamd_task *task;

	msg_debug_lua_threads ("%s: lua_resume_thread_internal_full", loc);
	ret = lua_do_resume_full (thread_entry->lua_state, narg, loc);

	if (ret != LUA_YIELD) {
		/*
		 LUA_YIELD state should not be handled here.
		 It should only happen when the thread initiated a asynchronous event and it will be restored as soon
		 the event is finished
		 */

		if (thread_entry->task) {
			pool = thread_entry->task->cfg->lua_thread_pool;
		}
		else {
			pool = thread_entry->cfg->lua_thread_pool;
		}

		if (ret == 0) {
			if (thread_entry->finish_callback) {
				thread_entry->finish_callback (thread_entry, ret);
			}
			lua_thread_pool_return_full (pool, thread_entry, loc);
		}
		else {
			rspamd_lua_traceback (thread_entry->lua_state);
			if (thread_entry->error_callback) {
				thread_entry->error_callback (thread_entry, ret,
						lua_tostring (thread_entry->lua_state, -1));
			}
			else if (thread_entry->task) {
				task = thread_entry->task;
				msg_err_task ("lua call failed (%d): %s", ret,
						lua_tostring (thread_entry->lua_state, -1));
			}
			else {
				msg_err ("lua call failed (%d): %s", ret,
						lua_tostring (thread_entry->lua_state, -1));
			}

			/*
			 * Maybe there is a way to recover here.
			 * For now, just remove faulty thread
			 */
			lua_thread_pool_terminate_entry (pool, thread_entry, loc);
		}
	}
}

gint
lua_thread_yield_full (struct thread_entry *thread_entry,
					   gint nresults,
					   const gchar *loc)
{
	g_assert (lua_status (thread_entry->lua_state) == 0);

	msg_debug_lua_threads ("%s: lua_thread_yield_full", loc);
	return lua_yield (thread_entry->lua_state, nresults);
}
