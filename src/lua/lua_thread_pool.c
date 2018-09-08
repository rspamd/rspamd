#include "config.h"

#include "lua_common.h"
#include "lua_thread_pool.h"

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

struct thread_entry *lua_thread_pool_get_for_config (struct rspamd_config *cfg);

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
lua_thread_pool_return (struct lua_thread_pool *pool, struct thread_entry *thread_entry)
{
	g_assert (lua_status (thread_entry->lua_state) == 0); /* we can't return a running/yielded thread into the pool */

	if (pool->running_entry == thread_entry) {
		pool->running_entry = NULL;
	}

	if (g_queue_get_length (pool->available_items) <= pool->max_items) {
		thread_entry->cd = NULL;
		thread_entry->finish_callback = NULL;
		thread_entry->error_callback = NULL;
		thread_entry->task = NULL;
		thread_entry->cfg = NULL;

		g_queue_push_head (pool->available_items, thread_entry);
	}
	else {
		thread_entry_free (pool->L, thread_entry);
	}
}

static void
lua_thread_pool_terminate_entry (struct lua_thread_pool *pool, struct thread_entry *thread_entry)
{
	struct thread_entry *ent = NULL;

	/* we should only terminate failed threads */
	g_assert (lua_status (thread_entry->lua_state) != 0 && lua_status (thread_entry->lua_state) != LUA_YIELD);

	if (pool->running_entry == thread_entry) {
		pool->running_entry = NULL;
	}

	thread_entry_free (pool->L, thread_entry);

	if (g_queue_get_length (pool->available_items) <= pool->max_items) {
		ent = thread_entry_new (pool->L);
		g_queue_push_head (pool->available_items, ent);
	}
}

struct thread_entry *
lua_thread_pool_get_running_entry (struct lua_thread_pool *pool)
{
	return pool->running_entry;
}

void
lua_thread_pool_set_running_entry (struct lua_thread_pool *pool, struct thread_entry *thread_entry)
{
	pool->running_entry = thread_entry;
}

static void
lua_thread_pool_set_running_entry_for_thread (struct thread_entry *thread_entry)
{
	struct lua_thread_pool *pool;

	if (thread_entry->task) {
		pool = thread_entry->task->cfg->lua_thread_pool;
	}
	else {
		pool = thread_entry->cfg->lua_thread_pool;
	}

	lua_thread_pool_set_running_entry (pool, thread_entry);
}

void
lua_thread_pool_prepare_callback (struct lua_thread_pool *pool, struct lua_callback_state *cbs)
{
	cbs->thread_pool = pool;
	cbs->previous_thread = lua_thread_pool_get_running_entry (pool);
	cbs->my_thread = lua_thread_pool_get (pool);
	cbs->L = cbs->my_thread->lua_state;
}

void
lua_thread_pool_restore_callback (struct lua_callback_state *cbs)
{
	lua_thread_pool_return (cbs->thread_pool, cbs->my_thread);
	lua_thread_pool_set_running_entry (cbs->thread_pool, cbs->previous_thread);
}

static gint
lua_do_resume (lua_State *L, gint narg)
{
#if LUA_VERSION_NUM < 503
	return lua_resume (L, narg);
#else
	return lua_resume (L, NULL, narg);
#endif
}

static void lua_resume_thread_internal (struct thread_entry *thread_entry, gint narg);

void
lua_thread_call (struct thread_entry *thread_entry, int narg)
{
	g_assert (lua_status (thread_entry->lua_state) == 0); /* we can't call running/yielded thread */
	g_assert (thread_entry->task != NULL || thread_entry->cfg != NULL); /* we can't call without pool */

	lua_resume_thread_internal (thread_entry, narg);
}

void
lua_thread_resume (struct thread_entry *thread_entry, gint narg)
{
	/*
	 * The only state where we can resume from is LUA_YIELD
	 * Another acceptable status is OK (0) but in that case we should push function on stack
	 * to start the thread from, which is happening in lua_thread_call(), not in this function.
	 */
	g_assert (lua_status (thread_entry->lua_state) == LUA_YIELD);

	lua_thread_pool_set_running_entry_for_thread(thread_entry);

	lua_resume_thread_internal (thread_entry, narg);
}

static void
lua_resume_thread_internal (struct thread_entry *thread_entry, gint narg)
{
	gint ret;
	struct lua_thread_pool *pool;
	GString *tb;
	struct rspamd_task *task;

	ret = lua_do_resume (thread_entry->lua_state, narg);

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
			lua_thread_pool_return (pool, thread_entry);
		}
		else {
			tb = rspamd_lua_get_traceback_string (thread_entry->lua_state);
			if (thread_entry->error_callback) {
				thread_entry->error_callback (thread_entry, ret, tb->str);
			}
			else if (thread_entry->task) {
				task = thread_entry->task;
				msg_err_task ("lua call failed (%d): %v", ret, tb);
			}
			else {
				msg_err ("lua call failed (%d): %v", ret, tb);
			}

			if (tb) {
				g_string_free (tb, TRUE);
			}
			/* maybe there is a way to recover here. For now, just remove faulty thread */
			lua_thread_pool_terminate_entry (pool, thread_entry);
		}
	}
}

gint
lua_thread_yield (struct thread_entry *thread_entry, gint nresults)
{
	g_assert (lua_status (thread_entry->lua_state) == 0);

	return lua_yield (thread_entry->lua_state, nresults);
}
