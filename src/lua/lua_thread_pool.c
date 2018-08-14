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

struct thread_entry *
lua_thread_pool_get(struct lua_thread_pool *pool)
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
lua_thread_pool_return(struct lua_thread_pool *pool, struct thread_entry *thread_entry)
{
	g_assert (lua_status (thread_entry->lua_state) == 0); /* we can't return a running/yielded thread into the pool */

	if (pool->running_entry == thread_entry) {
		pool->running_entry = NULL;
	}

	if (g_queue_get_length (pool->available_items) <= pool->max_items) {
		thread_entry->cd = NULL;
		g_queue_push_head (pool->available_items, thread_entry);
	}
	else {
		thread_entry_free (pool->L, thread_entry);
	}
}

void
lua_thread_pool_terminate_entry(struct lua_thread_pool *pool, struct thread_entry *thread_entry)
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
lua_thread_pool_get_running_entry(struct lua_thread_pool *pool)
{
	return pool->running_entry;
}

void
lua_thread_pool_set_running_entry(struct lua_thread_pool *pool, struct thread_entry *thread_entry)
{
	pool->running_entry = thread_entry;
}
