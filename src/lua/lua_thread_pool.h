#ifndef LUA_THREAD_POOL_H_
#define LUA_THREAD_POOL_H_

#include <lua.h>

struct thread_entry {
	lua_State *lua_state;
	gint thread_index;
};

struct thread_pool;

struct lua_thread_pool *
lua_thread_pool_new (lua_State * L);

void
lua_thread_pool_free (struct lua_thread_pool *pool);

struct thread_entry *
lua_thread_pool_get(struct lua_thread_pool *pool);

void
lua_thread_pool_return(struct lua_thread_pool *pool, struct thread_entry *thread_entry);

void
lua_thread_pool_terminate_entry(struct lua_thread_pool *pool, struct thread_entry *thread_entry);

struct thread_entry *
lua_thread_pool_get_running_entry(struct lua_thread_pool *pool);

void
lua_thread_pool_set_running_entry(struct lua_thread_pool *pool, struct thread_entry *thread_entry);

#endif /* LUA_THREAD_POOL_H_ */

