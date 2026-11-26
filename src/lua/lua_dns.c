/*-
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
#include "lua_common.h"
#include "lua_dns_resolver.h"
#include "lua_thread_pool.h"

LUA_FUNCTION_DEF(dns, request);

static const struct luaL_reg dns_f[] = {
	LUA_INTERFACE_DEF(dns, request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}};

static const char *M = "rspamd lua dns";

void lua_dns_callback(struct rdns_reply *reply, void *arg);

struct lua_rspamd_dns_cbdata {
	struct thread_entry *thread;
	guint64 thread_generation;
	struct rspamd_task *task;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_symcache_dynamic_item *item;
	struct rspamd_async_session *s;
};

static int
lua_dns_request(lua_State *L)
{
	GError *err = NULL;
	struct rspamd_async_session *session = NULL;
	struct rspamd_config *cfg = NULL;
	struct lua_rspamd_dns_cbdata *cbdata = NULL;
	const char *to_resolve = NULL;
	const char *type_str = NULL;
	struct rspamd_task *task = NULL;
	struct thread_entry *thread = NULL;
	rspamd_mempool_t *pool = NULL;
	int ret = 0;
	gboolean forced = FALSE;

	/* Check arguments */
	if (!rspamd_lua_parse_table_arguments(L, 1, &err,
										  RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
										  "*name=S;task=U{task};*type=S;forced=B;session=U{session};config=U{config}",
										  &to_resolve,
										  &task,
										  &type_str,
										  &forced,
										  &session,
										  &cfg)) {

		if (err) {
			ret = luaL_error(L, "invalid arguments: %s", err->message);
			g_error_free(err);

			return ret;
		}

		return luaL_error(L, "invalid arguments");
	}

	if (task) {
		session = task->s;
		pool = task->task_pool;
		cfg = task->cfg;
	}
	else if (session && cfg) {
		pool = cfg->cfg_pool;
	}
	else {
		return luaL_error(L, "invalid arguments: either task or session/config should be set");
	}

	/*
	 * The caller is suspended until the reply comes, so it must be a pooled
	 * coroutine that can yield right now; checked before anything is sent
	 */
	if (cfg->lua_thread_pool) {
		thread = lua_thread_pool_get_yieldable_entry(cfg->lua_thread_pool, L);
	}

	if (thread == NULL) {
		return luaL_error(L, "rspamd_dns.request must be called from a coroutine "
							 "that can yield (a symbol registered with flags = 'coro', "
							 "not an async callback)");
	}

	enum rdns_request_type type = rdns_type_fromstr(type_str);

	if (type == RDNS_REQUEST_INVALID) {
		return luaL_error(L, "invalid arguments: this record type is not supported");
	}

	cbdata = rspamd_mempool_alloc0(pool, sizeof(*cbdata));

	cbdata->task = task;

	if (type == RDNS_REQUEST_PTR) {
		char *ptr_str;

		ptr_str = rdns_generate_ptr_from_str(to_resolve);

		if (ptr_str == NULL) {
			msg_err_task_check("wrong resolve string to PTR request: %s",
							   to_resolve);
			lua_pushnil(L);

			return 1;
		}

		to_resolve = rspamd_mempool_strdup(pool, ptr_str);
		free(ptr_str);
	}


	if (task == NULL) {
		ret = (rspamd_dns_resolver_request(cfg->dns_resolver,
										   session,
										   pool,
										   lua_dns_callback,
										   cbdata,
										   type,
										   to_resolve) != NULL);
	}
	else {
		if (forced) {
			ret = rspamd_dns_resolver_request_task_forced(task,
														  lua_dns_callback,
														  cbdata,
														  type,
														  to_resolve);
		}
		else {
			ret = rspamd_dns_resolver_request_task(task,
												   lua_dns_callback,
												   cbdata,
												   type,
												   to_resolve);
		}
	}

	if (ret) {
		cbdata->thread = thread;
		cbdata->thread_generation = thread->generation;
		/* Keep the entry alive until our callback fires (or is cancelled) */
		lua_thread_pool_retain_entry(thread);
		cbdata->s = session;

		if (task) {
			cbdata->item = rspamd_symcache_get_cur_item(task);

			/* No current item outside of the symbols processing (e.g. finish scripts) */
			if (cbdata->item) {
				rspamd_symcache_item_async_inc(task, cbdata->item, M);
			}
		}

		return lua_thread_yield(thread, 0);
	}
	else {
		lua_pushnil(L);
		return 1;
	}
}

void lua_dns_callback(struct rdns_reply *reply, void *arg)
{
	struct lua_rspamd_dns_cbdata *cbdata = arg;
	struct thread_entry *thread = cbdata->thread;
	lua_State *L = thread->lua_state;
	int top;

	/*
	 * A dead coroutine is never run again: e.g. its task has been destroyed
	 * while it waited for a request that is not bound to that task
	 */
	if (thread->state != LUA_THREAD_DEAD) {
		top = lua_gettop(L);

		if (reply->code != RDNS_RC_NOERROR) {
			lua_pushboolean(L, false);
			lua_pushstring(L, rdns_strerror(reply->code));
		}
		else {
			lua_push_dns_reply(L, reply);

			lua_pushboolean(L, reply->flags & RDNS_AUTH);
			lua_setfield(L, -3, "authenticated");

			lua_pushboolean(L, reply->flags & RDNS_TRUNCATED);
			lua_setfield(L, -3, "truncated");

			/* result 1 - not and error */
			lua_pushboolean(L, true);
			/* push table into stack, result 2 - results itself */
			lua_pushvalue(L, -3);
		}

		if (!lua_thread_resume_checked(thread, cbdata->thread_generation, 2)) {
			/* The entry may serve another coroutine: leave its stack as it was */
			lua_settop(L, top);
		}
	}

	/*
	 * cbdata->task is alive even if nothing has been resumed: cbdata is
	 * allocated from its pool and the request is bound to its session, whose
	 * cleanup cancels the request before the task is freed
	 */
	if (cbdata->item) {
		rspamd_symcache_item_async_dec_check(cbdata->task, cbdata->item, M);
	}

	/* Drop the reference taken when the request was issued */
	lua_thread_pool_release_entry(thread);
}

static int
lua_load_dns(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, dns_f);

	return 1;
}

void luaopen_dns(lua_State *L)
{
	rspamd_lua_add_preload(L, "rspamd_dns", lua_load_dns);
}
