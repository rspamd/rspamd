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

#include "config.h"
#include "rspamd.h"
#include "util.h"
#include "lua/lua_common.h"
#include "lua/lua_thread_pool.h"
#include "unix-std.h"

static const char *lua_src_name = "lua/pcall_test.lua";
extern gchar *argv0_dirname;

extern struct rspamd_main *rspamd_main;

const int N = 20000;


static gdouble
test_pcall(lua_State *L, gint function_call)
{
	gdouble t1, t2;
	gint i;
	t1 = rspamd_get_virtual_ticks ();

	for (i = 0; i < N; i ++) {
		lua_rawgeti (L, LUA_REGISTRYINDEX, function_call);
		lua_pcall (L, 0, 1, 0);
		lua_pop (L, 1);
	}

	t2 = rspamd_get_virtual_ticks ();

	return t2 - t1;
}

static gdouble
test_resume(lua_State *L, gint function_call)
{
	gdouble t1, t2;
	gint i;
	t1 = rspamd_get_virtual_ticks ();

	for (i = 0; i < N; i ++) {
		lua_rawgeti (L, LUA_REGISTRYINDEX, function_call);
#if LUA_VERSION_NUM < 502
		lua_resume (L, 0);
#elif LUA_VERSION_NUM >= 504
		lua_resume (L, NULL, 0, NULL);
#else
		lua_resume (L, NULL, 0);
#endif
		lua_pop (L, 1);
	}

	t2 = rspamd_get_virtual_ticks ();

	return t2 - t1;
}

static gdouble
test_resume_get_thread(gint function_call)
{
	gdouble t1, t2;
	gint i;
	struct thread_entry *ent;

	t1 = rspamd_get_virtual_ticks ();

	for (i = 0; i < N; i ++) {
		ent = lua_thread_pool_get_for_config (rspamd_main->cfg);

		lua_rawgeti (ent->lua_state, LUA_REGISTRYINDEX, function_call);
#if LUA_VERSION_NUM < 502
		lua_resume (ent->lua_state, 0);
#elif LUA_VERSION_NUM >= 504
		lua_resume (ent->lua_state, NULL, 0, NULL);
#else
		lua_resume (ent->lua_state, NULL, 0);
#endif
		lua_pop (ent->lua_state, 1);

		lua_thread_pool_return (rspamd_main->cfg->lua_thread_pool, ent);
	}

	t2 = rspamd_get_virtual_ticks ();

	return t2 - t1;
}

static gdouble
test_resume_get_new_thread(gint function_call)
{
	gdouble t1, t2;
	gint i;
	struct thread_entry *ent;

	t1 = rspamd_get_virtual_ticks ();

	for (i = 0; i < N; i ++) {
		ent = lua_thread_pool_get_for_task (rspamd_main->cfg->lua_thread_pool);

		lua_rawgeti (ent->lua_state, LUA_REGISTRYINDEX, function_call);
#if LUA_VERSION_NUM < 502
		lua_resume (ent->lua_state, 0);
#elif LUA_VERSION_NUM >= 504
		lua_resume (ent->lua_state, NULL, 0, NULL);
#else
		lua_resume (ent->lua_state, NULL, 0);
#endif
		lua_pop (ent->lua_state, 1);

		/* lua_thread_pool_return (rspamd_main->cfg->lua_thread_pool, ent); */
	}

	t2 = rspamd_get_virtual_ticks ();

	return t2 - t1;
}

void
rspamd_lua_lua_pcall_vs_resume_test_func (void)
{
	lua_State *L = rspamd_main->cfg->lua_state;
	gchar *lua_src;
	gdouble t1, reference;

	lua_src = g_build_filename (argv0_dirname, lua_src_name, NULL);
	if (luaL_dofile (L, lua_src) != 0) {
		msg_err ("failed to load test file: %s ", lua_tostring (L, -1));
		g_assert (0);
	}
	g_free (lua_src);

	gint function_call = luaL_ref (L, LUA_REGISTRYINDEX);

	msg_info ("calling");

	reference = t1 = test_pcall(L, function_call);
	msg_notice ("pcall stat: ts: %1.5f, avg:%1.5f, slow=%1.2f", t1, t1/(gdouble)N, t1 / reference);

	t1 = test_resume (L, function_call);
	msg_notice ("resume stat: ts: %1.5f, avg:%1.5f, slow=%1.2f", t1, t1/(gdouble)N, t1 / reference);

	t1 = test_resume_get_thread (function_call);
	msg_notice ("resume+get thread stat: ts: %1.5f, avg:%1.5f, slow=%1.2f", t1, t1/(gdouble)N, t1 / reference);

	t1 = test_resume_get_new_thread (function_call);
	msg_notice ("resume+get [new] thread stat: ts: %1.5f, avg:%1.5f, slow=%1.2f", t1, t1/(gdouble)N, t1 / reference);
}
