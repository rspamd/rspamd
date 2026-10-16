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
#include "libserver/task.h"
#include "lua/lua_common.h"
#include "unix-std.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

extern struct rspamd_main *rspamd_main;
extern struct ev_loop *event_loop;

static void
rspamd_lua_task_store_in_file_test(gboolean limited, gboolean keep)
{
	static const char message[] = "Subject: store_in_file\r\n\r\nTest\0message\r\n";
	lua_State *L = rspamd_main->cfg->lua_state;
	struct rspamd_task *task;
	char *dirname, *filename, *contents = NULL;
	gsize len = 0;
	gboolean result_ok, contents_ok, exists_before, exists_after;
	int ret, top = lua_gettop(L);
#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
	struct rlimit old_limit, limit;
	struct sigaction old_action, action;
#endif

	dirname = g_build_filename(g_get_tmp_dir(), "rspamd-store-in-file-XXXXXX", NULL);
	g_assert(g_mkdtemp(dirname) != NULL);
	filename = g_build_filename(dirname, "message", NULL);
	task = rspamd_task_new(NULL, rspamd_main->cfg, NULL, NULL, event_loop, FALSE);
	task->msg.begin = message;
	task->msg.len = sizeof(message) - 1;

	rspamd_lua_task_push(L, task);
	lua_getfield(L, -1, "store_in_file");
	lua_pushvalue(L, -2);
	lua_newtable(L);
	lua_pushstring(L, filename);
	lua_setfield(L, -2, "filename");
	lua_pushinteger(L, 00600);
	lua_setfield(L, -2, "mode");
	lua_pushboolean(L, keep);
	lua_setfield(L, -2, "keep");

#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
	if (limited) {
		/* Force a short write, followed by EFBIG on the next write. */
		g_assert_cmpint(getrlimit(RLIMIT_FSIZE, &old_limit), ==, 0);
		limit = old_limit;
		limit.rlim_cur = 1;
		memset(&action, 0, sizeof(action));
		action.sa_handler = SIG_IGN;
		sigemptyset(&action.sa_mask);
		g_assert_cmpint(sigaction(SIGXFSZ, &action, &old_action), ==, 0);
		g_assert_cmpint(setrlimit(RLIMIT_FSIZE, &limit), ==, 0);
	}
#endif

	ret = lua_pcall(L, 2, 1, 0);

#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
	if (limited) {
		/* Restore process state even when the Lua call failed. */
		g_assert_cmpint(setrlimit(RLIMIT_FSIZE, &old_limit), ==, 0);
		g_assert_cmpint(sigaction(SIGXFSZ, &old_action, NULL), ==, 0);
	}
#endif

	if (limited) {
		result_ok = ret == 0 && lua_isnil(L, -1);
	}
	else {
		result_ok = ret == 0 && lua_type(L, -1) == LUA_TSTRING &&
					strcmp(lua_tostring(L, -1), filename) == 0;
	}
	exists_before = g_file_test(filename, G_FILE_TEST_EXISTS);
	contents_ok = g_file_get_contents(filename, &contents, &len, NULL) &&
				  len == sizeof(message) - 1 &&
				  memcmp(contents, message, len) == 0;
	g_free(contents);
	lua_settop(L, top);
	rspamd_task_free(task);
	exists_after = g_file_test(filename, G_FILE_TEST_EXISTS);

	/* Clean up before asserting, including when testing the unpatched code. */
	unlink(filename);
	g_assert_cmpint(rmdir(dirname), ==, 0);
	g_free(filename);
	g_free(dirname);

	g_assert(result_ok);
	if (limited) {
		/* Incomplete files must be removed immediately, even with keep=true. */
		g_assert(!exists_before);
		g_assert(!exists_after);
	}
	else {
		g_assert(contents_ok);
		g_assert(exists_before);
		g_assert(exists_after == keep);
	}
}

void rspamd_lua_task_test_func(void)
{
	rspamd_lua_task_store_in_file_test(FALSE, FALSE);
	rspamd_lua_task_store_in_file_test(FALSE, TRUE);
#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
	rspamd_lua_task_store_in_file_test(TRUE, FALSE);
	rspamd_lua_task_store_in_file_test(TRUE, TRUE);
#endif
}
