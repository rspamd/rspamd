/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "rspamd.h"
#include "util.h"
#include "lua/lua_common.h"
#include "unix-std.h"

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

static const char *lua_src_name = "lua/tests.lua";
extern gchar *lua_test;
extern gchar *lua_test_case;
extern gchar *argv0_dirname;
extern struct rspamd_main *rspamd_main;

static int
traceback (lua_State *L)
{
	if (!lua_isstring (L, 1)) {
		return 1;
	}

	lua_getglobal (L, "debug");

	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}

	lua_getfield (L, -1, "traceback");

	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue (L, 1);
	lua_pushinteger (L, 2);
	lua_call(L, 2, 1);

	return 1;
}

void
rspamd_lua_test_func (void)
{
	lua_State *L = (lua_State *)rspamd_main->cfg->lua_state;
	gchar *lua_src, *rp, rp_buf[PATH_MAX], path_buf[PATH_MAX], *tmp, *dir, *pattern;
	const gchar *old_path;
	glob_t globbuf;
	gint i, len;

	rspamd_lua_set_env (L, NULL, NULL, NULL);
	rspamd_lua_set_globals (rspamd_main->cfg, L);
	rspamd_lua_start_gc (rspamd_main->cfg);

	if (lua_test_case) {
		lua_pushstring (L, lua_test_case);
		lua_setglobal (L, "test_pattern");
	}

	rspamd_printf ("Starting lua tests\n");

	lua_src = g_build_filename (argv0_dirname, lua_src_name, NULL);
	if ((rp = realpath (lua_src, rp_buf)) == NULL) {
		msg_err ("cannot find path %s: %s",
				lua_src, strerror (errno));
		g_assert (0);
	}
	g_free (lua_src);

	tmp = g_strdup (rp);
	dir = dirname (tmp);
	/* Set lua path */
	lua_getglobal (L, "package");
	lua_getfield (L, -1, "path");
	old_path = luaL_checkstring (L, -1);

	rspamd_snprintf (path_buf, sizeof (path_buf), "%s;%s/?.lua;%s/unit/?.lua",
			old_path, dir, dir);
	lua_pop (L, 1);
	lua_pushstring (L, path_buf);
	lua_setfield (L, -2, "path");
	lua_pop (L, 1);

	lua_newtable (L);

	globbuf.gl_offs = 0;
	len = strlen (dir) + sizeof ("/unit/") + sizeof ("*.lua");
	pattern = g_malloc (len);
	rspamd_snprintf (pattern, len, "%s/unit/%s", dir, "*.lua");

	gint lua_test_len = 0;
	gint inserted_file = 1;
	gint path_start;
	if (lua_test) {
		lua_test_len = strlen (lua_test);
	}
	if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
		for (i = 0; i < (gint)globbuf.gl_pathc; i++) {
			if (lua_test) {
				path_start = strlen (globbuf.gl_pathv[i]) - lua_test_len;
				if (path_start < 0 ||
						strncmp (globbuf.gl_pathv[i] + path_start, lua_test, lua_test_len) != 0) {
					continue;
				}
			}

			lua_pushinteger (L, inserted_file);
			lua_pushstring (L, globbuf.gl_pathv[i]);
			lua_settable (L, -3);

			inserted_file ++;
		}
		globfree (&globbuf);
		g_free (pattern);
	}
	else {
		msg_err ("pattern %s doesn't match: %s", pattern,
				strerror (errno));
		g_assert (0);
	}

	lua_setglobal (L, "tests_list");
	rspamd_lua_set_path (L, NULL, NULL);

	lua_pushcfunction (L, traceback);
	luaL_loadfile (L, rp);

	if (lua_pcall (L, 0, 0, lua_gettop (L) - 1) != 0) {
		msg_err ("run test failed: %s", lua_tostring (L, -1));
		g_assert (0);
	}

	exit (EXIT_SUCCESS);
}
