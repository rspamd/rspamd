/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "main.h"
#include "util.h"
#include "lua/lua_common.h"

static const char *lua_src = BUILDROOT "/test/lua/tests.lua";

static int
traceback (lua_State *L)
{
	if (!lua_isstring (L, 1)) {
		return 1;
	}

	lua_getfield (L, LUA_GLOBALSINDEX, "debug");

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
	lua_State *L = rspamd_lua_init (NULL);
	gchar *rp, rp_buf[PATH_MAX], path_buf[PATH_MAX], *tmp, *dir, *pattern;
	const gchar *old_path;
	glob_t globbuf;
	gint i, len;

	rspamd_printf ("Starting lua tests\n");

	if ((rp = realpath (lua_src, rp_buf)) == NULL) {
		msg_err ("cannot find path %s: %s",
				lua_src, strerror (errno));
		g_assert (0);
	}

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

	if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
		for (i = 0; i < (gint)globbuf.gl_pathc; i++) {
			lua_pushinteger (L, i + 1);
			lua_pushstring (L, globbuf.gl_pathv[i]);
			lua_settable (L, -3);
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

	lua_pushcfunction (L, traceback);
	luaL_loadfile (L, rp);

	if (lua_pcall (L, 0, 0, lua_gettop (L) - 1) != 0) {
		msg_err ("run test failed: %s", lua_tostring (L, -1));
		g_assert (0);
	}

	exit (EXIT_SUCCESS);
}
