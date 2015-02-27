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

static const char *lua_src = "./lua";

void
rspamd_lua_test_func (int argc, char **argv)
{
	lua_State *L = rspamd_lua_init (NULL);
	gchar rp[PATH_MAX], path_buf[PATH_MAX];
	const gchar *old_path;
	guint i;

	msg_info ("Starting lua tests");

	if (realpath (lua_src, rp) == NULL) {
		msg_err ("cannod find path %s: %s", lua_src, strerror (errno));
		g_assert (0);
	}

	/* Set lua path */
	lua_getglobal (L, "package");
	lua_getfield (L, -1, "path");
	old_path = luaL_checkstring (L, -1);

	rspamd_snprintf (path_buf, sizeof (path_buf), "%s;%s/?.lua;%s/busted/?.lua",
			old_path, rp, rp);
	lua_pop (L, 1);
	lua_pushstring (L, path_buf);
	lua_setfield (L, -2, "path");
	lua_pop (L, 1);

	lua_getglobal (L, "arg");

	if (lua_type (L, -1) != LUA_TTABLE) {
		lua_newtable (L);
	}

	for (i = 0; i < argc - 1; i ++) {
		lua_pushinteger (L, i + 1);
		lua_pushstring (L, argv[i]);
		lua_settable (L, -3);
	}

	lua_setglobal (L, "arg");
	lua_pop (L, 1);

	rspamd_snprintf (path_buf, sizeof (path_buf),
			"require 'busted.runner'({ batch = true })");
	if (luaL_dostring (L, path_buf) != 0) {
		rspamd_fprintf (stderr, "run test failed: %s", lua_tostring (L, -1));
		g_assert (0);
	}

	exit (EXIT_SUCCESS);
}
