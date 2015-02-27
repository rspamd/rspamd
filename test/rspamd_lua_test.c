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
rspamd_lua_test_func (void)
{
	lua_State *L = rspamd_lua_init (NULL);
	gchar *lua_file;
	gchar rp[PATH_MAX];
	glob_t globbuf;
	gchar *pattern;
	guint i, len;
	struct stat st;

	msg_info ("Starting lua tests");

	if (realpath (lua_src, rp) == NULL) {
		msg_err ("cannod find path %s: %s", lua_src, strerror (errno));
		g_assert (0);
	}

	globbuf.gl_offs = 0;
	len = strlen (rp) + sizeof ("*.lua") + 1;
	pattern = g_malloc (len);
	rspamd_snprintf (pattern, len, "%s/%s", rp, "*.lua");

	if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
		for (i = 0; i < globbuf.gl_pathc; i++) {
			lua_file = globbuf.gl_pathv[i];

			if (stat (lua_file, &st) == -1 || !S_ISREG (st.st_mode)) {
				continue;
			}

			if (strstr (lua_file, "busted") != NULL) {
				/* Skip busted code itself */
				continue;
			}

			if (luaL_loadfile (L, lua_file) != 0) {
				msg_err ("load test from %s failed", lua_file);
				g_assert (0);
			}
			/* Now do it */
			if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
				msg_err ("run test from %s failed: %s", lua_file,
						lua_tostring (L, -1));
				g_assert (0);
			}
		}
		globfree (&globbuf);
		g_free (pattern);
	}
	else {
		msg_err ("glob for %s failed: %s", pattern, strerror (errno));
		g_assert (0);
	}
}
