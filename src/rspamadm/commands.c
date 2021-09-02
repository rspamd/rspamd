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
#include "rspamadm.h"
#include "libutil/util.h"
#include "libserver/logger.h"
#include "lua/lua_common.h"
#include "lua/lua_thread_pool.h"

extern struct rspamadm_command pw_command;
extern struct rspamadm_command configtest_command;
extern struct rspamadm_command configdump_command;
extern struct rspamadm_command control_command;
extern struct rspamadm_command confighelp_command;
extern struct rspamadm_command statconvert_command;
extern struct rspamadm_command fuzzyconvert_command;
extern struct rspamadm_command signtool_command;
extern struct rspamadm_command lua_command;
extern struct rspamadm_command dkim_keygen_command;

const struct rspamadm_command *commands[] = {
	&help_command,
	&pw_command,
	&configtest_command,
	&configdump_command,
	&control_command,
	&confighelp_command,
	&statconvert_command,
	&fuzzyconvert_command,
	&signtool_command,
	&lua_command,
	&dkim_keygen_command,
	NULL
};


const struct rspamadm_command *
rspamadm_search_command (const gchar *name, GPtrArray *all_commands)
{
	const struct rspamadm_command *ret = NULL, *cmd;
	const gchar *alias;
	guint i, j;

	if (name == NULL) {
		name = "help";
	}

	PTR_ARRAY_FOREACH (all_commands, i, cmd) {
			if (strcmp (name, cmd->name) == 0) {
				ret = cmd;
				break;
			}

		PTR_ARRAY_FOREACH (cmd->aliases, j, alias) {
			if (strcmp (name, alias) == 0) {
				ret = cmd;
				break;
			}
		}
	}

	return ret;
}

void
rspamadm_fill_internal_commands (GPtrArray *dest)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		if (commands[i]) {
			g_ptr_array_add (dest, (gpointer)commands[i]);
		}
	}
}

static void
lua_thread_str_error_cb (struct thread_entry *thread, int ret, const char *msg)
{
	msg_err ("call to rspamadm lua script failed (%d): %s",
			ret, msg);
}

static void
rspamadm_lua_command_run (gint argc, gchar **argv,
						  const struct rspamadm_command *cmd)
{
	struct thread_entry *thread = lua_thread_pool_get_for_config (rspamd_main->cfg);

	lua_State *L = thread->lua_state;

	gint table_idx = GPOINTER_TO_INT (cmd->command_data);
	gint i;

	/* Function */
	lua_rawgeti (L, LUA_REGISTRYINDEX, table_idx);
	lua_pushstring (L, "handler");
	lua_gettable (L, -2);

	/* Args */
	lua_createtable (L, argc + 1, 0);

	for (i = 0; i < argc; i ++) {
		lua_pushstring (L, argv[i]);
		lua_rawseti (L, -2, i); /* Starting from zero ! */
	}

	if (lua_repl_thread_call (thread, 1, (void *)cmd, lua_thread_str_error_cb) != 0) {
		exit (EXIT_FAILURE);
	}

	lua_settop (L, 0);
}

static const gchar *
rspamadm_lua_command_help (gboolean full_help,
						  const struct rspamadm_command *cmd)
{
	gint table_idx = GPOINTER_TO_INT (cmd->command_data);

	if (full_help) {
		struct thread_entry *thread = lua_thread_pool_get_for_config (rspamd_main->cfg);

		lua_State *L = thread->lua_state;
		lua_rawgeti (L, LUA_REGISTRYINDEX, table_idx);
		/* Function */
		lua_pushstring (L, "handler");
		lua_gettable (L, -2);

		/* Args */
		lua_createtable (L, 2, 0);
		lua_pushstring (L, cmd->name);
		lua_rawseti (L, -2, 0); /* Starting from zero ! */

		lua_pushstring (L, "--help");
		lua_rawseti (L, -2, 1);

		if (lua_repl_thread_call (thread, 1, (void *)cmd, lua_thread_str_error_cb) != 0) {
			exit (EXIT_FAILURE);
		}

		lua_settop (L, 0);
	}
	else {
		lua_State *L = rspamd_main->cfg->lua_state;
		lua_rawgeti (L, LUA_REGISTRYINDEX, table_idx);
		lua_pushstring (L, "description");
		lua_gettable (L, -2);

		if (lua_isstring (L, -1)) {
			printf ("  %-18s %-60s\n", cmd->name, lua_tostring (L, -1));
		}
		else {
			printf ("  %-18s %-60s\n", cmd->name, "no description available");
		}

		lua_settop (L, 0);
	}

	return NULL; /* Must be handled in rspamadm itself */
}

void
rspamadm_fill_lua_commands (lua_State *L, GPtrArray *dest)
{
	gint i;

	GPtrArray *lua_paths;
	GError *err = NULL;
	const gchar *lualibdir = RSPAMD_LUALIBDIR, *path;
	struct rspamadm_command *lua_cmd;
	gchar search_dir[PATH_MAX];

	if (g_hash_table_lookup (ucl_vars, "LUALIBDIR")) {
		lualibdir = g_hash_table_lookup (ucl_vars, "LUALIBDIR");
	}

	rspamd_snprintf (search_dir, sizeof (search_dir), "%s%crspamadm%c",
			lualibdir, G_DIR_SEPARATOR, G_DIR_SEPARATOR);

	if ((lua_paths = rspamd_glob_path (search_dir, "*.lua", FALSE, &err)) == NULL) {
		msg_err ("cannot glob files in %s/*.lua: %e", search_dir, err);
		g_error_free (err);

		return;
	}

	PTR_ARRAY_FOREACH (lua_paths, i, path) {
		if (luaL_dofile (L, path) != 0) {
			msg_err ("cannot execute lua script %s: %s",
					path, lua_tostring (L, -1));
			lua_settop (L, 0);
			continue;
		} else {
			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_pushstring (L, "handler");
				lua_gettable (L, -2);
			}
			else {
				continue; /* Something goes wrong, huh */
			}

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				msg_err ("rspamadm script %s does not have 'handler' field with type "
						 "function",
						path);
				continue;
			}

			/* Pop handler */
			lua_pop (L, 1);
			lua_cmd = g_malloc0 (sizeof (*lua_cmd));

			lua_pushstring (L, "name");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TSTRING) {
				lua_cmd->name = g_strdup (lua_tostring (L, -1));
			}
			else {
				goffset ext_pos;
				gchar *name;

				name = g_path_get_basename (path);
				/* Remove .lua */
				ext_pos = rspamd_substring_search (path, strlen (path), ".lua", 4);

				if (ext_pos != -1) {
					name[ext_pos] = '\0';
				}

				lua_cmd->name = name;
			}

			lua_pop (L, 1);

			lua_pushstring (L, "aliases");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_cmd->aliases = g_ptr_array_new_full (
						rspamd_lua_table_size (L, -1),
						g_free);

				for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
					if (lua_isstring (L, -1)) {
						g_ptr_array_add (lua_cmd->aliases,
								g_strdup (lua_tostring (L, -1)));
					}
				}
			}

			lua_pop (L, 1);

			lua_pushvalue (L, -1);
			/* Reference table itself */
			lua_cmd->command_data = GINT_TO_POINTER (luaL_ref (L, LUA_REGISTRYINDEX));
			lua_cmd->flags |= RSPAMADM_FLAG_LUA|RSPAMADM_FLAG_DYNAMIC;
			lua_cmd->run = rspamadm_lua_command_run;
			lua_cmd->help = rspamadm_lua_command_help;

			g_ptr_array_add (dest, lua_cmd);
		}

		lua_settop (L, 0);
	}

	g_ptr_array_free (lua_paths, TRUE);
}
