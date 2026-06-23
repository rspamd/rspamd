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
	NULL};


const struct rspamadm_command *
rspamadm_search_command(const char *name, GPtrArray *all_commands)
{
	const struct rspamadm_command *ret = NULL, *cmd;
	const char *alias;
	unsigned int i, j;

	if (name == NULL) {
		name = "help";
	}

	PTR_ARRAY_FOREACH(all_commands, i, cmd)
	{
		if (strcmp(name, cmd->name) == 0) {
			ret = cmd;
			break;
		}

		PTR_ARRAY_FOREACH(cmd->aliases, j, alias)
		{
			if (strcmp(name, alias) == 0) {
				ret = cmd;
				break;
			}
		}
	}

	return ret;
}

void rspamadm_fill_internal_commands(GPtrArray *dest)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(commands); i++) {
		if (commands[i]) {
			g_ptr_array_add(dest, (gpointer) commands[i]);
		}
	}
}

static void
lua_thread_str_error_cb(struct thread_entry *thread, int ret, const char *msg)
{
	msg_err("call to rspamadm lua script failed (%d): %s",
			ret, msg);
}

static void
rspamadm_lua_command_run(int argc, char **argv,
						 const struct rspamadm_command *cmd)
{
	struct thread_entry *thread = lua_thread_pool_get_for_config(rspamd_main->cfg);

	lua_State *L = thread->lua_state;

	int table_idx = GPOINTER_TO_INT(cmd->command_data);
	int i;

	/* Function */
	lua_rawgeti(L, LUA_REGISTRYINDEX, table_idx);
	lua_pushstring(L, "handler");
	lua_gettable(L, -2);

	/* Args */
	lua_createtable(L, argc + 1, 0);

	for (i = 0; i < argc; i++) {
		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, i); /* Starting from zero ! */
	}

	if (lua_repl_thread_call(thread, 1, (void *) cmd, lua_thread_str_error_cb) != 0) {
		exit(EXIT_FAILURE);
	}

	lua_settop(L, 0);
}

static const char *
rspamadm_lua_command_help(gboolean full_help,
						  const struct rspamadm_command *cmd)
{
	int table_idx = GPOINTER_TO_INT(cmd->command_data);

	if (full_help) {
		struct thread_entry *thread = lua_thread_pool_get_for_config(rspamd_main->cfg);

		lua_State *L = thread->lua_state;
		lua_rawgeti(L, LUA_REGISTRYINDEX, table_idx);
		/* Function */
		lua_pushstring(L, "handler");
		lua_gettable(L, -2);

		/* Args */
		lua_createtable(L, 2, 0);
		lua_pushstring(L, cmd->name);
		lua_rawseti(L, -2, 0); /* Starting from zero ! */

		lua_pushstring(L, "--help");
		lua_rawseti(L, -2, 1);

		if (lua_repl_thread_call(thread, 1, (void *) cmd, lua_thread_str_error_cb) != 0) {
			exit(EXIT_FAILURE);
		}

		lua_settop(L, 0);
	}
	else {
		lua_State *L = rspamd_main->cfg->lua_state;
		lua_rawgeti(L, LUA_REGISTRYINDEX, table_idx);
		lua_pushstring(L, "description");
		lua_gettable(L, -2);

		if (lua_isstring(L, -1)) {
			printf("  %-18s %-60s\n", cmd->name, lua_tostring(L, -1));
		}
		else {
			printf("  %-18s %-60s\n", cmd->name, "no description available");
		}

		lua_settop(L, 0);
	}

	return NULL; /* Must be handled in rspamadm itself */
}

/*
 * Load a single rspamadm command module from a .lua file and append it to dest.
 * Returns TRUE if a command has been registered.
 */
static gboolean
rspamadm_load_lua_command(lua_State *L, GPtrArray *dest, const char *path)
{
	struct rspamadm_command *lua_cmd;
	char *cmd_name;

	if (luaL_dofile(L, path) != 0) {
		msg_err("cannot execute lua script %s: %s",
				path, lua_tostring(L, -1));
		lua_settop(L, 0);

		return FALSE;
	}

	if (lua_type(L, -1) != LUA_TTABLE) {
		/* The script did not return a command table */
		lua_settop(L, 0);

		return FALSE;
	}

	/* The command must export a `handler` function */
	lua_pushstring(L, "handler");
	lua_gettable(L, -2);

	if (lua_type(L, -1) != LUA_TFUNCTION) {
		msg_err("rspamadm script %s does not have 'handler' field with type "
				"function",
				path);
		lua_settop(L, 0);

		return FALSE;
	}

	/* Pop handler */
	lua_pop(L, 1);

	/* Resolve the command name, falling back to the file basename */
	lua_pushstring(L, "name");
	lua_gettable(L, -2);

	if (lua_type(L, -1) == LUA_TSTRING) {
		cmd_name = g_strdup(lua_tostring(L, -1));
	}
	else {
		goffset ext_pos;

		cmd_name = g_path_get_basename(path);
		/* Remove .lua from the basename itself (not from the full path) */
		ext_pos = rspamd_substring_search(cmd_name, strlen(cmd_name), ".lua", 4);

		if (ext_pos != -1) {
			cmd_name[ext_pos] = '\0';
		}
	}

	lua_pop(L, 1);

	/*
	 * Skip duplicate command names: built-in commands and directories scanned
	 * earlier take precedence (PATH-like, first wins). This prevents a drop-in
	 * package from accidentally shadowing a built-in command.
	 */
	if (rspamadm_search_command(cmd_name, dest) != NULL) {
		msg_info("skip rspamadm command %s from %s: already defined",
				 cmd_name, path);
		g_free(cmd_name);
		lua_settop(L, 0);

		return FALSE;
	}

	lua_cmd = g_malloc0(sizeof(*lua_cmd));
	lua_cmd->name = cmd_name;

	lua_pushstring(L, "aliases");
	lua_gettable(L, -2);

	if (lua_type(L, -1) == LUA_TTABLE) {
		lua_cmd->aliases = g_ptr_array_new_full(
			rspamd_lua_table_size(L, -1),
			g_free);

		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			if (lua_isstring(L, -1)) {
				g_ptr_array_add(lua_cmd->aliases,
								g_strdup(lua_tostring(L, -1)));
			}
		}
	}

	lua_pop(L, 1);

	lua_pushvalue(L, -1);
	/* Reference table itself */
	lua_cmd->command_data = GINT_TO_POINTER(luaL_ref(L, LUA_REGISTRYINDEX));
	lua_cmd->flags |= RSPAMADM_FLAG_LUA | RSPAMADM_FLAG_DYNAMIC;
	lua_cmd->run = rspamadm_lua_command_run;
	lua_cmd->help = rspamadm_lua_command_help;

	g_ptr_array_add(dest, lua_cmd);

	lua_settop(L, 0);

	return TRUE;
}

/*
 * Glob `dir/ *.lua` and load every matching rspamadm command module. A missing
 * directory is not an error (glob simply yields nothing), so this is safe for
 * the optional drop-in / extra command paths.
 */
static void
rspamadm_scan_lua_commands_dir(lua_State *L, GPtrArray *dest, const char *dir)
{
	GPtrArray *lua_paths;
	GError *err = NULL;
	const char *path;
	unsigned int i;

	if ((lua_paths = rspamd_glob_path(dir, "*.lua", FALSE, &err)) == NULL) {
		msg_err("cannot glob files in %s/*.lua: %e", dir, err);
		g_error_free(err);

		return;
	}

	PTR_ARRAY_FOREACH(lua_paths, i, path)
	{
		rspamadm_load_lua_command(L, dest, path);
	}

	g_ptr_array_free(lua_paths, TRUE);
}

void rspamadm_fill_lua_commands(lua_State *L, GPtrArray *dest)
{
	const char *lualibdir = RSPAMD_LUALIBDIR, *confdir = RSPAMD_CONFDIR;
	const char *extra_path;
	char search_dir[PATH_MAX];

	if (g_hash_table_lookup(ucl_vars, "LUALIBDIR")) {
		lualibdir = g_hash_table_lookup(ucl_vars, "LUALIBDIR");
	}

	if (g_hash_table_lookup(ucl_vars, "CONFDIR")) {
		confdir = g_hash_table_lookup(ucl_vars, "CONFDIR");
	}

	/* Built-in commands shipped with the OSS lualib tree */
	rspamd_snprintf(search_dir, sizeof(search_dir), "%s%crspamadm",
					lualibdir, G_DIR_SEPARATOR);
	rspamadm_scan_lua_commands_dir(L, dest, search_dir);

	/*
	 * Drop-in commands from $CONFDIR/rspamadm.d, consistent with local.d /
	 * modules.local.d. An absent directory is fine.
	 */
	rspamd_snprintf(search_dir, sizeof(search_dir), "%s%crspamadm.d",
					confdir, G_DIR_SEPARATOR);
	rspamadm_scan_lua_commands_dir(L, dest, search_dir);

	/*
	 * Additional command directories from a colon-separated
	 * RSPAMADM_COMMAND_PATH (mirrors how PATH works). Lets third-party /
	 * premium packages ship rspamadm commands without writing into the OSS
	 * lualib tree. Modules load with the same globals and lua_path as the
	 * built-in ones, so they can require premium lualibs and use lua_redis.
	 */
	extra_path = g_getenv("RSPAMADM_COMMAND_PATH");

	if (extra_path != NULL) {
		char **dirs = g_strsplit(extra_path, ":", -1);

		for (char **d = dirs; d != NULL && *d != NULL; d++) {
			if (**d != '\0') {
				rspamadm_scan_lua_commands_dir(L, dest, *d);
			}
		}

		g_strfreev(dirs);
	}
}
