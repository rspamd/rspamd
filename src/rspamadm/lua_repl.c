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
#include "rspamadm.h"
#include "cryptobox.h"
#include "printf.h"
#include "lua/lua_common.h"
#include "message.h"
#include "task.h"
#include "unix-std.h"
#include "linenoise.h"
#ifdef WITH_LUAJIT
#include <luajit.h>
#endif

static gchar **paths = NULL;
static gchar **scripts = NULL;
static gchar *histfile = NULL;
static guint max_history = 2000;

static const char *default_history_file = ".rspamd_repl.hist";

#ifdef WITH_LUAJIT
#define MAIN_PROMPT LUAJIT_VERSION "> "
#else
#define MAIN_PROMPT LUA_VERSION "> "
#endif
#define MULTILINE_PROMPT "... "

static void rspamadm_lua (gint argc, gchar **argv);
static const char *rspamadm_lua_help (gboolean full_help);

struct rspamadm_command lua_command = {
		.name = "lua",
		.flags = 0,
		.help = rspamadm_lua_help,
		.run = rspamadm_lua
};

/*
 * Dot commands
 */
typedef void (*rspamadm_lua_dot_handler)(lua_State *L, gint argc, gchar **argv);
struct rspamadm_lua_dot_command {
	const gchar *name;
	const gchar *description;
	rspamadm_lua_dot_handler handler;
};

static void rspamadm_lua_help_handler (lua_State *L, gint argc, gchar **argv);
static void rspamadm_lua_load_handler (lua_State *L, gint argc, gchar **argv);
static void rspamadm_lua_message_handler (lua_State *L, gint argc, gchar **argv);

static struct rspamadm_lua_dot_command cmds[] = {
	{
		.name = "help",
		.description = "shows help for commands",
		.handler = rspamadm_lua_help_handler
	},
	{
		.name = "load",
		.description = "load lua file",
		.handler = rspamadm_lua_load_handler
	},
	{
		.name = "message",
		.description = "scans message using specified callback: .message <callback_name> <file>...",
		.handler = rspamadm_lua_message_handler
	},
};

static GHashTable *cmds_hash = NULL;

static GOptionEntry entries[] = {
		{"script", 's', 0, G_OPTION_ARG_STRING_ARRAY, &scripts,
				"Load specified scripts", NULL},
		{"path", 'p', 0, G_OPTION_ARG_STRING_ARRAY, &paths,
				"Add specified paths to lua paths", NULL},
		{"history-file", 'H', 0, G_OPTION_ARG_FILENAME, &histfile,
				"Load history from the specified file", NULL},
		{"max-history", 'm', 0, G_OPTION_ARG_INT, &max_history,
				"Store this number of history entries", NULL},
		{NULL,       0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_lua_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Run lua read/execute/print loop\n\n"
				"Usage: rspamadm lua [-p paths] [-s scripts]\n"
				"Where options are:\n\n"
				"-p: add additional lua paths (may be repeated)\n"
				"-s: load scripts on start from specified files (may be repeated)\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Run LUA interpreter";
	}

	return help_str;
}

static void
rspamadm_lua_add_path (lua_State *L, const gchar *path)
{
	const gchar *old_path;
	gsize len;
	GString *new_path;

	lua_getglobal (L, "package");
	lua_getfield (L, -1, "path");
	old_path = luaL_checklstring (L, -1, &len);

	new_path = g_string_sized_new (len + strlen (path) + sizeof("/?.lua"));

	if (strstr (path, "?.lua") == NULL) {
		rspamd_printf_gstring (new_path, "%s/?.lua;%s", path, old_path);
	}
	else {
		rspamd_printf_gstring (new_path, "%s;%s", path, old_path);
	}

	lua_pushlstring (L, new_path->str, new_path->len);
	lua_setfield (L, -2, "path");
	lua_settop (L, 0);
	g_string_free (new_path, TRUE);
}

static gboolean
rspamadm_lua_load_script (lua_State *L, const gchar *path)
{
	GString *tb;
	gint err_idx;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	if (luaL_loadfile (L, path) != 0) {
		rspamd_fprintf (stderr, "cannot load script %s: %s\n",
				path, strerror (errno));
		lua_settop (L, 0);

		return FALSE;
	}

	if (lua_pcall (L, 0, 0, err_idx) != 0) {
		tb = lua_touserdata (L, -1);
		rspamd_fprintf (stderr, "call to %s failed: %v", path, tb);
		g_string_free (tb, TRUE);
		lua_settop (L, 0);

		return FALSE;
	}

	lua_settop (L, 0);

	return TRUE;
}

static void
rspamadm_exec_input (lua_State *L, const gchar *input)
{
	GString *tb;
	gint err_idx, i, cbref;
	gchar outbuf[8192];

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	/* First try return + input */
	tb = g_string_sized_new (strlen (input) + sizeof ("return "));
	rspamd_printf_gstring (tb, "return %s", input);

	if (luaL_loadstring (L, tb->str) != 0) {
		/* Reset stack */
		lua_settop (L, 0);
		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);
		/* Try with no return */
		if (luaL_loadstring (L, input) != 0) {
			rspamd_fprintf (stderr, "cannot load string %s\n",
					input);
			g_string_free (tb, TRUE);
			lua_settop (L, 0);
			return;
		}
	}

	g_string_free (tb, TRUE);

	if (lua_pcall (L, 0, LUA_MULTRET, err_idx) != 0) {
		tb = lua_touserdata (L, -1);
		rspamd_fprintf (stderr, "call failed: %v", tb);
		g_string_free (tb, TRUE);
		lua_settop (L, 0);
		return;
	}

	/* Print output */
	for (i = err_idx + 1; i <= lua_gettop (L); i ++) {
		if (lua_isfunction (L, i)) {
			lua_pushvalue (L, i);
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);

			rspamd_printf ("local function: %d\n", cbref);
		}
		else {
			lua_logger_out_type (L, i, outbuf, sizeof (outbuf));
			rspamd_printf ("%s\n", outbuf);
		}
	}

	lua_settop (L, 0);
}

static void
rspamadm_lua_help_handler (lua_State *L, gint argc, gchar **argv)
{
	guint i;
	struct rspamadm_lua_dot_command *cmd;

	if (argv[1] == NULL) {
		/* Print all commands */
		for (i = 0; i < G_N_ELEMENTS (cmds); i ++) {
			rspamd_printf ("%s: %s\n", cmds[i].name, cmds[i].description);
		}
	}
	else {
		for (i = 1; argv[i] != NULL; i ++) {
			cmd = g_hash_table_lookup (cmds_hash, argv[i]);

			if (cmd) {
				rspamd_printf ("%s: %s\n", cmds->name, cmds->description);
			}
			else {
				rspamd_printf ("%s: no such command\n", argv[i]);
			}
		}
	}
}

static void
rspamadm_lua_load_handler (lua_State *L, gint argc, gchar **argv)
{
	guint i;
	gboolean ret;

	for (i = 1; argv[i] != NULL; i ++) {
		ret = rspamadm_lua_load_script (L, argv[i]);
		rspamd_printf ("%s: %sloaded\n", argv[i], ret ? "" : "NOT ");
	}
}

static void
rspamadm_lua_message_handler (lua_State *L, gint argc, gchar **argv)
{
	gulong cbref;
	gint err_idx, func_idx, i, j;
	struct rspamd_task *task, **ptask;
	gpointer map;
	gsize len;
	GString *tb;
	gchar outbuf[8192];

	if (argv[1] == NULL) {
		rspamd_printf ("no callback is specified\n");
		return;
	}

	if (rspamd_strtoul (argv[1], strlen (argv[1]), &cbref)) {
		lua_rawgeti (L, LUA_REGISTRYINDEX, cbref);
	}
	else {
		lua_getglobal (L, argv[1]);
	}

	if (lua_type (L, -1) != LUA_TFUNCTION) {
		rspamd_printf ("bad callback type: %s\n", lua_typename (L, lua_type (L, -1)));
		return;
	}

	/* Save index to reuse */
	func_idx = lua_gettop (L);

	for (i = 2; argv[i] != NULL; i ++) {
		map = rspamd_file_xmap (argv[i], PROT_READ, &len);

		if (map == NULL) {
			rspamd_printf ("cannot open %s: %s\n", argv[i], strerror (errno));
		}
		else {
			task = rspamd_task_new (NULL, NULL);

			if (!rspamd_task_load_message (task, NULL, map, len)) {
				rspamd_printf ("cannot load %s\n", argv[i]);
				rspamd_task_free (task);
				munmap (map, len);
				continue;
			}

			if (!rspamd_message_parse (task)) {
				rspamd_printf ("cannot parse %s: %e\n", argv[i], task->err);
				rspamd_task_free (task);
				munmap (map, len);
				continue;
			}

			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			lua_pushvalue (L, func_idx);
			ptask = lua_newuserdata (L, sizeof (*ptask));
			*ptask = task;
			rspamd_lua_setclass (L, "rspamd{task}", -1);

			if (lua_pcall (L, 1, LUA_MULTRET, err_idx) != 0) {
				tb = lua_touserdata (L, -1);
				rspamd_printf ("lua callback for %s failed: %v\n", argv[i], tb);
				g_string_free (tb, TRUE);
			}
			else {
				rspamd_printf ("lua callback for %s returned:\n", argv[i]);

				for (j = err_idx + 1; j <= lua_gettop (L); j ++) {
					lua_logger_out_type (L, j, outbuf, sizeof (outbuf));
					rspamd_printf ("%s\n", outbuf);
				}
			}

			rspamd_task_free (task);
			munmap (map, len);
			/* Pop all but the original function */
			lua_settop (L, func_idx);
		}
	}

	lua_settop (L, 0);
}


static gboolean
rspamadm_lua_try_dot_command (lua_State *L, const gchar *input)
{
	struct rspamadm_lua_dot_command *cmd;
	gchar **argv;

	argv = g_strsplit_set (input + 1, " ", -1);

	if (argv == NULL || argv[0] == NULL) {
		if (argv) {
			g_strfreev (argv);
		}

		return FALSE;
	}

	cmd = g_hash_table_lookup (cmds_hash, argv[0]);

	if (cmd) {
		cmd->handler (L, g_strv_length (argv), argv);
		g_strfreev (argv);

		return TRUE;
	}

	g_strfreev (argv);

	return FALSE;
}

static void
rspamadm_lua_run_repl (lua_State *L)
{
	gchar *input;
	gboolean is_multiline = FALSE;
	GString *tb;

	for (;;) {
		if (!is_multiline) {
			input = linenoise (MAIN_PROMPT);

			if (input == NULL) {
				return;
			}

			if (input[0] == '.') {
				if (rspamadm_lua_try_dot_command (L, input)) {
					linenoiseHistoryAdd (input);
					linenoiseFree (input);
					continue;
				}
			}

			if (strcmp (input, "{{") == 0) {
				is_multiline = TRUE;
				linenoiseFree (input);
				tb = g_string_sized_new (8192);
				continue;
			}

			rspamadm_exec_input (L, input);
			linenoiseHistoryAdd (input);
			linenoiseFree (input);
			lua_settop (L, 0);
		}
		else {
			input = linenoise (MULTILINE_PROMPT);

			if (input == NULL) {
				g_string_free (tb, TRUE);
				return;
			}

			if (strcmp (input, "}}") == 0) {
				is_multiline = FALSE;
				linenoiseFree (input);
				rspamadm_exec_input (L, tb->str);
				g_string_free (tb, TRUE);
			}
			else {
				g_string_append (tb, input);
				g_string_append (tb, "\n");
				linenoiseFree (input);
			}
		}
	}
}

static void
rspamadm_lua (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	gchar **elt;
	guint i;
	lua_State *L;

	context = g_option_context_new ("lua - run lua interpreter");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	L = rspamd_lua_init ();
	rspamd_lua_set_path (L, NULL);

	if (paths) {
		for (elt = paths; *elt != NULL; elt ++) {
			rspamadm_lua_add_path (L, *elt);
		}
	}

	if (scripts) {
		for (elt = scripts; *elt != NULL; elt ++) {
			if (!rspamadm_lua_load_script (L, *elt)) {
				exit (EXIT_FAILURE);
			}
		}
	}

	if (histfile == NULL) {
		const gchar *homedir;
		GString *hist_path;

		homedir = getenv ("HOME");

		if (homedir) {
			hist_path = g_string_sized_new (strlen (homedir) +
					strlen (default_history_file) + 1);
			rspamd_printf_gstring (hist_path, "%s/%s", homedir,
					default_history_file);
		}
		else {
			hist_path = g_string_sized_new (strlen (default_history_file) + 2);
			rspamd_printf_gstring (hist_path, "./%s", default_history_file);
		}

		histfile = hist_path->str;
		g_string_free (hist_path, FALSE);
	}

	/* Init dot commands */
	cmds_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	for (i = 0; i < G_N_ELEMENTS (cmds); i ++) {
		g_hash_table_insert (cmds_hash, (gpointer)cmds[i].name, &cmds[i]);
	}

	linenoiseHistorySetMaxLen (max_history);
	linenoiseHistoryLoad (histfile);
	rspamadm_lua_run_repl (L);
	linenoiseHistorySave (histfile);
}
