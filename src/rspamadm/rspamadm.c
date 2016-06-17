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
#include "rspamd.h"
#include "ottery.h"
#include "lua/lua_common.h"
#include "lua_ucl.h"
#include "unix-std.h"

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

static gboolean verbose = FALSE;
static gboolean list_commands = FALSE;
static gboolean show_help = FALSE;
static gboolean show_version = FALSE;
GHashTable *ucl_vars = NULL;
struct rspamd_main *rspamd_main = NULL;

static void rspamadm_help (gint argc, gchar **argv);
static const char* rspamadm_help_help (gboolean full_help);

struct rspamadm_command help_command = {
	.name = "help",
	.flags = RSPAMADM_FLAG_NOHELP,
	.help = rspamadm_help_help,
	.run = rspamadm_help
};

static gboolean rspamadm_parse_ucl_var (const gchar *option_name,
		const gchar *value, gpointer data,
		GError **error);


static GOptionEntry entries[] = {
	{"verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
			"Enable verbose logging", NULL},
	{"list-commands", 'l', 0, G_OPTION_ARG_NONE, &list_commands,
			"List available commands", NULL},
	{"var", 0, 0, G_OPTION_ARG_CALLBACK, (gpointer)&rspamadm_parse_ucl_var,
			"Redefine UCL variable", NULL},
	{"help", 'h', 0, G_OPTION_ARG_NONE, &show_help,
			"Show help", NULL},
	{"version", 'v', 0, G_OPTION_ARG_NONE, &show_version,
			"Show version", NULL},
	{NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

GQuark
rspamadm_error (void)
{
	return g_quark_from_static_string ("rspamadm");
}

static void
rspamadm_version (void)
{
	printf ("Rspamadm %s\n", RVERSION);
}

static void
rspamadm_usage (GOptionContext *context)
{
	gchar *help_str;

	help_str = g_option_context_get_help (context, TRUE, NULL);
	printf ("%s", help_str);
}

static void
rspamadm_commands (void)
{
	const struct rspamadm_command **cmd;

	printf ("Rspamadm %s\n", RVERSION);
	printf ("Usage: rspamadm [global_options] command [command_options]\n");
	printf ("\nAvailable commands:\n");

	cmd = commands;

	while (*cmd) {
		if (!((*cmd)->flags & RSPAMADM_FLAG_NOHELP)) {
			printf ("  %-18s %-60s\n", (*cmd)->name, (*cmd)->help (FALSE));
		}
		cmd ++;
	}
}

static const char *
rspamadm_help_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Shows help for a specified command\n"
				"Usage: rspamadm help <command>";
	}
	else {
		help_str = "Shows help for a specified command";
	}

	return help_str;
}

static void
rspamadm_help (gint argc, gchar **argv)
{
	const gchar *cmd_name;
	const struct rspamadm_command *cmd, **cmd_list;

	printf ("Rspamadm %s\n", RVERSION);
	printf ("Usage: rspamadm [global_options] command [command_options]\n\n");

	if (argc <= 1) {
		cmd_name = "help";
	}
	else {
		cmd_name = argv[1];
		printf ("Showing help for %s command\n\n", cmd_name);
	}

	cmd = rspamadm_search_command (cmd_name);

	if (cmd == NULL) {
		fprintf (stderr, "Invalid command name: %s\n", cmd_name);
		exit (EXIT_FAILURE);
	}

	if (strcmp (cmd_name, "help") == 0) {
		printf ("Available commands:\n");

		cmd_list = commands;

		while (*cmd_list) {
			if (!((*cmd_list)->flags & RSPAMADM_FLAG_NOHELP)) {
				printf ("  %-18s %-60s\n", (*cmd_list)->name,
						(*cmd_list)->help (FALSE));
			}
			cmd_list++;
		}
	}
	else {
		printf ("%s\n", cmd->help (TRUE));
	}
}

static gboolean
rspamadm_parse_ucl_var (const gchar *option_name,
		const gchar *value, gpointer data,
		GError **error)
{
	gchar *k, *v, *t;

	t = strchr (value, '=');

	if (t != NULL) {
		k = g_strdup (value);
		t = k + (t - value);
		v = g_strdup (t + 1);
		*t = '\0';

		g_hash_table_insert (ucl_vars, k, v);
	}
	else {
		g_set_error (error, rspamadm_error (), EINVAL,
				"Bad variable format: %s", value);
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamadm_execute_lua_ucl_subr (gpointer pL, gint argc, gchar **argv,
		const ucl_object_t *res, const gchar *script)
{
	lua_State *L = pL;
	gint err_idx, cb_idx, i, ret;
	GString *tb;

	g_assert (script != NULL);
	g_assert (res != NULL);
	g_assert (L != NULL);

	if (luaL_dostring (L, script) != 0) {
		msg_err ("cannot execute lua script: %s",
				lua_tostring (L, -1));
		return FALSE;
	}
	else {
		if (lua_type (L, -1) == LUA_TFUNCTION) {
			cb_idx = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			msg_err ("lua script must return "
					"function and not %s",
					lua_typename (L,
							lua_type (L, -1)));
			return FALSE;
		}
	}

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	/* Push function */
	lua_rawgeti (L, LUA_REGISTRYINDEX, cb_idx);

	/* Push argv */
	lua_newtable (L);

	for (i = 0; i < argc; i ++) {
		lua_pushstring (L, argv[i]);
		lua_rawseti (L, -2, i + 1);
	}

	/* Push results */
	ucl_object_push_lua (L, res, TRUE);

	if ((ret = lua_pcall (L, 2, 0, err_idx)) != 0) {
		tb = lua_touserdata (L, -1);
		msg_err ("call to adm lua script failed (%d): %v", ret, tb);

		if (tb) {
			g_string_free (tb, TRUE);
		}

		lua_pop (L, 2);

		return FALSE;
	}

	/* error function */
	lua_pop (L, 1);

	luaL_unref (L, LUA_REGISTRYINDEX, cb_idx);

	return TRUE;
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	GError *error = NULL;
	GOptionContext *context;
	GOptionGroup *og;
	struct rspamd_config *cfg;
	GQuark process_quark;
	gchar **nargv, **targv;
	const gchar *cmd_name;
	const struct rspamadm_command *cmd;
	gint i, nargc, targc;

	ucl_vars = g_hash_table_new_full (rspamd_strcase_hash,
		rspamd_strcase_equal, g_free, g_free);
	process_quark = g_quark_from_static_string ("rspamadm");
	cfg = rspamd_config_new ();
	cfg->libs_ctx = rspamd_init_libs ();
	rspamd_main = g_malloc0 (sizeof (*rspamd_main));
	rspamd_main->cfg = cfg;
	rspamd_main->pid = getpid ();
	rspamd_main->type = process_quark;
	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"rspamadm");

	cfg->log_level = G_LOG_LEVEL_WARNING;

	cfg->log_type = RSPAMD_LOG_CONSOLE;
	rspamd_set_logger (cfg, process_quark, rspamd_main);
	(void) rspamd_log_open (rspamd_main->logger);
	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);
	g_set_printerr_handler (rspamd_glib_printerr_function);
	rspamd_config_post_load (cfg, FALSE);

	/* Setup logger */
	if (verbose) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		cfg->log_level = G_LOG_LEVEL_INFO;
	}

	gperf_profiler_init (cfg, "rspamadm");
	setproctitle ("rspamdadm");

	/* Now read options and store everything till the first non-dash argument */
	nargv = g_malloc0 (sizeof (gchar *) * (argc + 1));
	nargv[0] = g_strdup (argv[0]);

	for (i = 1, nargc = 1; i < argc; i ++) {
		if (argv[i] && argv[i][0] == '-') {
			/* Copy to nargv */
			nargv[nargc] = g_strdup (argv[i]);
			nargc ++;
		}
		else {
			break;
		}
	}

	context = g_option_context_new ("command - rspamd administration utility");
	og = g_option_group_new ("global", "global options", "global options",
			NULL, NULL);
	g_option_context_set_help_enabled (context, FALSE);
	g_option_group_add_entries (og, entries);
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_set_main_group (context, og);

	targv = nargv;
	targc = nargc;
	if (!g_option_context_parse (context, &targc, &targv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	g_strfreev (nargv);

	if (show_version) {
		rspamadm_version ();
		exit (EXIT_SUCCESS);
	}
	if (show_help) {
		rspamadm_usage (context);
		exit (EXIT_SUCCESS);
	}
	if (list_commands) {
		rspamadm_commands ();
		exit (EXIT_SUCCESS);
	}

	cmd_name = argv[nargc];

	if (cmd_name == NULL) {
		cmd_name = "help";
	}

	cmd = rspamadm_search_command (cmd_name);

	if (cmd == NULL) {
		fprintf (stderr, "Invalid command name: %s\n", cmd_name);
		exit (EXIT_FAILURE);
	}

	if (nargc < argc) {
		nargv = g_malloc0 (sizeof (gchar *) * (argc - nargc + 1));
		nargv[0] = g_strdup_printf ("%s %s", argv[0], cmd_name);

		for (i = 1; i < argc - nargc; i ++) {
			nargv[i] = g_strdup (argv[i + nargc]);
		}

		targc = argc - nargc;
		targv = nargv;
		cmd->run (targc, targv);
		g_strfreev (nargv);
	}
	else {
		cmd->run (0, NULL);
	}

	rspamd_log_close (rspamd_main->logger);
	REF_RELEASE (rspamd_main->cfg);
	g_free (rspamd_main);

	return 0;
}

