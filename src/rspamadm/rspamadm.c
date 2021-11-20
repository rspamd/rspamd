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
#include "lua/lua_thread_pool.h"
#include "lua_ucl.h"
#include "unix-std.h"
#include "contrib/libev/ev.h"

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

static gboolean verbose = FALSE;
static gboolean list_commands = FALSE;
static gboolean show_help = FALSE;
static gboolean show_version = FALSE;
GHashTable *ucl_vars = NULL;
gchar **lua_env = NULL;
struct rspamd_main *rspamd_main = NULL;
struct rspamd_async_session *rspamadm_session = NULL;
lua_State *L = NULL;

/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

static void rspamadm_help (gint argc, gchar **argv, const struct rspamadm_command *);
static const char* rspamadm_help_help (gboolean full_help, const struct rspamadm_command *);

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
			"Redefine/define environment variable", NULL},
	{"help", 'h', 0, G_OPTION_ARG_NONE, &show_help,
			"Show help", NULL},
	{"version", 'V', 0, G_OPTION_ARG_NONE, &show_version,
			"Show version", NULL},
	{"lua-env", '\0', 0, G_OPTION_ARG_FILENAME_ARRAY, &lua_env,
			"Load lua environment from the specified files", NULL},
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
	rspamd_printf ("Rspamadm %s\n", RVERSION);
}

static void
rspamadm_usage (GOptionContext *context)
{
	gchar *help_str;

	help_str = g_option_context_get_help (context, TRUE, NULL);
	rspamd_printf ("%s", help_str);
}

static void
rspamadm_commands (GPtrArray *all_commands)
{
	const struct rspamadm_command *cmd;
	guint i;

	rspamd_printf ("Rspamadm %s\n", RVERSION);
	rspamd_printf ("Usage: rspamadm [global_options] command [command_options]\n");
	rspamd_printf ("\nAvailable commands:\n");

	PTR_ARRAY_FOREACH (all_commands, i, cmd) {
		if (!(cmd->flags & RSPAMADM_FLAG_NOHELP)) {
			if (cmd->flags & RSPAMADM_FLAG_LUA) {
				(void)cmd->help (FALSE, cmd);
			}
			else {
				printf ("  %-18s %-60s\n", cmd->name, cmd->help (FALSE, cmd));
			}
		}
	}
}

static const char *
rspamadm_help_help (gboolean full_help, const struct rspamadm_command *cmd)
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
rspamadm_help (gint argc, gchar **argv, const struct rspamadm_command *command)
{
	const gchar *cmd_name;
	const struct rspamadm_command *cmd;
	GPtrArray *all_commands = (GPtrArray *)command->command_data;

	rspamd_printf ("Rspamadm %s\n", RVERSION);
	rspamd_printf ("Usage: rspamadm [global_options] command [command_options]\n\n");

	if (argc <= 1) {
		cmd_name = "help";
	}
	else {
		cmd_name = argv[1];
		rspamd_printf ("Showing help for %s command\n\n", cmd_name);
	}

	cmd = rspamadm_search_command (cmd_name, all_commands);

	if (cmd == NULL) {
		fprintf (stderr, "Invalid command name: %s\n", cmd_name);
		exit (EXIT_FAILURE);
	}

	if (strcmp (cmd_name, "help") == 0) {
		guint i;
		rspamd_printf ("Available commands:\n");

		PTR_ARRAY_FOREACH (all_commands, i, cmd) {
			if (!(cmd->flags & RSPAMADM_FLAG_NOHELP)) {
				if (!(cmd->flags & RSPAMADM_FLAG_LUA)) {
					printf ("  %-18s %-60s\n", cmd->name,
							cmd->help (FALSE, cmd));
				}
				else {
					/* Just call lua subr */
					(void)cmd->help (FALSE, cmd);
				}
			}
		}
	}
	else {
		if (!(cmd->flags & RSPAMADM_FLAG_LUA)) {
			rspamd_printf ("%s\n", cmd->help (TRUE, cmd));
		}
		else {
			/* Just call lua subr */
			(void)cmd->help (TRUE, cmd);
		}
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

static void
lua_thread_str_error_cb (struct thread_entry *thread, int ret, const char *msg)
{
	struct lua_call_data *cd = thread->cd;

	msg_err ("call to rspamadm lua script failed (%d): %s", ret, msg);

	cd->ret = ret;
}

gboolean
rspamadm_execute_lua_ucl_subr (gint argc, gchar **argv,
							   const ucl_object_t *res,
							   const gchar *script_name,
							   gboolean rspamadm_subcommand)
{
	struct thread_entry *thread = lua_thread_pool_get_for_config (rspamd_main->cfg);

	lua_State *L = thread->lua_state;

	gint i;
	gchar str[PATH_MAX];

	g_assert (script_name != NULL);
	g_assert (res != NULL);
	g_assert (L != NULL);

	/* Init internal rspamadm routines */

	if (rspamadm_subcommand) {
		rspamd_snprintf (str, sizeof (str), "return require \"%s.%s\"", "rspamadm",
				script_name);
	}
	else {
		rspamd_snprintf (str, sizeof (str), "return require \"%s\"",
				script_name);
	}

	if (luaL_dostring (L, str) != 0) {
		msg_err ("cannot execute lua script %s: %s",
				str, lua_tostring (L, -1));
		return FALSE;
	}
	else {
		if (lua_type (L, -1) == LUA_TTABLE) {
			lua_pushstring (L, "handler");
			lua_gettable (L, -2);
		}

		if (lua_type (L, -1) != LUA_TFUNCTION) {
			msg_err ("lua script must return "
					"function and not %s",
					lua_typename (L, lua_type (L, -1)));

			return FALSE;
		}
	}

	/* Push function */
	lua_pushvalue (L, -1);

	/* Push argv */
	lua_newtable (L);

	for (i = 1; i < argc; i ++) {
		lua_pushstring (L, argv[i]);
		lua_rawseti (L, -2, i);
	}

	/* Push results */
	ucl_object_push_lua (L, res, TRUE);

	if (lua_repl_thread_call (thread, 2, NULL, lua_thread_str_error_cb) != 0) {

		return FALSE;
	}

	/* error function */
	lua_settop (L, 0);

	return TRUE;
}

static gint
rspamdadm_commands_sort_func (gconstpointer a, gconstpointer b)
{
	const struct rspamadm_command *cmda = *((struct rspamadm_command const **)a),
			*cmdb = *((struct rspamadm_command const **)b);

	return strcmp (cmda->name, cmdb->name);
}

static gboolean
rspamadm_command_maybe_match_name (const gchar *cmd, const gchar *input)
{
	gsize clen, inplen;

	clen = strlen (cmd);
	inplen = strlen (input);

	if (rspamd_strings_levenshtein_distance (cmd, clen,
			input, inplen, 1) == 1) {
		return TRUE;
	}
	else if ((clen > inplen &&
			  rspamd_substring_search (cmd, clen, input, inplen) != -1) ||
			 (inplen > clen &&
			  rspamd_substring_search (input, inplen, cmd, clen) != -1)) {
		return TRUE;
	}

	return FALSE;
}



static void
rspamadm_add_lua_globals (struct rspamd_dns_resolver *resolver)
{
	struct rspamd_async_session  **psession;
	struct ev_loop **pev_base;
	struct rspamd_dns_resolver **presolver;

	rspamadm_session = rspamd_session_create (rspamd_main->cfg->cfg_pool, NULL,
			NULL, (event_finalizer_t )NULL, NULL);

	psession = lua_newuserdata (L, sizeof (struct rspamd_async_session*));
	rspamd_lua_setclass (L, "rspamd{session}", -1);
	*psession = rspamadm_session;
	lua_setglobal (L, "rspamadm_session");

	pev_base = lua_newuserdata (L, sizeof (struct ev_loop *));
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	*pev_base = rspamd_main->event_loop;
	lua_setglobal (L, "rspamadm_ev_base");

	presolver = lua_newuserdata (L, sizeof (struct rspamd_dns_resolver *));
	rspamd_lua_setclass (L, "rspamd{resolver}", -1);
	*presolver = resolver;
	lua_setglobal (L, "rspamadm_dns_resolver");
}

static void
rspamadm_cmd_dtor (gpointer p)
{
	struct rspamadm_command *cmd = (struct rspamadm_command *)p;

	if (cmd->flags & RSPAMADM_FLAG_DYNAMIC) {
		if (cmd->aliases) {
			g_ptr_array_free (cmd->aliases, TRUE);
		}

		g_free ((gpointer)cmd->name);
		g_free (cmd);
	}
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
	struct rspamd_dns_resolver *resolver;
	GPtrArray *all_commands = g_ptr_array_new_full (32,
			rspamadm_cmd_dtor); /* Discovered during check */
	gint i, nargc, targc;
	worker_t **pworker;
	gboolean lua_file = FALSE;
	gint retcode = 0;

	ucl_vars = g_hash_table_new_full (rspamd_strcase_hash,
		rspamd_strcase_equal, g_free, g_free);
	process_quark = g_quark_from_static_string ("rspamadm");
	cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_DEFAULT|RSPAMD_CONFIG_INIT_WIPE_LUA_MEM);
	cfg->libs_ctx = rspamd_init_libs ();
	rspamd_main = g_malloc0 (sizeof (*rspamd_main));
	rspamd_main->cfg = cfg;
	rspamd_main->pid = getpid ();
	rspamd_main->type = process_quark;
	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"rspamadm", 0);

	rspamadm_fill_internal_commands (all_commands);
	help_command.command_data = all_commands;

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
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}


	/* Setup logger */
	if (verbose) {
		rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_USEC|RSPAMD_LOG_FLAG_ENFORCED|RSPAMD_LOG_FLAG_RSPAMADM);
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_DEBUG);
	}
	else {
		rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_RSPAMADM);
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_MESSAGE);
	}

	rspamd_main->event_loop = ev_default_loop (rspamd_config_ev_backend_get (cfg));

	resolver = rspamd_dns_resolver_init (rspamd_main->logger,
			rspamd_main->event_loop,
			cfg);
	rspamd_main->http_ctx = rspamd_http_context_create (cfg, rspamd_main->event_loop,
			NULL);

	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);
	g_set_printerr_handler (rspamd_glib_printerr_function);
	rspamd_config_post_load (cfg,
			RSPAMD_CONFIG_INIT_LIBS|RSPAMD_CONFIG_INIT_URL|RSPAMD_CONFIG_INIT_NO_TLD);

	pworker = &workers[0];
	while (*pworker) {
		/* Init string quarks */
		(void) g_quark_from_static_string ((*pworker)->name);
		pworker++;
	}

	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;

	setproctitle ("rspamdadm");

	L = cfg->lua_state;
	rspamd_lua_set_path (L, NULL, ucl_vars);

	if (!rspamd_lua_set_env (L, ucl_vars, lua_env, &error)) {
		rspamd_fprintf (stderr, "Cannot load lua environment: %e", error);
		g_error_free (error);

		goto end;
	}

	rspamd_lua_set_globals (cfg, L);
	rspamadm_add_lua_globals (resolver);
	rspamd_redis_pool_config (cfg->redis_pool, cfg, rspamd_main->event_loop);

	/* Init rspamadm global */
	lua_newtable (L);

	PTR_ARRAY_FOREACH (all_commands, i, cmd) {
		if (cmd->lua_subrs != NULL) {
			cmd->lua_subrs (L);
		}

		cmd ++;
	}

	lua_setglobal (L, "rspamadm");

	rspamadm_fill_lua_commands (L, all_commands);
	rspamd_lua_start_gc (cfg);
	g_ptr_array_sort (all_commands, rspamdadm_commands_sort_func);

	g_strfreev (nargv);

	if (show_version) {
		rspamadm_version ();
		goto end;
	}
	if (show_help) {
		rspamadm_usage (context);
		goto end;
	}
	if (list_commands) {
		rspamadm_commands (all_commands);
		goto end;
	}

	cmd_name = argv[nargc];

	if (cmd_name == NULL) {
		cmd_name = "help";
	}

	gsize cmdlen = strlen (cmd_name);

	if (cmdlen > 4 && memcmp (cmd_name + (cmdlen - 4), ".lua", 4) == 0) {
		cmd_name = "lua";
		lua_file = TRUE;
	}

	cmd = rspamadm_search_command (cmd_name, all_commands);

	if (cmd == NULL) {
		rspamd_fprintf (stderr, "Invalid command name: %s\n", cmd_name);

		/* Try fuzz search */
		rspamd_fprintf (stderr, "Suggested commands:\n");
		PTR_ARRAY_FOREACH (all_commands, i, cmd) {
			guint j;
			const gchar *alias;

			if (rspamadm_command_maybe_match_name (cmd->name, cmd_name)) {
				rspamd_fprintf (stderr, "%s\n", cmd->name);
			}
			else {
				PTR_ARRAY_FOREACH (cmd->aliases, j, alias) {
					if (rspamadm_command_maybe_match_name (alias, cmd_name)) {
						rspamd_fprintf (stderr, "%s\n", alias);
					}
				}
			}
		}

		retcode = EXIT_FAILURE;
		goto end;
	}

	if (nargc < argc) {

		if (lua_file) {
			nargv = g_malloc0 (sizeof (gchar *) * (argc - nargc + 2));
			nargv[1] = g_strdup (argv[nargc]);
			i = 2;
			argc ++;
		}
		else {
			nargv = g_malloc0 (sizeof (gchar *) * (argc - nargc + 1));
			i = 1;
		}

		nargv[0] = g_strdup_printf ("%s %s", argv[0], cmd_name);

		for (; i < argc - nargc; i ++) {
			if (lua_file) {
				/*
				 * We append prefix '--arg=' to each argument and shift argv index
				 */
				gsize arglen = strlen (argv[i + nargc - 1]);

				arglen += sizeof ("--args="); /* Including \0 */
				nargv[i] = g_malloc (arglen);
				rspamd_snprintf (nargv[i], arglen, "--args=%s", argv[i + nargc - 1]);
			}
			else {
				nargv[i] = g_strdup (argv[i + nargc]);
			}
		}

		targc = argc - nargc;
		targv = nargv;
		cmd->run (targc, targv, cmd);
		g_strfreev (nargv);
	}
	else {
		cmd->run (0, NULL, cmd);
	}

	ev_break (rspamd_main->event_loop, EVBREAK_ALL);

end:
	g_option_context_free (context);
	rspamd_dns_resolver_deinit (resolver);
	REF_RELEASE (rspamd_main->cfg);
	rspamd_http_context_free (rspamd_main->http_ctx);
	rspamd_log_close (rspamd_main->logger);
	rspamd_url_deinit ();
	g_ptr_array_free (all_commands, TRUE);
	ev_loop_destroy (rspamd_main->event_loop);
	g_hash_table_unref (ucl_vars);
	rspamd_mempool_delete (rspamd_main->server_pool);
	g_free (rspamd_main);

	return retcode;
}

