/*-
 * Copyright 2017 Vsevolod Stakhov
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
#include "cfg_file.h"
#include "cfg_rcl.h"
#include "utlist.h"
#include "rspamd.h"
#include "lua/lua_common.h"
#include "utlist.h"

static gchar *config = NULL;
extern struct rspamd_main *rspamd_main;
/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

static void rspamadm_configwizard (gint argc, gchar **argv);
static const char *rspamadm_configwizard_help (gboolean full_help);

struct rspamadm_command configwizard_command = {
		.name = "configwizard",
		.flags = 0,
		.help = rspamadm_configwizard_help,
		.run = rspamadm_configwizard,
		.lua_subrs = NULL,
};

static GOptionEntry entries[] = {
		{"config", 'c', 0, G_OPTION_ARG_STRING, &config,
				"Config file to use",     NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_configwizard_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Perform guided configuration for Rspamd daemon\n\n"
				"Usage: rspamadm configwizard [-c <config_name>] [checks...]\n"
		 		"       rspamadm configwizard [-c <config_name>] list\n"
				"Where options are:\n\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Perform guided configuration for Rspamd daemon";
	}

	return help_str;
}

static void
config_logger (rspamd_mempool_t *pool, gpointer ud)
{
	struct rspamd_main *rm = ud;

	rm->cfg->log_type = RSPAMD_LOG_CONSOLE;
	rm->cfg->log_level = G_LOG_LEVEL_MESSAGE;

	rspamd_set_logger (rm->cfg, g_quark_try_string ("main"), &rm->logger,
			rm->server_pool);

	if (rspamd_log_open_priv (rm->logger, rm->workers_uid, rm->workers_gid) ==
			-1) {
		fprintf (stderr, "Fatal error, cannot open logfile, exiting\n");
		exit (EXIT_FAILURE);
	}
}

static void
rspamadm_configwizard (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	const gchar *confdir;
	struct rspamd_config *cfg = rspamd_main->cfg;
	gboolean ret = TRUE;
	worker_t **pworker;
	lua_State *L;

	context = g_option_context_new (
			"configwizard - perform guided configuration");
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

	if (config == NULL) {
		if ((confdir = g_hash_table_lookup (ucl_vars, "CONFDIR")) == NULL) {
			confdir = RSPAMD_CONFDIR;
		}

		config = g_strdup_printf ("%s%c%s", confdir, G_DIR_SEPARATOR,
				"rspamd.conf");
	}

	pworker = &workers[0];
	while (*pworker) {
		/* Init string quarks */
		(void) g_quark_from_static_string ((*pworker)->name);
		pworker++;
	}

	cfg->cache = rspamd_symbols_cache_new (cfg);
	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;
	cfg->cfg_name = config;

	if (!rspamd_config_read (cfg, cfg->cfg_name, NULL,
			config_logger, rspamd_main, ucl_vars)) {
		ret = FALSE;
	}
	else {
		/* Do post-load actions */
		rspamd_lua_post_load_config (cfg);

		if (!rspamd_init_filters (cfg, FALSE)) {
			ret = FALSE;
		}

		if (ret) {
			ret = rspamd_config_post_load (cfg, RSPAMD_CONFIG_INIT_SYMCACHE);
		}
	}

	if (ret) {
		L = cfg->lua_state;
		rspamd_lua_set_path (L, cfg->rcl_obj, ucl_vars);
		ucl_object_insert_key (cfg->rcl_obj, ucl_object_fromstring (cfg->cfg_name),
				"config_path", 0, false);

		rspamadm_execute_lua_ucl_subr (L,
				argc,
				argv,
				cfg->rcl_obj,
				"configwizard");

		lua_close (L);
	}

	exit (ret ? EXIT_SUCCESS  : EXIT_FAILURE);
}
