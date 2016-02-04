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
#include "cfg_file.h"
#include "cfg_rcl.h"
#include "utlist.h"
#include "rspamd.h"
#include "lua/lua_common.h"

static gboolean json = FALSE;
static gboolean compact = FALSE;
static gchar *config = NULL;
static gchar **sections = NULL;
extern struct rspamd_main *rspamd_main;
/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

static void rspamadm_configdump (gint argc, gchar **argv);
static const char *rspamadm_configdump_help (gboolean full_help);

struct rspamadm_command configdump_command = {
		.name = "configdump",
		.flags = 0,
		.help = rspamadm_configdump_help,
		.run = rspamadm_configdump
};

static GOptionEntry entries[] = {
		{"json", 'j', 0, G_OPTION_ARG_NONE, &json,
				"Json output (pretty formatted)", NULL},
		{"compact", 'C', 0, G_OPTION_ARG_NONE, &compact,
				"Compacted json output", NULL},
		{"config", 'c', 0, G_OPTION_ARG_STRING, &config,
				"Config file to test",     NULL},
		{"section", 's', 0, G_OPTION_ARG_STRING_ARRAY, &sections,
				"Sections to dump",      NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_configdump_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Perform configuration file dump\n\n"
				"Usage: rspamadm configdump [-c <config_name> -j --compact [-s <section> [-s <section>]]]\n"
				"Where options are:\n\n"
				"-j: output plain json\n"
				"--compact: output compacted json\n"
				"-c: config file to test\n"
				"-s: specify section to dump (can be multiple)\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Perform configuration file dump";
	}

	return help_str;
}

static void
config_logger (rspamd_mempool_t *pool, gpointer ud)
{
	struct rspamd_main *rm = ud;

	rm->cfg->log_type = RSPAMD_LOG_CONSOLE;
	rm->cfg->log_level = G_LOG_LEVEL_CRITICAL;

	rspamd_set_logger (rm->cfg, g_quark_try_string ("main"), rm);
	if (rspamd_log_open_priv (rm->logger, rm->workers_uid, rm->workers_gid) ==
			-1) {
		fprintf (stderr, "Fatal error, cannot open logfile, exiting\n");
		exit (EXIT_FAILURE);
	}
}

static void
rspamadm_dump_section_obj (const ucl_object_t *obj)
{
	rspamd_fstring_t *output;

	output = rspamd_fstring_new ();

	if (json) {
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON, &output);
	}
	else if (compact) {
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &output);
	}
	else {
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_CONFIG, &output);
	}

	rspamd_printf ("%V", output);

	rspamd_fstring_free (output);
}

static void
rspamadm_configdump (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	const gchar *confdir;
	const ucl_object_t *obj, *cur;
	struct rspamd_config *cfg = rspamd_main->cfg;
	gboolean ret = TRUE;
	worker_t **pworker;
	gchar **sec;

	context = g_option_context_new (
			"keypair - create encryption keys");
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

		if (!rspamd_init_filters (rspamd_main->cfg, FALSE)) {
			ret = FALSE;
		}

		if (ret) {
			ret = rspamd_config_post_load (cfg, FALSE);
		}
	}

	if (ret) {
		/* Output configuration */


		if (!sections) {
			rspamadm_dump_section_obj (cfg->rcl_obj);
		}
		else {
			sec = sections;

			while (*sec != NULL) {
				obj = ucl_object_find_key (cfg->rcl_obj, *sec);

				if (!obj) {
					rspamd_printf ("Section %s NOT FOUND\n", *sec);
				}
				else {
					LL_FOREACH (obj, cur) {
						if (!json && !compact) {
							rspamd_printf ("*** Section %s ***\n", *sec);
						}
						rspamadm_dump_section_obj (cur);

						if (!json && !compact) {
							rspamd_printf ("*** End of section %s ***\n", *sec);
						}
						else {
							rspamd_printf ("\n");
						}
					}
				}

				sec ++;
			}

			g_strfreev (sections);
		}
	}

	if (!ret) {
		exit (EXIT_FAILURE);
	}

	exit (EXIT_SUCCESS);
}
