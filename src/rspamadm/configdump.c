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
static gboolean show_help = FALSE;
static gchar *config = NULL;
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
		{"show-help", 'h', 0, G_OPTION_ARG_NONE, &show_help,
				"Show help as comments for each option", NULL },
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_configdump_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Perform configuration file dump\n\n"
				"Usage: rspamadm configdump [-c <config_name> -j --compact [<path1> [<path2> ...]]]\n"
				"Where options are:\n\n"
				"-j: output plain json\n"
				"--compact: output compacted json\n"
				"-c: config file to test\n"
				"-h: show help for dumped options\n"
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
rspamadm_add_doc_elt (const ucl_object_t *obj, const ucl_object_t *doc_obj,
		ucl_object_t *comment_obj)
{
	rspamd_fstring_t *comment = rspamd_fstring_new ();
	const ucl_object_t *elt, *cur;
	ucl_object_t *nobj;

	if (doc_obj != NULL) {
		/* Create doc comment */
		rspamd_printf_fstring (&comment, "/*\n");
	}

	elt = ucl_object_find_key (doc_obj, "data");
	if (elt) {
		rspamd_printf_fstring (&comment, "* %s\n", ucl_object_tostring (elt));
	}

	elt = ucl_object_find_key (doc_obj, "type");
	if (elt) {
		rspamd_printf_fstring (&comment, "* Type: %s\n", ucl_object_tostring (elt));
	}

	elt = ucl_object_find_key (doc_obj, "required");
	if (elt) {
		rspamd_printf_fstring (&comment, "* Required %b\n",
				ucl_object_toboolean (elt));
	}

	rspamd_printf_fstring (&comment, " */\n");

	nobj = ucl_object_fromlstring (comment->str, comment->len);
	rspamd_fstring_free (comment);

	LL_FOREACH (obj, cur) {
		ucl_object_insert_key (comment_obj, nobj, (const char *)&cur,
				sizeof (void *), true);
	}
}

static void
rspamadm_gen_comments (const ucl_object_t *obj, const ucl_object_t *doc_obj,
		ucl_object_t *comments)
{
	const ucl_object_t *cur_obj, *cur_doc;
	ucl_object_iter_t it = NULL;
	ucl_object_t *cur_elt;

	if (obj == NULL || doc_obj == NULL || obj->keylen == 0) {
		return;
	}

	cur_doc = ucl_object_find_keyl (doc_obj, obj->key, obj->keylen);

	if (cur_doc != NULL) {
		rspamadm_add_doc_elt (obj, cur_doc, comments);
	}

	if (ucl_object_type (obj) == UCL_OBJECT) {
		while ((cur_obj = ucl_iterate_object (obj, &it, true))) {
			cur_doc = ucl_object_find_keyl (doc_obj, cur_obj->key,
					cur_obj->keylen);

			if (cur_doc != NULL) {
				cur_elt = (ucl_object_t *)ucl_object_find_keyl (comments,
						(const char *)&cur_obj,
						sizeof (void *));
				if (cur_elt == NULL) {
					cur_elt = ucl_object_typed_new (UCL_OBJECT);
				}

				ucl_object_insert_key (comments, cur_elt, (const char *)&cur_obj,
								sizeof (void *), true);

				rspamadm_gen_comments (cur_obj, cur_doc, cur_elt);
			}
		}
	}
}

static void
rspamadm_dump_section_obj (const ucl_object_t *obj, const ucl_object_t *doc_obj)
{
	rspamd_fstring_t *output;
	ucl_object_t *comments = NULL;

	output = rspamd_fstring_new ();

	if (show_help) {
		comments = ucl_object_typed_new (UCL_OBJECT);
		rspamadm_gen_comments (obj, doc_obj, comments);
	}

	if (json) {
		rspamd_ucl_emit_fstring_comments (obj, UCL_EMIT_JSON, &output, comments);
	}
	else if (compact) {
		rspamd_ucl_emit_fstring_comments (obj, UCL_EMIT_JSON_COMPACT, &output,
				comments);
	}
	else {
		rspamd_ucl_emit_fstring_comments (obj, UCL_EMIT_CONFIG, &output,
				comments);
	}

	rspamd_printf ("%V", output);
	rspamd_fstring_free (output);

	if (comments != NULL) {
		ucl_object_unref (comments);
	}
}

static void
rspamadm_configdump (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	const gchar *confdir;
	const ucl_object_t *obj, *cur, *doc_obj;
	struct rspamd_config *cfg = rspamd_main->cfg;
	gboolean ret = TRUE;
	worker_t **pworker;
	gint i;

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
		if (argc == 1) {
			rspamadm_dump_section_obj (cfg->rcl_obj, cfg->doc_strings);
		}
		else {
			for (i = 1; i < argc; i ++) {
				obj = ucl_lookup_path (cfg->rcl_obj, argv[i]);
				doc_obj = ucl_lookup_path (cfg->doc_strings, argv[i]);

				if (!obj) {
					rspamd_printf ("Section %s NOT FOUND\n", argv[i]);
				}
				else {
					LL_FOREACH (obj, cur) {
						if (!json && !compact) {
							rspamd_printf ("*** Section %s ***\n",  argv[i]);
						}
						rspamadm_dump_section_obj (cur, doc_obj);

						if (!json && !compact) {
							rspamd_printf ("*** End of section %s ***\n",  argv[i]);
						}
						else {
							rspamd_printf ("\n");
						}
					}
				}
			}
		}
	}

	if (!ret) {
		exit (EXIT_FAILURE);
	}

	exit (EXIT_SUCCESS);
}
