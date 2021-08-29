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
#include "utlist.h"

static gboolean json = FALSE;
static gboolean compact = FALSE;
static gboolean show_help = FALSE;
static gboolean show_comments = FALSE;
static gboolean modules_state = FALSE;
static gboolean symbol_groups_only = FALSE;
static gboolean skip_template = FALSE;
static gchar *config = NULL;
extern struct rspamd_main *rspamd_main;
/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

static void rspamadm_configdump (gint argc, gchar **argv, const struct rspamadm_command *);
static const char *rspamadm_configdump_help (gboolean full_help, const struct rspamadm_command *);

struct rspamadm_command configdump_command = {
		.name = "configdump",
		.flags = 0,
		.help = rspamadm_configdump_help,
		.run = rspamadm_configdump,
		.lua_subrs = NULL,
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
		{"show-comments", 's', 0, G_OPTION_ARG_NONE, &show_comments,
				"Show saved comments from the configuration file", NULL },
		{"modules-state", 'm', 0, G_OPTION_ARG_NONE, &modules_state,
				"Show modules state only", NULL},
		{"groups", 'g', 0, G_OPTION_ARG_NONE, &symbol_groups_only,
				"Show symbols groups only", NULL},
		{"skip-template", 'T', 0, G_OPTION_ARG_NONE, &skip_template,
				"Do not apply Jinja templates", NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_configdump_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Perform configuration file dump\n\n"
				"Usage: rspamadm configdump [-c <config_name> [-j --compact -m] [<path1> [<path2> ...]]]\n"
				"Where options are:\n\n"
				"-j: output plain json\n"
				"--compact: output compacted json\n"
				"-c: config file to test\n"
				"-m: show state of modules only\n"
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
}

static void
rspamadm_add_doc_elt (const ucl_object_t *obj, const ucl_object_t *doc_obj,
		ucl_object_t *comment_obj)
{
	rspamd_fstring_t *comment = rspamd_fstring_new ();
	const ucl_object_t *elt;
	ucl_object_t *nobj, *cur_comment;

	if (ucl_object_lookup_len (comment_obj, (const char *)&obj,
			sizeof (void *))) {
		rspamd_fstring_free (comment);
		/* Do not rewrite the existing comment */
		return;
	}

	if (doc_obj != NULL) {
		/* Create doc comment */
		nobj = ucl_object_fromstring_common ("/*", 0, 0);
	}
	else {
		rspamd_fstring_free (comment);
		return;
	}

	/* We create comments as a list of parts */
	elt = ucl_object_lookup (doc_obj, "data");
	if (elt) {
		rspamd_printf_fstring (&comment, " * %s", ucl_object_tostring (elt));
		cur_comment = ucl_object_fromstring_common (comment->str, comment->len, 0);
		rspamd_fstring_erase (comment, 0, comment->len);
		DL_APPEND (nobj, cur_comment);
	}

	elt = ucl_object_lookup (doc_obj, "type");
	if (elt) {
		rspamd_printf_fstring (&comment, " * Type: %s", ucl_object_tostring (elt));
		cur_comment = ucl_object_fromstring_common (comment->str, comment->len, 0);
		rspamd_fstring_erase (comment, 0, comment->len);
		DL_APPEND (nobj, cur_comment);
	}

	elt = ucl_object_lookup (doc_obj, "required");
	if (elt) {
		rspamd_printf_fstring (&comment, " * Required: %s",
				ucl_object_toboolean (elt) ? "true" : "false");
		cur_comment = ucl_object_fromstring_common (comment->str, comment->len, 0);
		rspamd_fstring_erase (comment, 0, comment->len);
		DL_APPEND (nobj, cur_comment);
	}

	cur_comment = ucl_object_fromstring (" */");
	DL_APPEND (nobj, cur_comment);
	rspamd_fstring_free (comment);

	ucl_object_insert_key (comment_obj, ucl_object_ref (nobj),
			(const char *)&obj,
			sizeof (void *), true);

	ucl_object_unref (nobj);
}

static void
rspamadm_gen_comments (const ucl_object_t *obj, const ucl_object_t *doc_obj,
		ucl_object_t *comments)
{
	const ucl_object_t *cur_obj, *cur_doc, *cur_elt;
	ucl_object_iter_t it = NULL;

	if (obj == NULL || doc_obj == NULL) {
		return;
	}

	if (obj->keylen > 0) {
		rspamadm_add_doc_elt (obj, doc_obj, comments);
	}

	if (ucl_object_type (obj) == UCL_OBJECT) {
		while ((cur_obj = ucl_object_iterate (obj, &it, true))) {
			cur_doc = ucl_object_lookup_len (doc_obj, cur_obj->key,
					cur_obj->keylen);

			if (cur_doc != NULL) {
				LL_FOREACH (cur_obj, cur_elt) {
					if (ucl_object_lookup_len (comments, (const char *)&cur_elt,
							sizeof (void *)) == NULL) {
						rspamadm_gen_comments (cur_elt, cur_doc, comments);
					}
				}
			}
		}
	}
}

static void
rspamadm_dump_section_obj (struct rspamd_config *cfg,
		const ucl_object_t *obj, const ucl_object_t *doc_obj)
{
	rspamd_fstring_t *output;
	ucl_object_t *comments = NULL;

	output = rspamd_fstring_new ();

	if (show_help) {
		if (show_comments) {
			comments = cfg->config_comments;
		}
		else {
			comments = ucl_object_typed_new (UCL_OBJECT);
		}

		rspamadm_gen_comments (obj, doc_obj, comments);
	}
	else if (show_comments) {
		comments = cfg->config_comments;
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

__attribute__((noreturn))
static void
rspamadm_configdump (gint argc, gchar **argv, const struct rspamadm_command *cmd)
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
			"configdump - dumps Rspamd configuration");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	g_option_context_free (context);

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

	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;
	cfg->cfg_name = config;

	if (!rspamd_config_read (cfg, cfg->cfg_name, config_logger, rspamd_main,
			ucl_vars, skip_template, lua_env)) {
		ret = FALSE;
	}
	else {
		/* Do post-load actions */
		rspamd_lua_post_load_config (cfg);

		(void)rspamd_init_filters (rspamd_main->cfg, false, false);
		rspamd_config_post_load (cfg, RSPAMD_CONFIG_INIT_SYMCACHE);
	}

	if (ret) {
		if (modules_state) {

			rspamadm_execute_lua_ucl_subr (argc,
					argv,
					cfg->rcl_obj,
					"plugins_stats",
					FALSE);

			exit (EXIT_SUCCESS);
		}

		if (symbol_groups_only) {
			/*
			 * Create object from symbols groups and output it using the
			 * specified format
			 */
			ucl_object_t *out = ucl_object_typed_new (UCL_OBJECT);
			GHashTableIter it;
			gpointer k, v;

			g_hash_table_iter_init (&it, cfg->groups);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				const gchar *gr_name = (const gchar *)k;
				struct rspamd_symbols_group *gr = (struct rspamd_symbols_group *)v;
				ucl_object_t *gr_ucl = ucl_object_typed_new (UCL_OBJECT);

				ucl_object_insert_key (gr_ucl,
						ucl_object_frombool (!!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)),
						"public", strlen ("public"), false);
				ucl_object_insert_key (gr_ucl,
						ucl_object_frombool (!!(gr->flags & RSPAMD_SYMBOL_GROUP_DISABLED)),
						"disabled", strlen ("disabled"), false);
				ucl_object_insert_key (gr_ucl,
						ucl_object_frombool (!!(gr->flags & RSPAMD_SYMBOL_GROUP_ONE_SHOT)),
						"one_shot", strlen ("one_shot"), false);
				ucl_object_insert_key (gr_ucl,
						ucl_object_fromdouble (gr->max_score),
						"max_score", strlen ("max_score"), false);
				ucl_object_insert_key (gr_ucl,
						ucl_object_fromstring (gr->description),
						"description", strlen ("description"), false);

				if (gr->symbols) {
					GHashTableIter sit;
					gpointer sk, sv;

					g_hash_table_iter_init (&sit, gr->symbols);
					ucl_object_t *sym_ucl = ucl_object_typed_new (UCL_OBJECT);

					while (g_hash_table_iter_next (&sit, &sk, &sv)) {
						const gchar *sym_name = (const gchar *) sk;
						struct rspamd_symbol *s = (struct rspamd_symbol *)sv;
						ucl_object_t *spec_sym = ucl_object_typed_new (UCL_OBJECT);

						ucl_object_insert_key (spec_sym,
								ucl_object_fromdouble (s->score),
								"score", strlen ("score"),
								false);
						ucl_object_insert_key (spec_sym,
								ucl_object_fromstring (s->description),
								"description", strlen ("description"), false);
						ucl_object_insert_key (spec_sym,
								ucl_object_frombool (!!(s->flags & RSPAMD_SYMBOL_FLAG_DISABLED)),
								"disabled", strlen ("disabled"),
								false);

						if (s->nshots == 1) {
							ucl_object_insert_key (spec_sym,
									ucl_object_frombool (true),
									"one_shot", strlen ("one_shot"),
									false);
						}
						else {
							ucl_object_insert_key (spec_sym,
									ucl_object_frombool (false),
									"one_shot", strlen ("one_shot"),
									false);
						}

						ucl_object_t *add_groups = ucl_object_typed_new (UCL_ARRAY);
						guint j;
						struct rspamd_symbols_group *add_gr;

						PTR_ARRAY_FOREACH (s->groups, j, add_gr) {
							if (add_gr->name && strcmp (add_gr->name, gr_name) != 0) {
								ucl_array_append (add_groups,
										ucl_object_fromstring (add_gr->name));
							}
						}

						ucl_object_insert_key (spec_sym,
								add_groups,
								"extra_groups", strlen ("extra_groups"),
								false);

						ucl_object_insert_key (sym_ucl, spec_sym, sym_name,
								strlen (sym_name), true);
					}

					ucl_object_insert_key (gr_ucl, sym_ucl, "symbols",
							strlen ("symbols"), false);
				}

				ucl_object_insert_key (out, gr_ucl, gr_name, strlen (gr_name),
						true);
			}

			rspamadm_dump_section_obj (cfg, out, NULL);

			exit (EXIT_SUCCESS);
		}

		/* Output configuration */
		if (argc == 1) {
			rspamadm_dump_section_obj (cfg, cfg->rcl_obj, cfg->doc_strings);
		}
		else {
			for (i = 1; i < argc; i ++) {
				obj = ucl_object_lookup_path (cfg->rcl_obj, argv[i]);
				doc_obj = ucl_object_lookup_path (cfg->doc_strings, argv[i]);

				if (!obj) {
					rspamd_printf ("Section %s NOT FOUND\n", argv[i]);
				}
				else {
					LL_FOREACH (obj, cur) {
						if (!json && !compact) {
							rspamd_printf ("*** Section %s ***\n",  argv[i]);
						}
						rspamadm_dump_section_obj (cfg, cur, doc_obj);

						if (!json && !compact) {
							rspamd_printf ("\n*** End of section %s ***\n",  argv[i]);
						}
						else {
							rspamd_printf ("\n");
						}
					}
				}
			}
		}
	}

	exit (ret ? EXIT_SUCCESS  : EXIT_FAILURE);
}
