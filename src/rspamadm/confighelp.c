/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#include <ucl.h>
#include "config.h"
#include "rspamadm.h"
#include "cfg_file.h"
#include "cfg_rcl.h"
#include "rspamd.h"
#include "lua/lua_common.h"

static gboolean json = FALSE;
static gboolean compact = FALSE;
static gboolean keyword = FALSE;
extern struct rspamd_main *rspamd_main;
/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

static void rspamadm_confighelp (gint argc, gchar **argv);

static const char *rspamadm_confighelp_help (gboolean full_help);

struct rspamadm_command confighelp_command = {
		.name = "confighelp",
		.flags = 0,
		.help = rspamadm_confighelp_help,
		.run = rspamadm_confighelp
};

static GOptionEntry entries[] = {
		{"json",    'j', 0, G_OPTION_ARG_NONE, &json,
				"Output json",      NULL},
		{"compact", 'c', 0, G_OPTION_ARG_NONE, &compact,
				"Output compacted", NULL},
		{"keyword", 'k', 0, G_OPTION_ARG_NONE, &keyword,
				"Search by keyword", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_confighelp_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Shows help for the specified configuration options\n\n"
				"Usage: rspamadm confighelp [option[, option...]]\n"
				"Where options are:\n\n"
				"-c: output compacted JSON\n"
				"-j: output pretty formatted JSON\n"
				"-k: search by keyword in doc string\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Shows help for configuration options";
	}

	return help_str;
}

static void
rspamadm_confighelp_show (const char *key, const ucl_object_t *obj)
{
	rspamd_fstring_t *out;

	out = rspamd_fstring_new ();

	if (json) {
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON, &out);
	}
	else if (compact) {
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &out);
	}
	else {
		/* TODO: add lua helper for output */
		if (key) {
			rspamd_fprintf (stdout, "Showing help for %s:\n", key);
		}
		else {
			rspamd_fprintf (stdout, "Showing help for all options:\n");
		}

		rspamd_ucl_emit_fstring (obj, UCL_EMIT_CONFIG, &out);
	}

	rspamd_fprintf (stdout, "%V", out);
	rspamd_fprintf (stdout, "\n");

	rspamd_fstring_free (out);
}

static void
rspamadm_confighelp_search_word_step (const ucl_object_t *obj,
		ucl_object_t *res,
		const gchar *str,
		gsize len,
		GString *path)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	const gchar *dot_pos;

	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		if (cur->keylen > 0) {
			rspamd_printf_gstring (path, ".%*s", (int) cur->keylen, cur->key);

			if (rspamd_substring_search (cur->key, cur->keylen, str, len) !=
					-1) {
				ucl_object_insert_key (res, ucl_object_ref (cur),
						path->str, path->len, true);
				goto fin;
			}
		}

		if (ucl_object_type (cur) == UCL_OBJECT) {
			elt = ucl_object_find_key (cur, "data");

			if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
				if (rspamd_substring_search (elt->value.sv,
						elt->len,
						str,
						len) != -1) {
					ucl_object_insert_key (res, ucl_object_ref (cur),
							path->str, path->len, true);
					goto fin;
				}
			}

			rspamadm_confighelp_search_word_step (cur, res, str, len, path);
		}

		fin:
		/* Remove the last component of the path */
		dot_pos = strrchr (path->str, '.');

		if (dot_pos) {
			g_string_erase (path, dot_pos - path->str,
					path->len - (dot_pos - path->str));
		}
	}
}

static ucl_object_t *
rspamadm_confighelp_search_word (const ucl_object_t *obj, const gchar *str)
{
	gsize len = strlen (str);
	GString *path = g_string_new ("");
	ucl_object_t *res;


	res = ucl_object_typed_new (UCL_OBJECT);

	rspamadm_confighelp_search_word_step (obj, res, str, len, path);

	return res;
}

static void
rspamadm_confighelp (gint argc, gchar **argv)
{
	struct rspamd_rcl_section *top;
	struct rspamd_config *cfg;
	const ucl_object_t *doc_obj;
	GOptionContext *context;
	GError *error = NULL;
	module_t *mod, **pmod;
	worker_t **pworker;
	struct module_ctx *mod_ctx;
	gint i = 1, ret = 0;

	context = g_option_context_new (
			"confighelp - displays help for the configuration options");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);
	g_option_context_set_ignore_unknown_options (context, TRUE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	cfg = rspamd_config_new ();
	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;

	top = rspamd_rcl_config_init (cfg);

	/* Init modules to get documentation strings */
	for (pmod = cfg->compiled_modules; pmod != NULL && *pmod != NULL; pmod++) {
		mod = *pmod;
		mod_ctx = g_slice_alloc0 (sizeof (struct module_ctx));

		if (mod->module_init_func (cfg, &mod_ctx) == 0) {
			g_hash_table_insert (cfg->c_modules,
					(gpointer) mod->name,
					mod_ctx);
			mod_ctx->mod = mod;
		}
	}
	/* Also init all workers */
	for (pworker = cfg->compiled_workers; *pworker != NULL; pworker ++) {
		(*pworker)->worker_init_func (cfg);
	}

	if (argc > 1) {
		while (argc > 1) {
			if (argv[i][0] != '-') {

				if (keyword) {
					doc_obj = rspamadm_confighelp_search_word (cfg->doc_strings,
							argv[i]);
				}
				else {
					doc_obj = ucl_lookup_path (cfg->doc_strings, argv[i]);
				}

				if (doc_obj != NULL) {
					rspamadm_confighelp_show (argv[i], doc_obj);

					if (keyword) {
						ucl_object_unref ((ucl_object_t *)doc_obj);
					}
				}
				else {
					rspamd_fprintf (stderr,
							"Cannot find help for %s\n",
							argv[i]);
					ret = EXIT_FAILURE;
				}
			}

			i++;
			argc--;
		}
	}
	else {
		/* Show all documentation strings */
		rspamadm_confighelp_show (NULL, cfg->doc_strings);
	}

	rspamd_config_free (cfg);

	exit (ret);
}
