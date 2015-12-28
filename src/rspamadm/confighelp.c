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

#include "config.h"
#include "rspamadm.h"
#include "cfg_file.h"
#include "cfg_rcl.h"
#include "rspamd.h"
#include "lua/lua_common.h"

static gchar *config = NULL;
static gboolean json = FALSE;
static gboolean compact = FALSE;
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
				"--help: shows available options and commands";
	}
	else {
		help_str = "Shows help for configuration options";
	}

	return help_str;
}

static void
rspamadm_confighelp_show (const ucl_object_t *obj)
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
		rspamd_ucl_emit_fstring (obj, UCL_EMIT_CONFIG, &out);
	}

	rspamd_fprintf (stdout, "%V", out);

	rspamd_fstring_free (out);
}

static void
rspamadm_confighelp (gint argc, gchar **argv)
{
	struct rspamd_rcl_section *top;
	struct rspamd_config *cfg;
	const ucl_object_t *doc_obj;
	GOptionContext *context;
	GError *error = NULL;
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

	top = rspamd_rcl_config_init (cfg);

	if (argc > 1) {
		while (argc > 1) {
			doc_obj = ucl_lookup_path (cfg->doc_strings, argv[i]);

			if (doc_obj != NULL) {
				rspamadm_confighelp_show (doc_obj);
			}
			else {
				rspamd_fprintf (stderr, "Cannot find help for %s\n", argv[i]);
				ret = EXIT_FAILURE;
			}

			i++;
			argc--;
		}
	}
	else {
		/* Show all documentation strings */
		rspamadm_confighelp_show (cfg->doc_strings);
	}

	exit (ret);
}
