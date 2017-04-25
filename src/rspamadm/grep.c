/*-
 * Copyright (c) 2017, Andrew Lewis <nerf@judo.za.org>
 * Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>
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
#include "lua/lua_common.h"
#include "grep.lua.h"

static gchar *string = NULL;
static gchar *pattern = NULL;
static gchar **inputs = NULL;
static gboolean sensitive = FALSE;
static gboolean orphans = FALSE;
static gboolean partial = FALSE;
static gboolean luapat = FALSE;

static void rspamadm_grep (gint argc, gchar **argv);
static const char *rspamadm_grep_help (gboolean full_help);

struct rspamadm_command grep_command = {
		.name = "grep",
		.flags = 0,
		.help = rspamadm_grep_help,
		.run = rspamadm_grep
};

static GOptionEntry entries[] = {
		{"string", 's', 0, G_OPTION_ARG_STRING, &string,
				"Plain string to search (case-insensitive)", NULL},
		{"lua", 'l', 0, G_OPTION_ARG_NONE, &luapat,
				"Use Lua patterns in string search", NULL},
		{"pattern", 'p', 0, G_OPTION_ARG_STRING, &pattern,
				"Pattern to search for (regex)", NULL},
                {"input", 'i', 0, G_OPTION_ARG_STRING_ARRAY, &inputs,
                                "Process specified inputs (stdin if unspecified)", NULL},
		{"sensitive", 'S', 0, G_OPTION_ARG_NONE, &sensitive,
				"Enable case-sensitivity in string search", NULL},
		{"orphans", 'o', 0, G_OPTION_ARG_NONE, &orphans,
				"Print orphaned logs", NULL},
		{"partial", 'P', 0, G_OPTION_ARG_NONE, &partial,
				"Print partial logs", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};


static const char *
rspamadm_grep_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Search for patterns in rspamd logs\n\n"
				"Usage: rspamadm grep <-s string | -p pattern> [-i input1 -i input2 -S -o -P]\n"
				"Where options are:\n\n"
				"-s: Plain string to search (case-insensitive)\n"
				"-l: Use Lua patterns in string search\n"
				"-p: Pattern to search for (regex)\n"
				"-i: Process specified inputs (stdin if unspecified)\n"
				"-S: Enable case-sensitivity in string search\n"
				"-o: Print orphaned logs\n"
				"-P: Print partial logs\n";
	}
	else {
		help_str = "Search for patterns in rspamd logs";
	}

	return help_str;
}

static void
rspamadm_grep (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	lua_State *L;
	ucl_object_t *obj, *nobj;
	gchar **elt;

	context = g_option_context_new (
			"grep - search for patterns in rspamd logs");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);
	g_option_context_set_ignore_unknown_options (context, FALSE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (!pattern && !string) {
		rspamd_fprintf (stderr, "no search pattern specified\n");
		exit (1);
	}
	if (pattern && string) {
		rspamd_fprintf (stderr, "-s and -p are mutually-exclusive\n");
		exit (1);
	}

	L = rspamd_lua_init ();

	obj = ucl_object_typed_new (UCL_OBJECT);
	if (string) {
		ucl_object_insert_key (obj, ucl_object_fromstring (string),
				"string", 0, false);
	}
	if (pattern) {
		ucl_object_insert_key (obj, ucl_object_fromstring (pattern),
				"pattern", 0, false);
	}
	nobj = ucl_object_typed_new (UCL_ARRAY);
	if (!inputs) {
		ucl_array_append (nobj, ucl_object_fromstring ("stdin"));
	}
	else {
		for (elt = inputs; *elt != NULL; elt ++) {
			ucl_array_append (nobj, ucl_object_fromstring (*elt));
		}
	}
	ucl_object_insert_key (obj, nobj, "inputs", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (sensitive),
			"sensitive", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (orphans),
			"orphans", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (partial),
			"partial", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (luapat),
			"luapat", 0, false);

	rspamadm_execute_lua_ucl_subr (L,
			argc,
			argv,
			obj,
			rspamadm_script_grep);

	lua_close (L);
	ucl_object_unref (obj);
}
