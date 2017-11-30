/*-
 * Copyright 2017 Pragadeesh C
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

#include "rspamadm.h"
#include "config.h"
#include "lua/lua_common.h"

static gchar *ham_directory = NULL;
static gchar *spam_directory = NULL;
static gchar *output_location = "results.log";
static gint n_connections = 10;

static void rspamadm_corpus_test (gint argc, gchar **argv);
static const char *rspamadm_corpus_test_help (gboolean full_help);

struct rspamadm_command corpus_test_command = {
	.name = "corpus_test",
	.flags = 0,
	.help = rspamadm_corpus_test_help,
	.run = rspamadm_corpus_test
};

// TODO add -nparellel and -o options
static GOptionEntry entries[] = {
			{"ham", 'a', 0, G_OPTION_ARG_FILENAME, &ham_directory,
												"Ham directory", NULL},
			{"spam", 's', 0, G_OPTION_ARG_FILENAME, &spam_directory,
												"Spam directory", NULL},
			{"output", 'o', 0, G_OPTION_ARG_FILENAME, &output_location,
												"Log output location", NULL},
			{"n_connections", 'n', 0, G_OPTION_ARG_INT, &n_connections,
						"Number of parellel connections [Default: 10]", NULL},
			{NULL,	0,	0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_corpus_test_help (gboolean full_help) 
{
	const char *help_str;

	if (full_help) {
		help_str = "Produces log files for ham and spam corpus\n\n"
					"Usage: rspamadm corpus_test [-a <ham_directory>]"
											" [-s <spam_directory>]\n"
					"Where option are:\n\n"
					"-a: path to ham directory\n"
					"-s: path to spam directory\n"
					"-n: maximum parellel connections\n"
					"-o: log output file\n";

	}

	else {
		help_str = "Produces log files for ham and spam corpus";
	}

	return help_str;
}

static void
rspamadm_corpus_test (gint argc, gchar **argv) 
{
	GOptionContext *context;
	GError *error = NULL;
	lua_State *L;
	ucl_object_t *obj;

	context = g_option_context_new (
				"corpus_test - produces log files for ham and spam corpus");

	g_option_context_set_summary (context, 
			"Summary:\n Rspamd administration utility version "
						RVERSION
						"\n Release id: "
						RID);
	
	g_option_context_add_main_entries (context, entries, NULL);
	g_option_context_set_ignore_unknown_options (context, TRUE);
	
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit(1);
	}

	L = rspamd_lua_init ();
	rspamd_lua_set_path(L, NULL, NULL);


	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (ham_directory),
											"ham_directory", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (spam_directory),
											"spam_directory", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (output_location),
											"output_location", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (n_connections),
											"n_connections", 0, false);

	rspamd_lua_set_path (L, NULL, ucl_vars);

	rspamadm_execute_lua_ucl_subr (L,
						argc,
						argv,
						obj,
						"corpus_test");

	lua_close (L);
	ucl_object_unref (obj);
}
