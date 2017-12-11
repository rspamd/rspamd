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

#include "config.h"
#include "rspamadm.h"
#include "lua/lua_common.h"

#if !defined(WITH_TORCH) || !defined(WITH_LUAJIT)
#define HAS_TORCH false
#else
#define HAS_TORCH true
#endif

static gchar *logdir = NULL;
static gchar *output = "new.scores";
static gdouble threshold = 15; /* Spam threshold */
static gboolean score_diff = false;  /* Print score diff flag */
static gint64 iters = 500; /* Perceptron max iterations */

/* TODO: think about adding the config file reading */

static void rspamadm_rescore (gint argc, gchar **argv);

static const char *rspamadm_rescore_help (gboolean full_help);

struct rspamadm_command rescore_command = {
		.name = "rescore",
		.flags = 0,
		.help = rspamadm_rescore_help,
		.run = rspamadm_rescore
};

static GOptionEntry entries[] = {
		{"logdir", 'l', 0, G_OPTION_ARG_FILENAME, &logdir,
				"Logs directory",                               NULL},
		{"output", 'o', 0, G_OPTION_ARG_FILENAME, &output,
				"Scores output locaiton",                       NULL},
		{"diff",   'd', 0, G_OPTION_ARG_NONE,     &score_diff,
				"Print score diff",                             NULL},
		{"iters",  'i', 0, G_OPTION_ARG_INT64,    &iters,
				"Max iterations for perceptron [Default: 500]", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL,       NULL}
};

static const char *
rspamadm_rescore_help (gboolean full_help) {

	const char *help_str;

	if (full_help) {
		help_str = "Estimate optimal symbol weights from log files\n\n"
				"Usage: rspamadm rescore -l <log_directory>\n"
				"Where options are:\n\n"
				"-l: path to logs directory\n"
				"-o: Scores output file location\n"
				"-d: Print scores diff\n"
				"-i: Max iterations for perceptron\n";
	} else {
		help_str = "Estimate optimal symbol weights from log files";
	}

	return help_str;
}

static void
rspamadm_rescore (gint argc, gchar **argv) {

	GOptionContext *context;
	GError *error = NULL;
	lua_State *L;
	ucl_object_t *obj;

	context = g_option_context_new (
			"rescore - Estimate optimal symbol weights from log files");

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
		exit (EXIT_FAILURE);
	}

	if (!HAS_TORCH) {
		rspamd_fprintf (stderr, "Torch is not enabled. "
				"Use -DENABLE_TORCH=ON option while running cmake.\n");
		exit (EXIT_FAILURE);
	}

	if (logdir == NULL) {
		rspamd_fprintf (stderr, "Please specify log directory.\n");
		exit (EXIT_FAILURE);
	}

	L = rspamd_lua_init ();
	rspamd_lua_set_path (L, NULL, NULL);

	obj = ucl_object_typed_new (UCL_OBJECT);

	ucl_object_insert_key (obj, ucl_object_fromstring (logdir),
			"logdir", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (output),
			"output", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromdouble (threshold),
			"threshold", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (iters),
			"iters", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (score_diff),
			"diff", 0, false);

	rspamadm_execute_lua_ucl_subr (L,
			argc,
			argv,
			obj,
			"rescore");

	lua_close (L);
	ucl_object_unref (obj);
}