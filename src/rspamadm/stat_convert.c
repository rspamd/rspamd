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
#include "lua/lua_common.h"

#include "contrib/uthash/utlist.h"

/* Common */
static gchar *config_file = NULL;
static gchar *symbol_ham = NULL;
static gchar *symbol_spam = NULL;

static gdouble expire = 0.0;

/* Inputs */
static gchar *spam_db = NULL;
static gchar *ham_db = NULL;
static gchar *cache_db = NULL;

/* Outputs */
static gchar *redis_host = NULL;
static gchar *redis_db = NULL;
static gchar *redis_password = NULL;
static gboolean reset_previous = FALSE;

static void rspamadm_statconvert (gint argc, gchar **argv,
								  const struct rspamadm_command *cmd);
static const char *rspamadm_statconvert_help (gboolean full_help,
											  const struct rspamadm_command *cmd);

struct rspamadm_command statconvert_command = {
		.name = "statconvert",
		.flags = 0,
		.help = rspamadm_statconvert_help,
		.run = rspamadm_statconvert,
		.lua_subrs = NULL,
};

static GOptionEntry entries[] = {
		{"config", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
				"Config file to read data from",      NULL},
		{"reset", 'r', 0, G_OPTION_ARG_NONE, &reset_previous,
				"Reset previous data instead of appending values", NULL},
		{"expire", 'e', 0, G_OPTION_ARG_DOUBLE, &expire,
				"Set expiration in seconds (can be fractional)", NULL},

		{"symbol-spam", 0, 0, G_OPTION_ARG_STRING, &symbol_spam,
				"Symbol for spam (e.g. BAYES_SPAM)", NULL},
		{"symbol-ham", 0, 0, G_OPTION_ARG_STRING, &symbol_ham,
				"Symbol for ham (e.g. BAYES_HAM)", NULL},
		{"spam-db", 0, 0, G_OPTION_ARG_STRING, &spam_db,
				"Input spam file (sqlite3)", NULL},
		{"ham-db", 0, 0, G_OPTION_ARG_STRING, &ham_db,
				"Input ham file (sqlite3)", NULL},
		{"cache", 0, 0, G_OPTION_ARG_FILENAME, &cache_db,
				"Input learn cache",      NULL},
		{"redis-host", 'h', 0, G_OPTION_ARG_STRING, &redis_host,
				"Output redis ip (in format ip:port)", NULL},
		{"redis-password", 'p', 0, G_OPTION_ARG_STRING, &redis_password,
				"Password to connect to redis", NULL},
		{"redis-db", 'd', 0, G_OPTION_ARG_STRING, &redis_db,
				"Redis database (should be numeric)", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};


static const char *
rspamadm_statconvert_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Convert statistics from sqlite3 to redis\n\n"
				"Usage: rspamadm statconvert -c /etc/rspamd.conf [-r]\n"
				"Where options are:\n\n"
				"-c: config file to read data from\n"
				"-r: reset previous data instead of increasing values\n"
				"-e: set expire to that amount of seconds\n"
				"** Or specify options directly **\n"
				"--redis-host: output redis ip (in format ip:port)\n"
				"--redis-db: output redis database\n"
				"--redis-password: redis password\n"
				"--cache: sqlite3 file for learn cache\n"
				"--spam-db: sqlite3 input file for spam data\n"
				"--ham-db: sqlite3 input file for ham data\n"
				"--symbol-spam: symbol in redis for spam (e.g. BAYES_SPAM)\n"
				"--symbol-ham: symbol in redis for ham (e.g. BAYES_HAM)\n"
				;
	}
	else {
		help_str = "Convert statistics from sqlite3 to redis";
	}

	return help_str;
}

static void
rspamadm_statconvert (gint argc, gchar **argv, const struct rspamadm_command *cmd)
{
	GOptionContext *context;
	GError *error = NULL;
	ucl_object_t *obj;

	context = g_option_context_new (
			"statconvert - converts statistics from sqlite3 to redis");
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
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	g_option_context_free (context);

	if (config_file) {
		/* Load config file, assuming that it has all information required */
		struct ucl_parser *parser;

		parser = ucl_parser_new (0);
		rspamd_ucl_add_conf_variables (parser, ucl_vars);

		if (!ucl_parser_add_file (parser, config_file)) {
			msg_err ("ucl parser error: %s", ucl_parser_get_error (parser));
			ucl_parser_free (parser);

			exit (EXIT_FAILURE);
		}

		obj = ucl_parser_get_object (parser);
		ucl_parser_free (parser);
	}
	else {
		/* We need to get all information from the command line */
		ucl_object_t *classifier, *statfile_ham, *statfile_spam, *tmp, *redis;

		/* Check arguments sanity */
		if (spam_db == NULL) {
			msg_err ("No spam-db specified");
			exit (EXIT_FAILURE);
		}
		if (ham_db == NULL) {
			msg_err ("No ham-db specified");
			exit (EXIT_FAILURE);
		}
		if (redis_host == NULL) {
			msg_err ("No redis-host specified");
			exit (EXIT_FAILURE);
		}
		if (symbol_ham == NULL) {
			msg_err ("No symbol-ham specified");
			exit (EXIT_FAILURE);
		}
		if (symbol_spam == NULL) {
			msg_err ("No symbol-spam specified");
			exit (EXIT_FAILURE);
		}

		obj = ucl_object_typed_new (UCL_OBJECT);

		classifier = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, classifier, "classifier", 0, false);
		/* Now we need to create "bayes" key in it */
		tmp = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (classifier, tmp, "bayes", 0, false);
		classifier = tmp;
		ucl_object_insert_key (classifier, ucl_object_fromstring ("sqlite3"),
				"backend", 0, false);

		if (cache_db != NULL) {
			ucl_object_t *cache;

			cache = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (cache, ucl_object_fromstring ("sqlite3"),
					"type", 0, false);
			ucl_object_insert_key (cache, ucl_object_fromstring (cache_db),
					"file", 0, false);

			ucl_object_insert_key (classifier, cache, "cache", 0, false);
		}

		statfile_ham = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (statfile_ham, ucl_object_fromstring (symbol_ham),
				"symbol", 0, false);
		ucl_object_insert_key (statfile_ham, ucl_object_frombool (false),
				"spam", 0, false);
		ucl_object_insert_key (statfile_ham, ucl_object_fromstring (ham_db),
				"db", 0, false);

		statfile_spam = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (statfile_spam, ucl_object_fromstring (symbol_spam),
				"symbol", 0, false);
		ucl_object_insert_key (statfile_spam, ucl_object_frombool (true),
				"spam", 0, false);
		ucl_object_insert_key (statfile_spam, ucl_object_fromstring (spam_db),
				"db", 0, false);

		DL_APPEND (statfile_ham, statfile_spam);
		ucl_object_insert_key (classifier, statfile_ham,
				"statfile", 0, false);

		/* Deal with redis */

		redis = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, redis, "redis", 0, false);

		ucl_object_insert_key (redis, ucl_object_fromstring (redis_host),
				"servers", 0, false);

		if (redis_db) {
			ucl_object_insert_key (redis, ucl_object_fromstring (redis_db),
					"dbname", 0, false);
		}

		if (redis_password) {
			ucl_object_insert_key (redis, ucl_object_fromstring (redis_password),
					"password", 0, false);
		}
	}

	ucl_object_insert_key (obj, ucl_object_frombool (reset_previous),
			"reset_previous", 0, false);

	if (expire != 0) {
		ucl_object_insert_key (obj, ucl_object_fromdouble (expire),
				"expire", 0, false);
	}

	rspamadm_execute_lua_ucl_subr (argc,
			argv,
			obj,
			"stat_convert",
			TRUE);

	ucl_object_unref (obj);
}
