/*-
 * Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
 * Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
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

static gchar *source_db = NULL;
static gchar *redis_host = NULL;
static gchar *redis_db = NULL;
static gchar *redis_password = NULL;
static int64_t fuzzy_expiry = 0;

static void rspamadm_fuzzyconvert (gint argc, gchar **argv,
								   const struct rspamadm_command *cmd);
static const char *rspamadm_fuzzyconvert_help (gboolean full_help,
											   const struct rspamadm_command *cmd);

struct rspamadm_command fuzzyconvert_command = {
		.name = "fuzzyconvert",
		.flags = 0,
		.help = rspamadm_fuzzyconvert_help,
		.run = rspamadm_fuzzyconvert,
		.lua_subrs = NULL,
};

static GOptionEntry entries[] = {
		{"database", 'd', 0, G_OPTION_ARG_FILENAME, &source_db,
				"Input sqlite",      NULL},
		{"expiry", 'e', 0, G_OPTION_ARG_INT, &fuzzy_expiry,
				"Time in seconds after which hashes should be expired", NULL},
		{"host", 'h', 0, G_OPTION_ARG_STRING, &redis_host,
				"Output redis ip (in format ip:port)", NULL},
		{"dbname", 'D', 0, G_OPTION_ARG_STRING, &redis_db,
				"Database in redis (should be numeric)", NULL},
		{"password", 'p', 0, G_OPTION_ARG_STRING, &redis_password,
				"Password to connect to redis", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};


static const char *
rspamadm_fuzzyconvert_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Convert fuzzy hashes from sqlite3 to redis\n\n"
				"Usage: rspamadm fuzzyconvert -d <sqlite_db> -h <redis_ip>\n"
				"Where options are:\n\n"
				"-d: input sqlite\n"
				"-h: output redis ip (in format ip:port)\n"
				"-D: output redis database\n"
				"-p: redis password\n";
	}
	else {
		help_str = "Convert fuzzy hashes from sqlite3 to redis";
	}

	return help_str;
}

static void
rspamadm_fuzzyconvert (gint argc, gchar **argv, const struct rspamadm_command *cmd)
{
	GOptionContext *context;
	GError *error = NULL;
	ucl_object_t *obj;

	context = g_option_context_new (
			"fuzzyconvert - converts fuzzy hashes from sqlite3 to redis");
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

	if (!source_db) {
		rspamd_fprintf (stderr, "source db is missing\n");
		exit (EXIT_FAILURE);
	}
	if (!redis_host) {
		rspamd_fprintf (stderr, "redis host is missing\n");
		exit (EXIT_FAILURE);
	}
	if (!fuzzy_expiry) {
		rspamd_fprintf (stderr, "expiry is missing\n");
		exit (EXIT_FAILURE);
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (source_db),
			"source_db", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (redis_host),
			"redis_host", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (fuzzy_expiry),
			"expiry", 0, false);

	if (redis_password) {
		ucl_object_insert_key (obj, ucl_object_fromstring (redis_password),
				"redis_password", 0, false);
	}

	if (redis_db) {
		ucl_object_insert_key (obj, ucl_object_fromstring (redis_db),
				"redis_db", 0, false);
	}

	rspamadm_execute_lua_ucl_subr (argc,
			argv,
			obj,
			"fuzzy_convert",
			TRUE);

	ucl_object_unref (obj);
}
