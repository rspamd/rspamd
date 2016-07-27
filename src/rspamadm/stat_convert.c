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
#include "stat_convert.lua.h"

static gchar *source_db = NULL;
static gchar *redis_host = NULL;
static gchar *symbol = NULL;
static gchar *cache_db = NULL;
static gchar *redis_db = NULL;
static gchar *redis_password = NULL;
static gboolean reset_previous = FALSE;

static void rspamadm_statconvert (gint argc, gchar **argv);
static const char *rspamadm_statconvert_help (gboolean full_help);

struct rspamadm_command statconvert_command = {
		.name = "statconvert",
		.flags = 0,
		.help = rspamadm_statconvert_help,
		.run = rspamadm_statconvert
};

static GOptionEntry entries[] = {
		{"database", 'd', 0, G_OPTION_ARG_FILENAME, &source_db,
				"Input sqlite",      NULL},
		{"cache", 'c', 0, G_OPTION_ARG_FILENAME, &cache_db,
				"Input learn cache",      NULL},
		{"host", 'h', 0, G_OPTION_ARG_STRING, &redis_host,
				"Output redis ip (in format ip:port)", NULL},
		{"symbol", 's', 0, G_OPTION_ARG_STRING, &symbol,
				"Symbol in redis (e.g. BAYES_SPAM)", NULL},
		{"dbname", 'D', 0, G_OPTION_ARG_STRING, &redis_db,
				"Database in redis (should be numeric)", NULL},
		{"password", 'p', 0, G_OPTION_ARG_STRING, &redis_password,
				"Password to connect to redis", NULL},
		{"reset", 'r', 0, G_OPTION_ARG_NONE, &reset_previous,
				"Reset previous data instead of appending values", NULL},
		{NULL,     0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};


static const char *
rspamadm_statconvert_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Convert statistics from sqlite3 to redis\n\n"
				"Usage: rspamadm statconvert -d <sqlite_db> -h <redis_ip> -s <symbol>\n"
				"Where options are:\n\n"
				"-d: input sqlite\n"
				"-h: output redis ip (in format ip:port)\n"
				"-s: symbol in redis (e.g. BAYES_SPAM)\n"
				"-c: also convert data from the learn cache\n"
				"-D: output redis database\n"
				"-p: redis password\n"
				"-r: reset previous data instead of increasing values\n";
	}
	else {
		help_str = "Convert statistics from sqlite3 to redis";
	}

	return help_str;
}

static void
rspamadm_statconvert (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	lua_State *L;
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
		exit (1);
	}

	if (!source_db) {
		rspamd_fprintf (stderr, "source db is missing\n");
		exit (1);
	}
	if (!redis_host) {
		rspamd_fprintf (stderr, "redis host is missing\n");
		exit (1);
	}
	if (!symbol) {
		rspamd_fprintf (stderr, "symbol is missing\n");
		exit (1);
	}

	L = rspamd_lua_init ();

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (source_db),
			"source_db", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (redis_host),
			"redis_host", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (symbol),
			"symbol", 0, false);
	ucl_object_insert_key (obj, ucl_object_frombool (reset_previous),
			"reset_previous", 0, false);

	if (cache_db != NULL) {
		ucl_object_insert_key (obj, ucl_object_fromstring (cache_db),
				"cache_db", 0, false);
	}

	if (redis_password) {
		ucl_object_insert_key (obj, ucl_object_fromstring (redis_password),
				"redis_password", 0, false);
	}

	if (redis_db) {
		ucl_object_insert_key (obj, ucl_object_fromstring (redis_db),
				"redis_db", 0, false);
	}

	rspamadm_execute_lua_ucl_subr (L,
			argc,
			argv,
			obj,
			rspamadm_script_stat_convert);

	lua_close (L);
	ucl_object_unref (obj);
}
