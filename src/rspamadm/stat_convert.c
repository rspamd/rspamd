/*
 * Copyright (c) 2016, Vsevolod Stakhov
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
#include "lua/lua_common.h"
#include "stat_convert.lua.h"

static gchar *source_db = NULL;
static gchar *redis_host = NULL;
static gchar *symbol = NULL;

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
		{"host", 'h', 0, G_OPTION_ARG_STRING, &redis_host,
				"Output redis ip (in format ip:port)", NULL},
		{"symbol", 's', 0, G_OPTION_ARG_STRING, &symbol,
				"Symbol in redis (e.g. BAYES_SPAM)", NULL},
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
				"-s: symbol in redis (e.g. BAYES_SPAM)\n";
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

	rspamadm_execute_lua_ucl_subr (L,
			argc,
			argv,
			obj,
			rspamadm_script_stat_convert);

	lua_close (L);
	ucl_object_unref (obj);
}
