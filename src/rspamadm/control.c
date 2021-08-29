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
#include "cryptobox.h"
#include "printf.h"
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "addr.h"
#include "unix-std.h"
#include "contrib/libev/ev.h"
#include "libutil/util.h"
#include "lua/lua_common.h"

static gchar *control_path = RSPAMD_DBDIR "/rspamd.sock";
static gboolean json = FALSE;
static gboolean ucl = TRUE;
static gboolean compact = FALSE;
static gdouble timeout = 1.0;

static void rspamadm_control (gint argc, gchar **argv,
							  const struct rspamadm_command *cmd);
static const char *rspamadm_control_help (gboolean full_help,
										  const struct rspamadm_command *cmd);

struct rspamadm_command control_command = {
		.name = "control",
		.flags = 0,
		.help = rspamadm_control_help,
		.run = rspamadm_control,
		.lua_subrs = NULL,
};

struct rspamadm_control_cbdata {
	const gchar *path;
	gint argc;
	gchar **argv;
};

static GOptionEntry entries[] = {
		{"json", 'j', 0, G_OPTION_ARG_NONE, &json,
				"Output json",                    NULL},
		{"compact", 'c', 0, G_OPTION_ARG_NONE, &compact,
				"Output compacted", NULL},
		{"ucl", 'u', 0, G_OPTION_ARG_NONE, &ucl,
				"Output ucl (default)", NULL},
		{"socket", 's', 0, G_OPTION_ARG_STRING, &control_path,
				"Use the following socket path", NULL},
		{"timeout", 't', 0, G_OPTION_ARG_DOUBLE, &timeout,
				"Set IO timeout (1s by default)", NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_control_help (gboolean full_help, const struct rspamadm_command *cmd)
{
	const char *help_str;

	if (full_help) {
		help_str = "Manage rspamd main control interface\n\n"
				"Usage: rspamadm control [-c] [-j] [-u] [-s path] command\n"
				"Where options are:\n\n"
				"-c: output compacted json\n"
				"-j: output linted json\n"
				"-u: output ucl (default)\n"
				"-s: use the following socket instead of " RSPAMD_DBDIR "/rspamd.sock\n"
				"-t: set IO timeout (1.0 seconds default)\n"
				"--help: shows available options and commands\n\n"
				"Supported commands:\n"
				"stat - show statistics\n"
				"reload - reload workers dynamic data\n"
				"reresolve - resolve upstreams addresses\n"
				"recompile - recompile hyperscan regexes\n"
				"fuzzystat - show fuzzy statistics\n"
				"fuzzysync - immediately sync fuzzy database to storage\n";
	}
	else {
		help_str = "Manage rspamd main control interface";
	}

	return help_str;
}

static void
rspamd_control_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	rspamd_fprintf (stderr, "Cannot make HTTP request: %e\n", err);
	ev_break (rspamd_main->event_loop, EVBREAK_ALL);
}

static gint
rspamd_control_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct ucl_parser *parser;
	ucl_object_t *obj;
	rspamd_fstring_t *out;
	const gchar *body;
	gsize body_len;
	struct rspamadm_control_cbdata *cbdata = conn->ud;

	body = rspamd_http_message_get_body (msg, &body_len);
	parser = ucl_parser_new (0);

	if (!body || !ucl_parser_add_chunk (parser, body, body_len)) {
		rspamd_fprintf (stderr, "cannot parse server's reply: %s\n",
				ucl_parser_get_error (parser));
		ucl_parser_free (parser);
	}
	else {
		obj = ucl_parser_get_object (parser);
		out = rspamd_fstring_new ();

		if (json) {
			rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON, &out);
		}
		else if (compact) {
			rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &out);
		}
		else {
			if (strcmp (cbdata->path, "/fuzzystat") == 0) {
				rspamadm_execute_lua_ucl_subr (cbdata->argc - 1,
						&cbdata->argv[1],
						obj,
						"fuzzy_stat",
						TRUE);

				rspamd_fstring_free (out);
				ucl_object_unref (obj);
				ucl_parser_free (parser);
				goto end;
			}
			else {
				rspamd_ucl_emit_fstring (obj, UCL_EMIT_CONFIG, &out);
			}
		}

		rspamd_fprintf (stdout, "%V", out);

		rspamd_fstring_free (out);
		ucl_object_unref (obj);
		ucl_parser_free (parser);
	}

end:
	ev_break (rspamd_main->event_loop, EVBREAK_ALL);

	return 0;
}

static void
rspamadm_control (gint argc, gchar **argv, const struct rspamadm_command *_cmd)
{
	GOptionContext *context;
	GError *error = NULL;
	const gchar *cmd, *path = NULL;
	struct rspamd_http_connection *conn;
	struct rspamd_http_message *msg;
	rspamd_inet_addr_t *addr;
	static struct rspamadm_control_cbdata cbdata;

	context = g_option_context_new (
			"control - manage rspamd main control interface");
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

	if (argc <= 1) {
		rspamd_fprintf (stderr, "command required\n");
		exit (EXIT_FAILURE);
	}

	cmd = argv[1];

	if (g_ascii_strcasecmp (cmd, "stat") == 0) {
		path = "/stat";
	}
	else if (g_ascii_strcasecmp (cmd, "reload") == 0) {
		path = "/reload";
	}
	else if (g_ascii_strcasecmp (cmd, "reresolve") == 0) {
		path = "/reresolve";
	}
	else if (g_ascii_strcasecmp (cmd, "recompile") == 0) {
		path = "/recompile";
	}
	else if (g_ascii_strcasecmp (cmd, "fuzzystat") == 0 ||
			g_ascii_strcasecmp (cmd, "fuzzy_stat") == 0) {
		path = "/fuzzystat";
	}
	else if (g_ascii_strcasecmp (cmd, "fuzzysync") == 0 ||
			g_ascii_strcasecmp (cmd, "fuzzy_sync") == 0) {
		path = "/fuzzysync";
	}
	else {
		rspamd_fprintf (stderr, "unknown command: %s\n", cmd);
		exit (EXIT_FAILURE);
	}

	if (!rspamd_parse_inet_address (&addr,
			control_path, strlen (control_path), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		rspamd_fprintf (stderr, "bad control path: %s\n", control_path);
		exit (EXIT_FAILURE);
	}


	conn = rspamd_http_connection_new_client (
			rspamd_main->http_ctx, /* Default context */
			NULL,
			rspamd_control_error_handler,
			rspamd_control_finish_handler,
			RSPAMD_HTTP_CLIENT_SIMPLE,
			addr);

	if (!conn) {
		rspamd_fprintf (stderr, "cannot open connection to %s: %s\n",
				control_path, strerror (errno));
		exit (-errno);
	}

	msg = rspamd_http_new_message (HTTP_REQUEST);
	msg->url = rspamd_fstring_new_init (path, strlen (path));

	cbdata.argc = argc;
	cbdata.argv = argv;
	cbdata.path = path;

	rspamd_http_connection_write_message (conn, msg, NULL, NULL, &cbdata,
			timeout);

	ev_loop (rspamd_main->event_loop, 0);

	rspamd_http_connection_unref (conn);
	rspamd_inet_address_free (addr);
}
