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
#include "cryptobox.h"
#include "printf.h"
#include "http.h"
#include "addr.h"
#include "unix-std.h"
#include <event.h>
#include "libutil/util.h"

static gchar *control_path = RSPAMD_DBDIR "/rspamd.sock";
gboolean json = FALSE;
gboolean compact = FALSE;
gdouble timeout = 1.0;

static void rspamadm_control (gint argc, gchar **argv);
static const char *rspamadm_control_help (gboolean full_help);

struct rspamadm_command control_command = {
		.name = "control",
		.flags = 0,
		.help = rspamadm_control_help,
		.run = rspamadm_control
};

static GOptionEntry entries[] = {
		{"json", 'j', 0, G_OPTION_ARG_NONE, &json,
				"Output json",                    NULL},
		{"compact", 'c', 0, G_OPTION_ARG_NONE, &compact,
				"Output compacted", NULL},
		{"socket", 's', 0, G_OPTION_ARG_STRING, &control_path,
				"Use the following socket path", NULL},
		{"timeout", 't', 0, G_OPTION_ARG_DOUBLE, &timeout,
				"Set IO timeout (1s by default)", NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const char *
rspamadm_control_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Manage rspamd main control interface\n\n"
				"Usage: rspamadm control [-c] [-j] [-u] [-s path] command\n"
				"Where options are:\n\n"
				"-c: output compacted json\n"
				"-j: output linted json\n"
				"-u: output ucl\n"
				"-s: use the following socket instead of " RSPAMD_DBDIR "/rspamd.sock\n"
				"-t: set IO timeout (1.0 seconds default)\n"
				"--help: shows available options and commands\n\n"
				"Supported commands:\n"
				"stat - show statistics\n"
				"reload - reload workers dynamic data\n"
				"reresolve - resolve upstreams addresses\n";
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
	rspamd_http_connection_unref (conn);
}

static gint
rspamd_control_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct ucl_parser *parser;
	ucl_object_t *obj;
	rspamd_fstring_t *out;

	parser = ucl_parser_new (0);

	if (!ucl_parser_add_chunk (parser, msg->body->str, msg->body->len)) {
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
			rspamd_ucl_emit_fstring (obj, UCL_EMIT_CONFIG, &out);
		}

		rspamd_fprintf (stdout, "%V", out);

		rspamd_fstring_free (out);
		ucl_object_unref (obj);
		ucl_parser_free (parser);
	}

	return 0;
}

static void
rspamadm_control (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	struct event_base *ev_base;
	const gchar *cmd, *path = NULL;
	struct rspamd_http_connection *conn;
	struct rspamd_http_message *msg;
	rspamd_inet_addr_t *addr;
	struct timeval tv;
	gint sock;

	context = g_option_context_new (
			"control - manage rspamd main control interface");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (argc <= 1) {
		rspamd_fprintf (stderr, "command required\n");
		exit (1);
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
	else {
		rspamd_fprintf (stderr, "unknown command: %s\n", cmd);
		exit (1);
	}

	if (!rspamd_parse_inet_address (&addr, control_path, 0)) {
		rspamd_fprintf (stderr, "bad control path: %s\n", control_path);
		exit (1);
	}

	ev_base = event_init ();
	sock = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE);

	if (sock == -1) {
		rspamd_fprintf (stderr, "cannot connect to: %s\n", control_path);
		rspamd_inet_address_destroy (addr);
		exit (1);
	}

	conn = rspamd_http_connection_new (NULL, rspamd_control_error_handler,
			rspamd_control_finish_handler, RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT, NULL);
	msg = rspamd_http_new_message (HTTP_REQUEST);
	msg->url = rspamd_fstring_new_init (path, strlen (path));
	double_to_tv (timeout, &tv);

	rspamd_http_connection_write_message (conn, msg, NULL, NULL, NULL, sock,
			&tv, ev_base);

	event_base_loop (ev_base, 0);

	rspamd_http_connection_unref (conn);
	rspamd_inet_address_destroy (addr);
	close (sock);
}
