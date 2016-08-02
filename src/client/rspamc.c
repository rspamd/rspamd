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
#include "libutil/util.h"
#include "libutil/http.h"
#include "libutil/http_private.h"
#include "rspamdclient.h"
#include "utlist.h"
#include "unix-std.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#define DEFAULT_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

static gchar *connect_str = "localhost";
static gchar *password = NULL;
static gchar *ip = NULL;
static gchar *from = NULL;
static gchar *deliver_to = NULL;
static gchar **rcpts = NULL;
static gchar *user = NULL;
static gchar *helo = NULL;
static gchar *hostname = NULL;
static gchar *classifier = NULL;
static gchar *local_addr = NULL;
static gchar *execute = NULL;
static gchar *sort = NULL;
static gchar **http_headers = NULL;
static gint weight = 0;
static gint flag = 0;
static gchar *fuzzy_symbol = NULL;
static gint max_requests = 8;
static gdouble timeout = 10.0;
static gboolean pass_all;
static gboolean tty = FALSE;
static gboolean verbose = FALSE;
static gboolean print_commands = FALSE;
static gboolean json = FALSE;
static gboolean compact = FALSE;
static gboolean headers = FALSE;
static gboolean raw = FALSE;
static gboolean extended_urls = FALSE;
static gboolean mime_output = FALSE;
static gboolean empty_input = FALSE;
static gchar *key = NULL;
static GList *children;

#define ADD_CLIENT_HEADER(o, n, v) do { \
    struct rspamd_http_client_header *nh; \
    nh = g_malloc (sizeof (*nh)); \
    nh->name = (n); \
    nh->value = (v); \
    g_queue_push_tail ((o), nh); \
} while (0)

static gboolean rspamc_password_callback (const gchar *option_name,
		const gchar *value,
		gpointer data,
		GError **error);

static GOptionEntry entries[] =
{
	{ "connect", 'h', 0, G_OPTION_ARG_STRING, &connect_str,
	  "Specify host and port", NULL },
	{ "password", 'P', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
	  &rspamc_password_callback, "Specify control password", NULL },
	{ "classifier", 'c', 0, G_OPTION_ARG_STRING, &classifier,
	  "Classifier to learn spam or ham", NULL },
	{ "weight", 'w', 0, G_OPTION_ARG_INT, &weight,
	  "Weight for fuzzy operations", NULL },
	{ "flag", 'f', 0, G_OPTION_ARG_INT, &flag, "Flag for fuzzy operations",
	  NULL },
	{ "pass-all", 'p', 0, G_OPTION_ARG_NONE, &pass_all, "Pass all filters",
	  NULL },
	{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "More verbose output",
	  NULL },
	{ "ip", 'i', 0, G_OPTION_ARG_STRING, &ip,
	  "Emulate that message was received from specified ip address",
	  NULL },
	{ "user", 'u', 0, G_OPTION_ARG_STRING, &user,
	  "Emulate that message was received from specified authenticated user", NULL },
	{ "deliver", 'd', 0, G_OPTION_ARG_STRING, &deliver_to,
	  "Emulate that message is delivered to specified user (for LDA/statistics)", NULL },
	{ "from", 'F', 0, G_OPTION_ARG_STRING, &from,
	  "Emulate that message has specified SMTP FROM address", NULL },
	{ "rcpt", 'r', 0, G_OPTION_ARG_STRING_ARRAY, &rcpts,
	  "Emulate that message has specified SMTP RCPT address", NULL },
	{ "helo", 0, 0, G_OPTION_ARG_STRING, &helo,
	  "Imitate SMTP HELO passing from MTA", NULL },
	{ "hostname", 0, 0, G_OPTION_ARG_STRING, &hostname,
	  "Imitate hostname passing from MTA", NULL },
	{ "timeout", 't', 0, G_OPTION_ARG_DOUBLE, &timeout,
	  "Time in seconds to wait for a reply", NULL },
	{ "bind", 'b', 0, G_OPTION_ARG_STRING, &local_addr,
	  "Bind to specified ip address", NULL },
	{ "commands", 0, 0, G_OPTION_ARG_NONE, &print_commands,
	  "List available commands", NULL },
	{ "json", 'j', 0, G_OPTION_ARG_NONE, &json, "Output json reply", NULL },
	{ "compact", '\0', 0, G_OPTION_ARG_NONE, &compact, "Output compact json reply", NULL},
	{ "headers", 0, 0, G_OPTION_ARG_NONE, &headers, "Output HTTP headers",
	  NULL },
	{ "raw", 0, 0, G_OPTION_ARG_NONE, &raw, "Output raw reply from rspamd",
	  NULL },
	{ "ucl", 0, 0, G_OPTION_ARG_NONE, &raw, "Output ucl reply from rspamd",
	  NULL },
	{ "max-requests", 'n', 0, G_OPTION_ARG_INT, &max_requests,
	  "Maximum count of parallel requests to rspamd", NULL },
	{ "extended-urls", 0, 0, G_OPTION_ARG_NONE, &extended_urls,
	   "Output urls in extended format", NULL },
	{ "key", 0, 0, G_OPTION_ARG_STRING, &key,
	   "Use specified pubkey to encrypt request", NULL },
	{ "exec", 'e', 0, G_OPTION_ARG_STRING, &execute,
	   "Execute the specified command and pass output to it", NULL },
	{ "mime", 'e', 0, G_OPTION_ARG_NONE, &mime_output,
	   "Write mime body of message with headers instead of just a scan's result", NULL },
	{"header", 0, 0, G_OPTION_ARG_STRING_ARRAY, &http_headers,
		"Add custom HTTP header to query (can be repeated)", NULL},
	{"sort", 0, 0, G_OPTION_ARG_STRING, &sort,
		"Sort output in a specific order (name, weight, time)", NULL},
	{ "empty", 'E', 0, G_OPTION_ARG_NONE, &empty_input,
	   "Allow empty input instead of reading from stdin", NULL },
	{ "fuzzy-symbol", 'S', 0, G_OPTION_ARG_STRING, &fuzzy_symbol,
	   "Learn the specified fuzzy symbol", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

/* Copy to avoid linking with librspamdserver */
enum rspamd_metric_action {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION,
	METRIC_ACTION_MAX
};

static void rspamc_symbols_output (FILE *out, ucl_object_t *obj);
static void rspamc_uptime_output (FILE *out, ucl_object_t *obj);
static void rspamc_counters_output (FILE *out, ucl_object_t *obj);
static void rspamc_stat_output (FILE *out, ucl_object_t *obj);

enum rspamc_command_type {
	RSPAMC_COMMAND_UNKNOWN = 0,
	RSPAMC_COMMAND_SYMBOLS,
	RSPAMC_COMMAND_LEARN_SPAM,
	RSPAMC_COMMAND_LEARN_HAM,
	RSPAMC_COMMAND_FUZZY_ADD,
	RSPAMC_COMMAND_FUZZY_DEL,
	RSPAMC_COMMAND_STAT,
	RSPAMC_COMMAND_STAT_RESET,
	RSPAMC_COMMAND_COUNTERS,
	RSPAMC_COMMAND_UPTIME,
	RSPAMC_COMMAND_ADD_SYMBOL,
	RSPAMC_COMMAND_ADD_ACTION
};

struct rspamc_command {
	enum rspamc_command_type cmd;
	const char *name;
	const char *description;
	const char *path;
	gboolean is_controller;
	gboolean is_privileged;
	gboolean need_input;
	void (*command_output_func)(FILE *, ucl_object_t *obj);
} rspamc_commands[] = {
	{
		.cmd = RSPAMC_COMMAND_SYMBOLS,
		.name = "symbols",
		.path = "check",
		.description = "scan message and show symbols (default command)",
		.is_controller = FALSE,
		.is_privileged = FALSE,
		.need_input = TRUE,
		.command_output_func = rspamc_symbols_output
	},
	{
		.cmd = RSPAMC_COMMAND_LEARN_SPAM,
		.name = "learn_spam",
		.path = "learnspam",
		.description = "learn message as spam",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_LEARN_HAM,
		.name = "learn_ham",
		.path = "learnham",
		.description = "learn message as ham",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_FUZZY_ADD,
		.name = "fuzzy_add",
		.path = "fuzzyadd",
		.description =
			"add message to fuzzy storage (check -f and -w options for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_FUZZY_DEL,
		.name = "fuzzy_del",
		.path = "fuzzydel",
		.description =
			"delete message from fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_STAT,
		.name = "stat",
		.path = "stat",
		.description = "show rspamd statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output,
	},
	{
		.cmd = RSPAMC_COMMAND_STAT_RESET,
		.name = "stat_reset",
		.path = "statreset",
		.description = "show and reset rspamd statistics (useful for graphs)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output
	},
	{
		.cmd = RSPAMC_COMMAND_COUNTERS,
		.name = "counters",
		.path = "counters",
		.description = "display rspamd symbols statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_counters_output
	},
	{
		.cmd = RSPAMC_COMMAND_UPTIME,
		.name = "uptime",
		.path = "auth",
		.description = "show rspamd uptime",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_uptime_output
	},
	{
		.cmd = RSPAMC_COMMAND_ADD_SYMBOL,
		.name = "add_symbol",
		.path = "addsymbol",
		.description = "add or modify symbol settings in rspamd",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_ADD_ACTION,
		.name = "add_action",
		.path = "addaction",
		.description = "add or modify action settings",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = NULL
	}
};

struct rspamc_callback_data {
	struct rspamc_command *cmd;
	gchar *filename;
	gdouble start;
};

gboolean
rspamc_password_callback (const gchar *option_name,
		const gchar *value,
		gpointer data,
		GError **error)
{
	guint plen = 8192;

	if (value != NULL) {
		password = g_strdup (value);
	}
	else {
		/* Read password from console */
		password = g_malloc0 (plen);
		plen = rspamd_read_passphrase (password, plen, 0, NULL);
	}

	if (plen == 0) {
		rspamd_fprintf (stderr, "Invalid password\n");
		exit (EXIT_FAILURE);
	}

	return TRUE;
}

/*
 * Parse command line
 */
static void
read_cmd_line (gint *argc, gchar ***argv)
{
	GError *error = NULL;
	GOptionContext *context;

	/* Prepare parser */
	context = g_option_context_new ("- run rspamc client");
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd client version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);

	/* Parse options */
	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (EXIT_FAILURE);
	}

	if (json || compact) {
		raw = TRUE;
	}
	/* Argc and argv are shifted after this function */
}

/*
 * Check rspamc command from string (used for arguments parsing)
 */
static struct rspamc_command *
check_rspamc_command (const gchar *cmd)
{
	enum rspamc_command_type ct = 0;
	guint i;

	if (g_ascii_strcasecmp (cmd, "SYMBOLS") == 0 ||
		g_ascii_strcasecmp (cmd, "CHECK") == 0 ||
		g_ascii_strcasecmp (cmd, "REPORT") == 0) {
		/* These all are symbols, don't use other commands */
		ct = RSPAMC_COMMAND_SYMBOLS;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_SPAM") == 0) {
		ct = RSPAMC_COMMAND_LEARN_SPAM;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_HAM") == 0) {
		ct = RSPAMC_COMMAND_LEARN_HAM;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_ADD") == 0) {
		ct = RSPAMC_COMMAND_FUZZY_ADD;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_DEL") == 0) {
		ct = RSPAMC_COMMAND_FUZZY_DEL;
	}
	else if (g_ascii_strcasecmp (cmd, "STAT") == 0) {
		ct = RSPAMC_COMMAND_STAT;
	}
	else if (g_ascii_strcasecmp (cmd, "STAT_RESET") == 0) {
		ct = RSPAMC_COMMAND_STAT_RESET;
	}
	else if (g_ascii_strcasecmp (cmd, "COUNTERS") == 0) {
		ct = RSPAMC_COMMAND_COUNTERS;
	}
	else if (g_ascii_strcasecmp (cmd, "UPTIME") == 0) {
		ct = RSPAMC_COMMAND_UPTIME;
	}
	else if (g_ascii_strcasecmp (cmd, "ADD_SYMBOL") == 0) {
		ct = RSPAMC_COMMAND_ADD_SYMBOL;
	}
	else if (g_ascii_strcasecmp (cmd, "ADD_ACTION") == 0) {
		ct = RSPAMC_COMMAND_ADD_ACTION;
	}

	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		if (rspamc_commands[i].cmd == ct) {
			return &rspamc_commands[i];
		}
	}

	return NULL;
}

static void
print_commands_list (void)
{
	guint i;

	rspamd_fprintf (stdout, "Rspamc commands summary:\n");
	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		rspamd_fprintf (stdout,
			"  %10s (%7s%1s)\t%s\n",
			rspamc_commands[i].name,
			rspamc_commands[i].is_controller ? "control" : "normal",
			rspamc_commands[i].is_privileged ? "*" : "",
			rspamc_commands[i].description);
	}
	rspamd_fprintf (stdout,
		"\n* is for privileged commands that may need password (see -P option)\n");
	rspamd_fprintf (stdout,
		"control commands use port 11334 while normal use 11333 by default (see -h option)\n");
}

static void
add_options (GQueue *opts)
{
	GString *numbuf;
	gchar **hdr, **rcpt;

	if (ip != NULL) {
		ADD_CLIENT_HEADER (opts, "Ip", ip);
	}
	if (from != NULL) {
		ADD_CLIENT_HEADER (opts, "From", from);
	}
	if (user != NULL) {
		ADD_CLIENT_HEADER (opts, "User", user);
	}
	if (rcpts != NULL) {

		for (rcpt = rcpts; *rcpt != NULL; rcpt ++) {
			ADD_CLIENT_HEADER (opts, "Rcpt", *rcpt);
		}
	}
	if (deliver_to != NULL) {
		ADD_CLIENT_HEADER (opts, "Deliver-To", deliver_to);
	}
	if (helo != NULL) {
		ADD_CLIENT_HEADER (opts, "Helo", helo);
	}
	if (hostname != NULL) {
		ADD_CLIENT_HEADER (opts, "Hostname", hostname);
	}
	if (password != NULL) {
		ADD_CLIENT_HEADER (opts, "Password", password);
	}
	if (pass_all) {
		ADD_CLIENT_HEADER (opts, "Pass", "all");
	}
	if (classifier) {
		ADD_CLIENT_HEADER (opts, "Classifier", classifier);
	}
	if (weight != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", weight);
		ADD_CLIENT_HEADER (opts, "Weight", numbuf->str);
	}
	if (fuzzy_symbol != NULL) {
		ADD_CLIENT_HEADER (opts, "Symbol", fuzzy_symbol);
	}
	if (flag != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", flag);
		ADD_CLIENT_HEADER (opts, "Flag", numbuf->str);
	}
	if (extended_urls) {
		ADD_CLIENT_HEADER (opts, "URL-Format", "extended");
	}

	hdr = http_headers;

	while (hdr != NULL && *hdr != NULL) {
		gchar **kv = g_strsplit_set (*hdr, ":=", 2);

		if (kv == NULL || kv[1] == NULL) {
			ADD_CLIENT_HEADER (opts, *hdr, "");

			if (kv) {
				g_strfreev (kv);
			}
		}
		else {
			ADD_CLIENT_HEADER (opts, kv[0], kv[1]);
		}

		hdr ++;
	}
}

static void
rspamc_symbol_output (FILE *out, const ucl_object_t *obj)
{
	const ucl_object_t *val, *cur;
	ucl_object_iter_t it = NULL;
	gboolean first = TRUE;

	rspamd_fprintf (out, "Symbol: %s ", ucl_object_key (obj));
	val = ucl_object_lookup (obj, "score");

	if (val != NULL) {
		rspamd_fprintf (out, "(%.2f)", ucl_object_todouble (val));
	}
	val = ucl_object_lookup (obj, "options");
	if (val != NULL && val->type == UCL_ARRAY) {
		rspamd_fprintf (out, "[");

		while ((cur = ucl_object_iterate (val, &it, TRUE)) != NULL) {
			if (first) {
				rspamd_fprintf (out, "%s", ucl_object_tostring (cur));
				first = FALSE;
			}
			else {
				rspamd_fprintf (out, ", %s", ucl_object_tostring (cur));
			}
		}
		rspamd_fprintf (out, "]");
	}
	rspamd_fprintf (out, "\n");
}

static gint
rspamc_symbols_sort_func (gconstpointer a, gconstpointer b)
{
	ucl_object_t * const *ua = a, * const *ub = b;

	return strcmp (ucl_object_key (*ua), ucl_object_key (*ub));
}

static void
rspamc_metric_output (FILE *out, const ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	gdouble score = 0, required_score = 0;
	gint got_scores = 0;
	GPtrArray *sym_ptr;
	guint i;

	sym_ptr = g_ptr_array_new ();
	rspamd_fprintf (out, "[Metric: %s]\n", ucl_object_key (obj));

	while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
		if (g_ascii_strcasecmp (ucl_object_key (cur), "is_spam") == 0) {
			rspamd_fprintf (out, "Spam: %s\n", ucl_object_toboolean (cur) ?
				"true" : "false");
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "score") == 0) {
			score = ucl_object_todouble (cur);
			got_scores++;
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur),
			"required_score") == 0) {
			required_score = ucl_object_todouble (cur);
			got_scores++;
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "action") == 0) {
			rspamd_fprintf (out, "Action: %s\n", ucl_object_tostring (cur));
		}
		else if (cur->type == UCL_OBJECT) {
			g_ptr_array_add (sym_ptr, (void *)cur);
		}
		if (got_scores == 2) {
			rspamd_fprintf (out,
				"Score: %.2f / %.2f\n",
				score,
				required_score);
			got_scores = 0;
		}
	}

	g_ptr_array_sort (sym_ptr, rspamc_symbols_sort_func);

	for (i = 0; i < sym_ptr->len; i ++) {
		cur = (const ucl_object_t *)g_ptr_array_index (sym_ptr, i);
		rspamc_symbol_output (out, cur);
	}

	g_ptr_array_free (sym_ptr, TRUE);
}

static void
rspamc_symbols_output (FILE *out, ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL, mit = NULL;
	const ucl_object_t *cur, *cmesg;
	gchar *emitted;

	while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
		if (g_ascii_strcasecmp (ucl_object_key (cur), "message-id") == 0) {
			rspamd_fprintf (out, "Message-ID: %s\n", ucl_object_tostring (
					cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "queue-id") == 0) {
			rspamd_fprintf (out, "Queue-ID: %s\n",
				ucl_object_tostring (cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "urls") == 0) {
			if (!extended_urls || compact) {
				emitted = ucl_object_emit (cur, UCL_EMIT_JSON_COMPACT);
			}
			else {
				emitted = ucl_object_emit (cur, UCL_EMIT_JSON);
			}
			rspamd_fprintf (out, "Urls: %s\n", emitted);
			free (emitted);
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "emails") == 0) {
			emitted = ucl_object_emit (cur, UCL_EMIT_JSON_COMPACT);
			rspamd_fprintf (out, "Emails: %s\n", emitted);
			free (emitted);
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "error") == 0) {
			rspamd_fprintf (out, "Scan error: %s\n", ucl_object_tostring (
					cur));
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "messages") == 0) {
			if (cur->type == UCL_ARRAY) {
				mit = NULL;
				while ((cmesg = ucl_object_iterate (cur, &mit, true)) != NULL) {
					rspamd_fprintf (out, "Message: %s\n",
							ucl_object_tostring (cmesg));
				}
			}
		}
		else if (g_ascii_strcasecmp (ucl_object_key (cur), "dkim-signature") == 0) {
			rspamd_fprintf (out, "DKIM-Signature: %s\n", ucl_object_tostring (
					cur));
		}
		else if (cur->type == UCL_OBJECT) {
			/* Parse metric */
			rspamc_metric_output (out, cur);
		}
	}
}

static void
rspamc_uptime_output (FILE *out, ucl_object_t *obj)
{
	const ucl_object_t *elt;
	int64_t seconds, days, hours, minutes;

	elt = ucl_object_lookup (obj, "version");
	if (elt != NULL) {
		rspamd_fprintf (out, "Rspamd version: %s\n", ucl_object_tostring (
				elt));
	}

	elt = ucl_object_lookup (obj, "uptime");
	if (elt != NULL) {
		rspamd_printf ("Uptime: ");
		seconds = ucl_object_toint (elt);
		if (seconds >= 2 * 3600) {
			days = seconds / 86400;
			hours = seconds / 3600 - days * 24;
			minutes = seconds / 60 - hours * 60 - days * 1440;
			rspamd_printf ("%L day%s %L hour%s %L minute%s\n", days,
				days > 1 ? "s" : "", hours, hours > 1 ? "s" : "",
				minutes, minutes > 1 ? "s" : "");
		}
		/* If uptime is less than 1 minute print only seconds */
		else if (seconds / 60 == 0) {
			rspamd_printf ("%L second%s\n", seconds,
				(gint)seconds > 1 ? "s" : "");
		}
		/* Else print the minutes and seconds. */
		else {
			hours = seconds / 3600;
			minutes = seconds / 60 - hours * 60;
			seconds -= hours * 3600 + minutes * 60;
			rspamd_printf ("%L hour %L minute%s %L second%s\n", hours,
				minutes, minutes > 1 ? "s" : "",
				seconds, seconds > 1 ? "s" : "");
		}
	}
}

static gint
rspamc_counters_sort (const ucl_object_t **o1, const ucl_object_t **o2)
{
	gint order1 = 0, order2 = 0, c;
	const ucl_object_t *elt1, *elt2;
	gboolean inverse = FALSE;
	gchar **args;

	if (sort != NULL) {
		args = g_strsplit_set (sort, ":", 2);
		if (args && args[0]) {
			if (args[1] && g_ascii_strcasecmp (args[1], "desc") == 0) {
				inverse = TRUE;
			}

			if (g_ascii_strcasecmp (args[0], "name") == 0) {
				elt1 = ucl_object_lookup (*o1, "symbol");
				elt2 = ucl_object_lookup (*o2, "symbol");

				if (elt1 && elt2) {
					c = strcmp (ucl_object_tostring (elt1),
							ucl_object_tostring (elt2));

					order1 = c > 0 ? 1 : 0;
					order2 = c < 0 ? 1 : 0;
				}
			}
			else if (g_ascii_strcasecmp (args[0], "weight") == 0) {
				elt1 = ucl_object_lookup (*o1, "weight");
				elt2 = ucl_object_lookup (*o2, "weight");

				if (elt1 && elt2) {
					order1 = ucl_object_todouble (elt1) * 1000.0;
					order2 = ucl_object_todouble (elt2) * 1000.0;
				}
			}
			else if (g_ascii_strcasecmp (args[0], "frequency") == 0) {
				elt1 = ucl_object_lookup (*o1, "frequency");
				elt2 = ucl_object_lookup (*o2, "frequency");

				if (elt1 && elt2) {
					order1 = ucl_object_toint (elt1);
					order2 = ucl_object_toint (elt2);
				}
			}
			else if (g_ascii_strcasecmp (args[0], "time") == 0) {
				elt1 = ucl_object_lookup (*o1, "time");
				elt2 = ucl_object_lookup (*o2, "time");

				if (elt1 && elt2) {
					order1 = ucl_object_todouble (elt1) * 1000000;
					order2 = ucl_object_todouble (elt2) * 1000000;
				}
			}

			g_strfreev (args);
		}
	}

	return (inverse ? (order2 - order1) : (order1 - order2));
}

static void
rspamc_counters_output (FILE *out, ucl_object_t *obj)
{
	const ucl_object_t *cur, *sym, *weight, *freq, *tim;
	ucl_object_iter_t iter = NULL;
	gchar fmt_buf[64], dash_buf[82];
	gint l, max_len = INT_MIN, i;

	if (obj->type != UCL_ARRAY) {
		rspamd_printf ("Bad output\n");
		return;
	}

	/* Sort symbols by their order */
	if (sort != NULL) {
		ucl_object_array_sort (obj, rspamc_counters_sort);
	}

	/* Find maximum width of symbol's name */
	while ((cur = ucl_object_iterate (obj, &iter, true)) != NULL) {
		sym = ucl_object_lookup (cur, "symbol");
		if (sym != NULL) {
			l = sym->len;
			if (l > max_len) {
				max_len = MIN (40, l);
			}
		}
	}

	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3s | %%%ds | %%6s | %%9s | %%9s |\n", max_len);
	memset (dash_buf, '-', 40 + max_len);
	dash_buf[40 + max_len] = '\0';

	printf ("Symbols cache\n");
	printf (" %s \n", dash_buf);
	if (tty) {
		printf ("\033[1m");
	}
	printf (fmt_buf, "Pri", "Symbol", "Weight", "Frequency", "Avg. time");
	if (tty) {
		printf ("\033[0m");
	}
	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3d | %%%ds | %%6.1f | %%9d | %%9.3f |\n", max_len);

	iter = NULL;
	i = 0;
	while ((cur = ucl_object_iterate (obj, &iter, true)) != NULL) {
		printf (" %s \n", dash_buf);
		sym = ucl_object_lookup (cur, "symbol");
		weight = ucl_object_lookup (cur, "weight");
		freq = ucl_object_lookup (cur, "frequency");
		tim = ucl_object_lookup (cur, "time");
		if (sym && weight && freq && tim) {
			printf (fmt_buf, i,
				ucl_object_tostring (sym),
				ucl_object_todouble (weight),
				(gint)ucl_object_toint (freq),
				ucl_object_todouble (tim));
		}
		i++;
	}
	printf (" %s \n", dash_buf);
}

static void
rspamc_stat_actions (ucl_object_t *obj, GString *out, gint64 scanned)
{
	const ucl_object_t *actions = ucl_object_lookup (obj, "actions"), *cur;
	ucl_object_iter_t iter = NULL;
	gint64 spam, ham;

	if (actions && ucl_object_type (actions) == UCL_OBJECT) {
		while ((cur = ucl_object_iterate (actions, &iter, true)) != NULL) {
			gint64 cnt = ucl_object_toint (cur);
			rspamd_printf_gstring (out, "Messages with action %s: %L"
				", %.2f%%\n", ucl_object_key (cur), cnt,
				((gdouble)cnt / (gdouble)scanned) * 100.);
		}
	}

	spam = ucl_object_toint (ucl_object_lookup (obj, "spam_count"));
	ham = ucl_object_toint (ucl_object_lookup (obj, "ham_count"));
	rspamd_printf_gstring (out, "Messages treated as spam: %L, %.2f%%\n", spam,
		((gdouble)spam / (gdouble)scanned) * 100.);
	rspamd_printf_gstring (out, "Messages treated as ham: %L, %.2f%%\n", ham,
		((gdouble)ham / (gdouble)scanned) * 100.);
}

static void
rspamc_stat_statfile (const ucl_object_t *obj, GString *out)
{
	gint64 version, size, blocks, used_blocks, nlanguages, nusers;
	const gchar *label, *symbol, *type;

	version = ucl_object_toint (ucl_object_lookup (obj, "revision"));
	size = ucl_object_toint (ucl_object_lookup (obj, "size"));
	blocks = ucl_object_toint (ucl_object_lookup (obj, "total"));
	used_blocks = ucl_object_toint (ucl_object_lookup (obj, "used"));
	label = ucl_object_tostring (ucl_object_lookup (obj, "label"));
	symbol = ucl_object_tostring (ucl_object_lookup (obj, "symbol"));
	type = ucl_object_tostring (ucl_object_lookup (obj, "type"));
	nlanguages = ucl_object_toint (ucl_object_lookup (obj, "languages"));
	nusers = ucl_object_toint (ucl_object_lookup (obj, "users"));

	if (label) {
		rspamd_printf_gstring (out, "Statfile: %s <%s> type: %s; ", symbol,
				label, type);
	}
	else {
		rspamd_printf_gstring (out, "Statfile: %s type: %s; ", symbol, type);
	}
	rspamd_printf_gstring (out, "length: %hL; free blocks: %hL; total blocks: %hL; "
			"free: %.2f%%; learned: %L; users: %L; languages: %L\n",
			size,
			blocks - used_blocks, blocks,
			blocks > 0 ? (blocks - used_blocks) * 100.0 / (gdouble)blocks : 0,
			version,
			nusers, nlanguages);
}

static void
rspamc_stat_output (FILE *out, ucl_object_t *obj)
{
	GString *out_str;
	ucl_object_iter_t iter = NULL;
	const ucl_object_t *st, *cur;
	gint64 scanned;

	out_str = g_string_sized_new (BUFSIZ);

	scanned = ucl_object_toint (ucl_object_lookup (obj, "scanned"));
	rspamd_printf_gstring (out_str, "Messages scanned: %L\n",
		scanned);

	if (scanned > 0) {
		rspamc_stat_actions (obj, out_str, scanned);
	}

	rspamd_printf_gstring (out_str, "Messages learned: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "learned")));
	rspamd_printf_gstring (out_str, "Connections count: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "connections")));
	rspamd_printf_gstring (out_str, "Control connections count: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "control_connections")));
	/* Pools */
	rspamd_printf_gstring (out_str, "Pools allocated: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "pools_allocated")));
	rspamd_printf_gstring (out_str, "Pools freed: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "pools_freed")));
	rspamd_printf_gstring (out_str, "Bytes allocated: %HL\n",
		ucl_object_toint (ucl_object_lookup (obj, "bytes_allocated")));
	rspamd_printf_gstring (out_str, "Memory chunks allocated: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "chunks_allocated")));
	rspamd_printf_gstring (out_str, "Shared chunks allocated: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "shared_chunks_allocated")));
	rspamd_printf_gstring (out_str, "Chunks freed: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "chunks_freed")));
	rspamd_printf_gstring (out_str, "Oversized chunks: %L\n",
		ucl_object_toint (ucl_object_lookup (obj, "chunks_oversized")));
	/* Fuzzy */

	st = ucl_object_lookup (obj, "fuzzy_hashes");
	if (st) {
		ucl_object_iter_t it = NULL;
		const ucl_object_t *cur;
		gint64 stored = 0;

		while ((cur = ucl_iterate_object (st, &it, true)) != NULL) {
			rspamd_printf_gstring (out_str, "Fuzzy hashes in storage \"%s\": %L\n",
					ucl_object_key (cur),
					ucl_object_toint (cur));
			stored += ucl_object_toint (cur);
		}

		rspamd_printf_gstring (out_str, "Fuzzy hashes stored: %L\n",
				stored);
	}

	st = ucl_object_lookup (obj, "fuzzy_checked");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		rspamd_printf_gstring (out_str, "Fuzzy hashes checked: ");
		iter = NULL;

		while ((cur = ucl_object_iterate (st, &iter, true)) != NULL) {
			rspamd_printf_gstring (out_str, "%hL ", ucl_object_toint (cur));
		}

		rspamd_printf_gstring (out_str, "\n");
	}

	st = ucl_object_lookup (obj, "fuzzy_found");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		rspamd_printf_gstring (out_str, "Fuzzy hashes found: ");
		iter = NULL;

		while ((cur = ucl_object_iterate (st, &iter, true)) != NULL) {
			rspamd_printf_gstring (out_str, "%hL ", ucl_object_toint (cur));
		}

		rspamd_printf_gstring (out_str, "\n");
	}

	st = ucl_object_lookup (obj, "statfiles");
	if (st != NULL && ucl_object_type (st) == UCL_ARRAY) {
		iter = NULL;

		while ((cur = ucl_object_iterate (st, &iter, true)) != NULL) {
			rspamc_stat_statfile (cur, out_str);
		}
	}
	rspamd_printf_gstring (out_str, "Total learns: %L\n",
			ucl_object_toint (ucl_object_lookup (obj, "total_learns")));

	rspamd_fprintf (out, "%v", out_str);
}

static void
rspamc_output_headers (FILE *out, struct rspamd_http_message *msg)
{
	struct rspamd_http_header *h, *htmp;

	HASH_ITER (hh, msg->headers, h, htmp) {
		rspamd_fprintf (out, "%T: %T\n", h->name, h->value);
	}

	rspamd_fprintf (out, "\n");
}

static gboolean
rspamd_action_from_str (const gchar *data, gint *result)
{
	if (g_ascii_strncasecmp (data, "reject", sizeof ("reject") - 1) == 0) {
		*result = METRIC_ACTION_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "greylist",
		sizeof ("greylist") - 1) == 0) {
		*result = METRIC_ACTION_GREYLIST;
	}
	else if (g_ascii_strncasecmp (data, "add_header", sizeof ("add_header") -
		1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite_subject",
		sizeof ("rewrite_subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "add header", sizeof ("add header") -
			1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite subject",
			sizeof ("rewrite subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft_reject",
			sizeof ("soft_reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft reject",
			sizeof ("soft reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "no_action",
			sizeof ("soft_reject") - 1) == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else if (g_ascii_strncasecmp (data, "no action",
			sizeof ("soft reject") - 1) == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else {
		return FALSE;
	}
	return TRUE;
}

static void
rspamc_mime_output (FILE *out, ucl_object_t *result, GString *input,
		gdouble time, GError *err)
{
	const ucl_object_t *cur, *metric, *res;
	ucl_object_iter_t it = NULL;
	const gchar *action = "no action";
	gchar scorebuf[32];
	GString *symbuf, *folded_symbuf, *added_headers;
	gint act = 0;
	goffset headers_pos;
	gdouble score = 0.0, required_score = 0.0;
	gboolean is_spam = FALSE;
	gchar *json_header, *json_header_encoded, *sc;

	headers_pos = rspamd_string_find_eoh (input, NULL);

	if (headers_pos == -1) {
		rspamd_fprintf (stderr,"cannot find end of headers position");
		return;
	}

	added_headers = g_string_sized_new (127);

	if (result) {
		metric = ucl_object_lookup (result, "default");

		if (metric != NULL) {
			res = ucl_object_lookup (metric, "action");

			if (res) {
				action = ucl_object_tostring (res);
			}

			res = ucl_object_lookup (metric, "score");
			if (res) {
				score = ucl_object_todouble (res);
			}

			res = ucl_object_lookup (metric, "required_score");
			if (res) {
				required_score = ucl_object_todouble (res);
			}
		}

		rspamd_action_from_str (action, &act);

		if (act < METRIC_ACTION_GREYLIST) {
			is_spam = TRUE;
		}

		rspamd_printf_gstring (added_headers, "X-Spam-Scanner: %s\r\n",
				"rspamc " RVERSION);
		rspamd_printf_gstring (added_headers, "X-Spam-Scan-Time: %.3f\r\n",
				time);

		if (is_spam) {
			rspamd_printf_gstring (added_headers, "X-Spam: yes\r\n");
		}

		rspamd_printf_gstring (added_headers, "X-Spam-Action: %s\r\n",
				action);
		rspamd_printf_gstring (added_headers, "X-Spam-Score: %.2f / %.2f\r\n",
				score, required_score);

		/* SA style stars header */
		for (sc = scorebuf; sc < scorebuf + sizeof (scorebuf) - 1 && score > 0;
			 sc ++, score -= 1.0) {
			*sc = '*';
		}

		*sc = '\0';
		rspamd_printf_gstring (added_headers, "X-Spam-Level: %s\r\n",
				scorebuf);

		/* Short description of all symbols */
		symbuf = g_string_sized_new (64);

		while ((cur = ucl_object_iterate (metric, &it, true)) != NULL) {

			if (ucl_object_type (cur) == UCL_OBJECT) {
				rspamd_printf_gstring (symbuf, "%s,", ucl_object_key (cur));
			}
		}
		/* Trim the last comma */
		if (symbuf->str[symbuf->len - 1] == ',') {
			g_string_erase (symbuf, symbuf->len - 1, 1);
		}

		folded_symbuf = rspamd_header_value_fold ("X-Spam-Symbols",
				symbuf->str,
				0);
		rspamd_printf_gstring (added_headers, "X-Spam-Symbols: %v\r\n",
				folded_symbuf);

		g_string_free (folded_symbuf, TRUE);
		g_string_free (symbuf, TRUE);

		if (ucl_object_lookup (result, "dkim-signature")) {
			folded_symbuf = rspamd_header_value_fold ("DKIM-Signature",
					ucl_object_tostring (ucl_object_lookup (result, "dkim-signature")),
					0);
			rspamd_printf_gstring (added_headers, "DKIM-Signature: %v\r\n",
					folded_symbuf);
			g_string_free (folded_symbuf, TRUE);
		}

		if (json || raw || compact) {
			/* We also append json data as a specific header */
			if (json) {
				json_header = ucl_object_emit (result,
						compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
			}
			else {
				json_header = ucl_object_emit (result,
						compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
			}

			json_header_encoded = rspamd_encode_base64_fold (json_header,
					strlen (json_header), 60, NULL);
			free (json_header);
			rspamd_printf_gstring (added_headers,
					"X-Spam-Result: %s\r\n",
					json_header_encoded);
			g_free (json_header_encoded);
		}

		ucl_object_unref (result);
	}
	else {
		rspamd_printf_gstring (added_headers, "X-Spam-Scanner: %s\r\n",
				"rspamc " RVERSION);
		rspamd_printf_gstring (added_headers, "X-Spam-Scan-Time: %.3f\r\n",
				time);
		rspamd_printf_gstring (added_headers, "X-Spam-Error: %e\r\n",
				err);
	}

	/* Write message */
	if (rspamd_fprintf (out, "%*s", (gint)headers_pos, input->str)
			== headers_pos) {
		if (rspamd_fprintf (out, "%v", added_headers)
				== (gint)added_headers->len) {
			rspamd_fprintf (out, "%s", input->str + headers_pos);
		}
	}

	g_string_free (added_headers, TRUE);
}

static void
rspamc_client_execute_cmd (struct rspamc_command *cmd, ucl_object_t *result,
		GString *input, gdouble time, GError *err)
{
	gchar **eargv;
	gint eargc, infd, outfd, errfd;
	GError *exec_err = NULL;
	GPid cld;
	FILE *out;
	gchar *ucl_out;

	if (!g_shell_parse_argv (execute, &eargc, &eargv, &err)) {
		rspamd_fprintf (stderr, "Cannot execute %s: %e", execute, err);
		g_error_free (err);

		return;
	}

	if (!g_spawn_async_with_pipes (NULL, eargv, NULL,
			G_SPAWN_SEARCH_PATH|G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &cld,
			&infd, &outfd, &errfd, &exec_err)) {

		rspamd_fprintf (stderr, "Cannot execute %s: %e", execute, exec_err);
		g_error_free (exec_err);

		exit (EXIT_FAILURE);
	}
	else {
		children = g_list_prepend (children, GSIZE_TO_POINTER (cld));
		out = fdopen (infd, "w");

		if (cmd->cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			rspamc_mime_output (out, result, input, time, err);
		}
		else if (result) {
			if (raw || cmd->command_output_func == NULL) {
				if (json) {
					ucl_out = ucl_object_emit (result,
							compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
				}
				else {
					ucl_out = ucl_object_emit (result,
							compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
				}
				rspamd_fprintf (out, "%s", ucl_out);
				free (ucl_out);
			}
			else {
				cmd->command_output_func (out, result);
			}

			ucl_object_unref (result);
		}
		else {
			rspamd_fprintf (out, "%e\n", err);
		}

		fflush (out);

		fclose (out);
	}

	g_strfreev (eargv);
}

static void
rspamc_client_cb (struct rspamd_client_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *name, ucl_object_t *result, GString *input,
	gpointer ud, GError *err)
{
	gchar *ucl_out;
	struct rspamc_callback_data *cbdata = (struct rspamc_callback_data *)ud;
	struct rspamc_command *cmd;
	FILE *out = stdout;
	gdouble finish = rspamd_get_ticks (), diff;
	const gchar *body;
	gsize body_len;

	cmd = cbdata->cmd;
	diff = finish - cbdata->start;

	if (execute) {
		/* Pass all to the external command */
		rspamc_client_execute_cmd (cmd, result, input, diff, err);
	}
	else {

		if (cmd->cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			rspamc_mime_output (out, result, input, diff, err);
		}
		else {
			if (cmd->need_input) {
				if (!compact) {
					rspamd_fprintf (out, "Results for file: %s (%.3f seconds)\n",
							cbdata->filename, diff);
				}
			}
			else {
				if (!compact) {
					rspamd_fprintf (out, "Results for command: %s (%.3f seconds)\n",
							cmd->name, diff);
				}
			}

			if (result != NULL) {
				if (headers && msg != NULL) {
					rspamc_output_headers (out, msg);
				}
				if (raw || cmd->command_output_func == NULL) {
					if (json) {
						ucl_out = ucl_object_emit (result,
								compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
					}
					else {
						ucl_out = ucl_object_emit (result,
								compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
					}
					rspamd_fprintf (out, "%s", ucl_out);
					free (ucl_out);
				}
				else {
					cmd->command_output_func (out, result);
				}

				ucl_object_unref (result);
			}
			else if (err != NULL) {
				rspamd_fprintf (out, "%s\n", err->message);

				if (json && msg != NULL) {
					body = rspamd_http_message_get_body (msg, &body_len);

					if (body) {
						/* We can also output the resulting json */
						rspamd_fprintf (out, "%*s\n", (gint)body_len, body);
					}
				}
			}
		}

		rspamd_fprintf (out, "\n");
		fflush (out);
	}

	rspamd_client_destroy (conn);
	g_free (cbdata->filename);
	g_slice_free1 (sizeof (struct rspamc_callback_data), cbdata);
}

static void
rspamc_process_input (struct event_base *ev_base, struct rspamc_command *cmd,
	FILE *in, const gchar *name, GQueue *attrs)
{
	struct rspamd_client_connection *conn;
	gchar *hostbuf = NULL, *p;
	guint16 port;
	GError *err = NULL;
	struct rspamc_callback_data *cbdata;

	if (connect_str[0] == '[') {
		p = strrchr (connect_str, ']');

		if (p != NULL) {
			hostbuf = g_malloc (p - connect_str);
			rspamd_strlcpy (hostbuf, connect_str + 1, p - connect_str);
			p ++;
		}
		else {
			p = connect_str;
		}
	}
	else {
		p = connect_str;
	}

	p = strrchr (p, ':');

	if (p != NULL) {
		port = strtoul (p + 1, NULL, 10);
	}
	else {
		port = cmd->is_controller ? DEFAULT_CONTROL_PORT : DEFAULT_PORT;
	}

	if (!hostbuf) {
		if (p != NULL) {
			hostbuf = g_malloc (p - connect_str + 1);
			rspamd_strlcpy (hostbuf, connect_str, p - connect_str + 1);
		}
		else {
			hostbuf = g_strdup (connect_str);
		}
	}

	conn = rspamd_client_init (ev_base, hostbuf, port, timeout, key);

	if (conn != NULL) {
		cbdata = g_slice_alloc (sizeof (struct rspamc_callback_data));
		cbdata->cmd = cmd;
		cbdata->filename = g_strdup (name);
		cbdata->start = rspamd_get_ticks ();

		if (cmd->need_input) {
			rspamd_client_command (conn, cmd->path, attrs, in, rspamc_client_cb,
				cbdata, &err);
		}
		else {
			rspamd_client_command (conn,
				cmd->path,
				attrs,
				NULL,
				rspamc_client_cb,
				cbdata,
				&err);
		}
	}
	else {
		rspamd_fprintf (stderr, "cannot connect to %s\n", connect_str);
		exit (EXIT_FAILURE);
	}

	g_free (hostbuf);
}

static void
rspamc_process_dir (struct event_base *ev_base, struct rspamc_command *cmd,
	const gchar *name, GQueue *attrs)
{
	DIR *d;
	struct dirent entry, *pentry = NULL;
	gint cur_req = 0;
	gchar fpath[PATH_MAX];
	FILE *in;
	struct stat st;

	memset (&entry, 0, sizeof (entry));
	d = opendir (name);

	if (d != NULL) {
		while (readdir_r (d, &entry, &pentry) == 0) {
			if (pentry == NULL) {
				break;
			}

			if (pentry->d_name[0] == '.') {
				continue;
			}

			rspamd_snprintf (fpath, sizeof (fpath), "%s%c%s",
					name, G_DIR_SEPARATOR, pentry->d_name);

			if (lstat (fpath, &st) == -1) {
				rspamd_fprintf (stderr, "cannot stat file %s: %s\n",
						fpath, strerror (errno));
				continue;
			}

			if (S_ISDIR (st.st_mode)) {
				rspamc_process_dir (ev_base, cmd, fpath, attrs);
				continue;
			}
			else if (S_ISREG (st.st_mode)) {
				in = fopen (fpath, "r");
				if (in == NULL) {
					rspamd_fprintf (stderr, "cannot open file %s: %s\n",
							fpath, strerror (errno));
					continue;
				}

				rspamc_process_input (ev_base, cmd, in, fpath, attrs);
				cur_req++;
				fclose (in);

				if (cur_req >= max_requests) {
					cur_req = 0;
					/* Wait for completion */
					event_base_loop (ev_base, 0);
				}
			}
		}
	}
	else {
		fprintf (stderr, "cannot open directory %s: %s\n", name, strerror (errno));
		exit (EXIT_FAILURE);
	}

	closedir (d);
	event_base_loop (ev_base, 0);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint i, start_argc, cur_req = 0, res, ret;
	GQueue *kwattrs;
	GList *cur;
	GPid cld;
	struct rspamc_command *cmd;
	FILE *in = NULL;
	struct event_base *ev_base;
	struct stat st;
	struct sigaction sigpipe_act;

	kwattrs = g_queue_new ();

	read_cmd_line (&argc, &argv);

	tty = isatty (STDOUT_FILENO);

	if (print_commands) {
		print_commands_list ();
		exit (EXIT_SUCCESS);
	}

	rspamd_init_libs ();
	ev_base = event_base_new ();

	/* Ignore sigpipe */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);

	/* Now read other args from argc and argv */
	if (argc == 1) {
		start_argc = argc;
		in = stdin;
		cmd = check_rspamc_command ("symbols");
	}
	else if (argc == 2) {
		/* One argument is whether command or filename */
		if ((cmd = check_rspamc_command (argv[1])) != NULL) {
			start_argc = argc;
			in = stdin;
		}
		else {
			cmd = check_rspamc_command ("symbols"); /* Symbols command */
			start_argc = 1;
		}
	}
	else {
		if ((cmd = check_rspamc_command (argv[1])) != NULL) {
			/* In case of command read arguments starting from 2 */
			if (cmd->cmd == RSPAMC_COMMAND_ADD_SYMBOL || cmd->cmd ==
				RSPAMC_COMMAND_ADD_ACTION) {
				if (argc < 4 || argc > 5) {
					fprintf (stderr, "invalid arguments\n");
					exit (EXIT_FAILURE);
				}
				if (argc == 5) {
					ADD_CLIENT_HEADER (kwattrs, "metric", argv[2]);
					ADD_CLIENT_HEADER (kwattrs, "name",	argv[3]);
					ADD_CLIENT_HEADER (kwattrs, "value",	argv[4]);
				}
				else {
					ADD_CLIENT_HEADER (kwattrs, "name",  argv[2]);
					ADD_CLIENT_HEADER (kwattrs, "value", argv[3]);
				}
				start_argc = argc;
			}
			else {
				start_argc = 2;
			}
		}
		else {
			cmd = check_rspamc_command ("symbols");
			start_argc = 1;
		}
	}

	add_options (kwattrs);

	if (start_argc == argc) {
		/* Do command without input or with stdin */
		if (empty_input) {
			rspamc_process_input (ev_base, cmd, NULL, "empty", kwattrs);
		}
		else {
			rspamc_process_input (ev_base, cmd, in, "stdin", kwattrs);
		}
	}
	else {
		for (i = start_argc; i < argc; i++) {
			if (stat (argv[i], &st) == -1) {
				fprintf (stderr, "cannot stat file %s\n", argv[i]);
				exit (EXIT_FAILURE);
			}
			if (S_ISDIR (st.st_mode)) {
				/* Directories are processed with a separate limit */
				rspamc_process_dir (ev_base, cmd, argv[i], kwattrs);
				cur_req = 0;
			}
			else {
				in = fopen (argv[i], "r");
				if (in == NULL) {
					fprintf (stderr, "cannot open file %s\n", argv[i]);
					exit (EXIT_FAILURE);
				}
				rspamc_process_input (ev_base, cmd, in, argv[i], kwattrs);
				cur_req++;
				fclose (in);
			}
			if (cur_req >= max_requests) {
				cur_req = 0;
				/* Wait for completion */
				event_base_loop (ev_base, 0);
			}
		}
	}

	event_base_loop (ev_base, 0);

	g_queue_free_full (kwattrs, g_free);

	/* Wait for children processes */
	cur = g_list_first (children);
	ret = 0;

	while (cur) {
		cld = GPOINTER_TO_SIZE (cur->data);

		if (waitpid (cld, &res, 0) == -1) {
			fprintf (stderr, "Cannot wait for %d: %s", (gint)cld,
					strerror (errno));

			ret = errno;
		}

		if (ret == 0) {
			/* Check return code */
			if (WIFSIGNALED (res)) {
				ret = WTERMSIG (res);
			}
			else if (WIFEXITED (res)) {
				ret = WEXITSTATUS (res);
			}
		}

		cur = g_list_next (cur);
	}

	if (children != NULL) {
		g_list_free (children);
	}

	return ret;
}
