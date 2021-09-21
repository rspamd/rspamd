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
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "libserver/cfg_file.h"
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
static gchar **exclude_patterns = NULL;
static gint weight = 0;
static gint flag = 0;
static gchar *fuzzy_symbol = NULL;
static gchar *dictionary = NULL;
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
static gboolean compressed = FALSE;
static gboolean profile = FALSE;
static gboolean skip_images = FALSE;
static gboolean skip_attachments = FALSE;
static gchar *key = NULL;
static gchar *user_agent = "rspamc";
static GList *children;
static GPatternSpec **exclude_compiled = NULL;
static struct rspamd_http_context *http_ctx;

static gint retcode = EXIT_SUCCESS;

#define ADD_CLIENT_HEADER(o, n, v) do { \
    struct rspamd_http_client_header *nh; \
    nh = g_malloc (sizeof (*nh)); \
    nh->name = g_strdup (n); \
    nh->value = g_strdup (v); \
    g_queue_push_tail ((o), nh); \
} while (0)

#define ADD_CLIENT_FLAG(str, n) do { \
   g_string_append ((str), n ","); \
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
	{ "mime", 'm', 0, G_OPTION_ARG_NONE, &mime_output,
	   "Write mime body of message with headers instead of just a scan's result", NULL },
	{"header", 0, 0, G_OPTION_ARG_STRING_ARRAY, &http_headers,
		"Add custom HTTP header to query (can be repeated)", NULL},
	{"exclude", 0, 0, G_OPTION_ARG_STRING_ARRAY, &exclude_patterns,
		"Exclude specific glob patterns in file names (can be repeated)", NULL},
	{"sort", 0, 0, G_OPTION_ARG_STRING, &sort,
		"Sort output in a specific order (name, weight, frequency, hits)", NULL},
	{ "empty", 'E', 0, G_OPTION_ARG_NONE, &empty_input,
	   "Allow empty input instead of reading from stdin", NULL },
	{ "fuzzy-symbol", 'S', 0, G_OPTION_ARG_STRING, &fuzzy_symbol,
	   "Learn the specified fuzzy symbol", NULL },
	{ "compressed", 'z', 0, G_OPTION_ARG_NONE, &compressed,
	   "Enable zstd compression", NULL },
	{ "profile", '\0', 0, G_OPTION_ARG_NONE, &profile,
	   "Profile symbols execution time", NULL },
	{ "dictionary", 'D', 0, G_OPTION_ARG_FILENAME, &dictionary,
	   "Use dictionary to compress data", NULL },
	{ "skip-images", '\0', 0, G_OPTION_ARG_NONE, &skip_images,
	   "Skip images when learning/unlearning fuzzy", NULL },
	{ "skip-attachments", '\0', 0, G_OPTION_ARG_NONE, &skip_attachments,
	   "Skip attachments when learning/unlearning fuzzy", NULL },
	{ "user-agent", 'U', 0, G_OPTION_ARG_STRING, &user_agent,
	   "Use specific User-Agent instead of \"rspamc\"", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

static void rspamc_symbols_output (FILE *out, ucl_object_t *obj);
static void rspamc_uptime_output (FILE *out, ucl_object_t *obj);
static void rspamc_counters_output (FILE *out, ucl_object_t *obj);
static void rspamc_stat_output (FILE *out, ucl_object_t *obj);

enum rspamc_command_type {
	RSPAMC_COMMAND_UNKNOWN = 0,
	RSPAMC_COMMAND_CHECK,
	RSPAMC_COMMAND_SYMBOLS,
	RSPAMC_COMMAND_LEARN_SPAM,
	RSPAMC_COMMAND_LEARN_HAM,
	RSPAMC_COMMAND_FUZZY_ADD,
	RSPAMC_COMMAND_FUZZY_DEL,
	RSPAMC_COMMAND_FUZZY_DELHASH,
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
		.path = "checkv2",
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
			"add hashes from a message to the fuzzy storage (check -f and -w options for this command)",
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
			"delete hashes from a message from the fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = NULL
	},
	{
		.cmd = RSPAMC_COMMAND_FUZZY_DELHASH,
		.name = "fuzzy_delhash",
		.path = "fuzzydelhash",
		.description =
			"delete a hash from fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
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
};

gboolean
rspamc_password_callback (const gchar *option_name,
		const gchar *value,
		gpointer data,
		GError **error)
{
	guint plen = 8192;
	guint8 *map, *end;
	gsize sz;

	if (value != NULL) {
		if (value[0] == '/' || value[0] == '.') {
			/* Try to open file */
			map = rspamd_file_xmap (value, PROT_READ, &sz, 0);

			if (map == NULL) {
				/* Just use it as a string */
				password = g_strdup (value);
			}
			else {
				/* Strip trailing spaces */
				g_assert (sz > 0);
				end = map + sz - 1;

				while (g_ascii_isspace (*end) && end > map) {
					end --;
				}

				end ++;
				password = g_malloc (end - map + 1);
				rspamd_strlcpy (password, map, end - map + 1);
				munmap (map, sz);
			}
		}
		else {
			password = g_strdup (value);
		}
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
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	if (json || compact) {
		raw = TRUE;
	}
	/* Argc and argv are shifted after this function */
	g_option_context_free (context);
}

static gboolean
rspamd_action_from_str_rspamc (const gchar *data, gint *result)
{
	if (strcmp (data, "reject") == 0) {
		*result = METRIC_ACTION_REJECT;
	}
	else if (strcmp (data, "greylist") == 0) {
		*result = METRIC_ACTION_GREYLIST;
	}
	else if (strcmp (data, "add_header") == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (strcmp (data, "rewrite_subject") == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (strcmp (data, "add header") == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (strcmp (data, "rewrite subject") == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (strcmp (data, "soft_reject") == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (strcmp (data, "soft reject") == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (strcmp (data, "no_action") == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else if (strcmp (data, "no action") == 0) {
		*result = METRIC_ACTION_NOACTION;
	}
	else {
		return FALSE;
	}
	return TRUE;
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
	else if (g_ascii_strcasecmp (cmd, "FUZZY_DELHASH") == 0) {
		ct = RSPAMC_COMMAND_FUZZY_DELHASH;
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
	guint cmd_len = 0;
	gchar fmt_str[32];

	rspamd_fprintf (stdout, "Rspamc commands summary:\n");

	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		gsize clen = strlen (rspamc_commands[i].name);

		if (clen > cmd_len) {
			cmd_len = clen;
		}
	}

	rspamd_snprintf (fmt_str, sizeof (fmt_str), "  %%%ds (%%7s%%1s)\t%%s\n",
			cmd_len);

	for (i = 0; i < G_N_ELEMENTS (rspamc_commands); i++) {
		fprintf (stdout,
				fmt_str,
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
	GString *flagbuf = g_string_new (NULL);

	if (ip != NULL) {
		rspamd_inet_addr_t *addr = NULL;

		if (!rspamd_parse_inet_address (&addr, ip, strlen (ip),
				RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			/* Try to resolve */
			struct addrinfo hints, *res, *cur;
			gint r;

			memset (&hints, 0, sizeof (hints));
			hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
#ifdef AI_IDN
			hints.ai_flags = AI_NUMERICSERV|AI_IDN;
#else
			hints.ai_flags = AI_NUMERICSERV;
#endif
			hints.ai_family = AF_UNSPEC;

			if ((r = getaddrinfo (ip, "25", &hints, &res)) == 0) {

				cur = res;
				while (cur) {
					addr = rspamd_inet_address_from_sa (cur->ai_addr,
							cur->ai_addrlen);

					if (addr != NULL) {
						ip = g_strdup (rspamd_inet_address_to_string (addr));
						rspamd_inet_address_free (addr);
						break;
					}

					cur = cur->ai_next;
				}

				freeaddrinfo (res);
			}
			else {
				rspamd_fprintf (stderr, "address resolution for %s failed: %s\n",
						ip,
						gai_strerror (r));
			}
		}
		else {
			rspamd_inet_address_free (addr);
		}

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
		ADD_CLIENT_FLAG (flagbuf, "pass_all");
	}

	if (classifier) {
		ADD_CLIENT_HEADER (opts, "Classifier", classifier);
	}

	if (weight != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", weight);
		ADD_CLIENT_HEADER (opts, "Weight", numbuf->str);
		g_string_free (numbuf, TRUE);
	}

	if (fuzzy_symbol != NULL) {
		ADD_CLIENT_HEADER (opts, "Symbol", fuzzy_symbol);
	}

	if (flag != 0) {
		numbuf = g_string_sized_new (8);
		rspamd_printf_gstring (numbuf, "%d", flag);
		ADD_CLIENT_HEADER (opts, "Flag", numbuf->str);
		g_string_free (numbuf, TRUE);
	}

	if (extended_urls) {
		ADD_CLIENT_HEADER (opts, "URL-Format", "extended");
	}

	if (profile) {
		ADD_CLIENT_FLAG (flagbuf, "profile");
	}

	ADD_CLIENT_FLAG (flagbuf, "body_block");

	if (skip_images) {
		ADD_CLIENT_HEADER (opts, "Skip-Images", "true");
	}

	if (skip_attachments) {
		ADD_CLIENT_HEADER (opts, "Skip-Attachments", "true");
	}

	hdr = http_headers;

	while (hdr != NULL && *hdr != NULL) {
		gchar **kv = g_strsplit_set (*hdr, ":=", 2);

		if (kv == NULL || kv[1] == NULL) {
			ADD_CLIENT_HEADER (opts, *hdr, "");
		}
		else {
			ADD_CLIENT_HEADER (opts, kv[0], kv[1]);
		}

		if (kv) {
			g_strfreev (kv);
		}

		hdr ++;
	}

	if (flagbuf->len > 0) {
		goffset last = flagbuf->len - 1;

		if (flagbuf->str[last] == ',') {
			flagbuf->str[last] = '\0';
			flagbuf->len --;
		}

		ADD_CLIENT_HEADER (opts, "Flags", flagbuf->str);
	}

	g_string_free (flagbuf, TRUE);
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

#define PRINT_PROTOCOL_STRING(ucl_name, output_message) do { \
	elt = ucl_object_lookup (obj, (ucl_name)); \
	if (elt) { \
		rspamd_fprintf (out, output_message ": %s\n", ucl_object_tostring (elt)); \
	} \
} while (0)

static void
rspamc_metric_output (FILE *out, const ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	gdouble score = 0, required_score = 0;
	gint got_scores = 0, action = METRIC_ACTION_MAX;
	GPtrArray *sym_ptr;
	guint i;

	sym_ptr = g_ptr_array_new ();
	rspamd_fprintf (out, "[Metric: default]\n");

	elt = ucl_object_lookup (obj, "required_score");

	if (elt) {
		required_score = ucl_object_todouble (elt);
		got_scores++;
	}

	elt = ucl_object_lookup (obj, "score");

	if (elt) {
		score = ucl_object_todouble (elt);
		got_scores++;
	}

	PRINT_PROTOCOL_STRING ("action", "Action");
	/* Defined by previous macro */
	if (elt && rspamd_action_from_str_rspamc (ucl_object_tostring (elt), &action)) {
		rspamd_fprintf (out, "Spam: %s\n", action < METRIC_ACTION_GREYLIST ?
				"true" : "false");
	}

	PRINT_PROTOCOL_STRING ("subject", "Subject");

	if (got_scores == 2) {
		rspamd_fprintf (out,
				"Score: %.2f / %.2f\n",
				score,
				required_score);
	}

	elt = ucl_object_lookup (obj, "symbols");

	while (elt && (cur = ucl_object_iterate (elt, &it, true)) != NULL) {
		if (cur->type == UCL_OBJECT) {
			g_ptr_array_add (sym_ptr, (void *)cur);
		}
	}

	g_ptr_array_sort (sym_ptr, rspamc_symbols_sort_func);

	for (i = 0; i < sym_ptr->len; i ++) {
		cur = (const ucl_object_t *)g_ptr_array_index (sym_ptr, i);
		rspamc_symbol_output (out, cur);
	}

	g_ptr_array_free (sym_ptr, TRUE);
}

static gint
rspamc_profile_sort_func (gconstpointer a, gconstpointer b)
{
	ucl_object_t * const *ua = a, * const *ub = b;

	return ucl_object_compare (*ua, *ub);
}

static void
rspamc_profile_output (FILE *out, const ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	guint i;
	GPtrArray *ar;

	ar = g_ptr_array_sized_new (obj->len);

	while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
		g_ptr_array_add (ar, (void *)cur);
	}

	g_ptr_array_sort (ar, rspamc_profile_sort_func);

	for (i = 0; i < ar->len; i ++) {
		cur = (const ucl_object_t *)g_ptr_array_index (ar, i);
		rspamd_fprintf (out, "\t%s: %.3f usec\n",
				ucl_object_key (cur), ucl_object_todouble (cur));
	}

	g_ptr_array_free (ar, TRUE);
}

static void
rspamc_symbols_output (FILE *out, ucl_object_t *obj)
{
	ucl_object_iter_t mit = NULL;
	const ucl_object_t *cmesg, *elt;
	gchar *emitted;

	rspamc_metric_output (out, obj);

	PRINT_PROTOCOL_STRING ("message-id", "Message-ID");
	PRINT_PROTOCOL_STRING ("queue-id", "Queue-ID");

	elt = ucl_object_lookup (obj, "urls");

	if (elt) {
		if (!extended_urls || compact) {
			emitted = ucl_object_emit (elt, UCL_EMIT_JSON_COMPACT);
		}
		else {
			emitted = ucl_object_emit (elt, UCL_EMIT_JSON);
		}

		rspamd_fprintf (out, "Urls: %s\n", emitted);
		free (emitted);
	}

	elt = ucl_object_lookup (obj, "emails");

	if (elt) {
		if (!extended_urls || compact) {
			emitted = ucl_object_emit (elt, UCL_EMIT_JSON_COMPACT);
		}
		else {
			emitted = ucl_object_emit (elt, UCL_EMIT_JSON);
		}

		rspamd_fprintf (out, "Emails: %s\n", emitted);
		free (emitted);
	}

	PRINT_PROTOCOL_STRING ("error", "Scan error");

	elt = ucl_object_lookup (obj, "messages");
	if (elt && elt->type == UCL_OBJECT) {
		mit = NULL;
		while ((cmesg = ucl_object_iterate (elt, &mit, true)) != NULL) {
			rspamd_fprintf (out, "Message - %s: %s\n",
					ucl_object_key (cmesg), ucl_object_tostring (cmesg));
		}
	}

	elt = ucl_object_lookup (obj, "dkim-signature");
	if (elt && elt->type == UCL_STRING) {
		rspamd_fprintf (out, "DKIM-Signature: %s\n", ucl_object_tostring (elt));
	} else if (elt && elt->type == UCL_ARRAY) {
		mit = NULL;
		while ((cmesg = ucl_object_iterate (elt, &mit, true)) != NULL) {
			rspamd_fprintf (out, "DKIM-Signature: %s\n", ucl_object_tostring (cmesg));
		}
	}

	elt = ucl_object_lookup (obj, "profile");

	if (elt) {
		rspamd_fprintf (out, "Profile data:\n");
		rspamc_profile_output (out, elt);
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
					order1 = ucl_object_todouble (elt1) * 100000;
					order2 = ucl_object_todouble (elt2) * 100000;
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
			else if (g_ascii_strcasecmp (args[0], "hits") == 0) {
				elt1 = ucl_object_lookup (*o1, "hits");
				elt2 = ucl_object_lookup (*o2, "hits");

				if (elt1 && elt2) {
					order1 = ucl_object_toint (elt1);
					order2 = ucl_object_toint (elt2);
				}
			}
		}

		g_strfreev (args);
	}

	return (inverse ? (order2 - order1) : (order1 - order2));
}

static void
rspamc_counters_output (FILE *out, ucl_object_t *obj)
{
	const ucl_object_t *cur, *sym, *weight, *freq, *freq_dev, *nhits;
	ucl_object_iter_t iter = NULL;
	gchar fmt_buf[64], dash_buf[82], sym_buf[82];
	static const gint dashes = 44;

	if (obj->type != UCL_ARRAY) {
		rspamd_printf ("Bad output\n");
		return;
	}

	/* Sort symbols by their order */
	if (sort != NULL) {
		ucl_object_array_sort (obj, rspamc_counters_sort);
	}

	/* Find maximum width of symbol's name */
	gint max_len = sizeof("Symbol") - 1;
	while ((cur = ucl_object_iterate (obj, &iter, true)) != NULL) {
		sym = ucl_object_lookup (cur, "symbol");
		if (sym != NULL) {
			if (sym->len > max_len) {
				max_len = sym->len;
			}
		}
	}

	max_len = MIN (sizeof (dash_buf) - dashes - 1, max_len);
	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3s | %%%ds | %%7s | %%13s | %%7s |\n", max_len);
	memset (dash_buf, '-', dashes + max_len);
	dash_buf[dashes + max_len] = '\0';

	printf ("Symbols cache\n");
	printf (" %s \n", dash_buf);
	if (tty) {
		printf ("\033[1m");
	}
	printf (fmt_buf, "Pri", "Symbol", "Weight", "Frequency", "Hits");
	printf (" %s \n", dash_buf);
	printf (fmt_buf, "", "", "", "hits/min", "");
	if (tty) {
		printf ("\033[0m");
	}
	rspamd_snprintf (fmt_buf, sizeof (fmt_buf),
		"| %%3d | %%%ds | %%7.1f | %%6.3f(%%5.3f) | %%7ju |\n", max_len);

	iter = NULL;
	gint i = 0;
	while ((cur = ucl_object_iterate (obj, &iter, true)) != NULL) {
		printf (" %s \n", dash_buf);
		sym = ucl_object_lookup (cur, "symbol");
		weight = ucl_object_lookup (cur, "weight");
		freq = ucl_object_lookup (cur, "frequency");
		freq_dev = ucl_object_lookup (cur, "frequency_stddev");
		nhits = ucl_object_lookup (cur, "hits");

		if (sym && weight && freq && nhits) {
			const gchar *sym_name;

			if (sym->len > max_len) {
				rspamd_snprintf (sym_buf, sizeof (sym_buf), "%*s...",
						(max_len - 3), ucl_object_tostring (sym));
				sym_name = sym_buf;
			}
			else {
				sym_name = ucl_object_tostring (sym);
			}

			printf (fmt_buf, i,
					sym_name,
					ucl_object_todouble (weight),
					ucl_object_todouble (freq) * 60.0,
					ucl_object_todouble (freq_dev) * 60.0,
					(uintmax_t)ucl_object_toint (nhits));
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
	struct rspamd_http_header *h;

	kh_foreach_value (msg->headers, h, {
		rspamd_fprintf (out, "%T: %T\n", &h->name, &h->value);
	});

	rspamd_fprintf (out, "\n");
}

static void
rspamc_mime_output (FILE *out, ucl_object_t *result, GString *input,
		gdouble time, GError *err)
{
	const ucl_object_t *cur, *res, *syms;
	ucl_object_iter_t it = NULL;
	const gchar *action = "no action", *line_end = "\r\n", *p;
	gchar scorebuf[32];
	GString *symbuf, *folded_symbuf, *added_headers;
	gint act = 0;
	goffset headers_pos;
	gdouble score = 0.0, required_score = 0.0;
	gboolean is_spam = FALSE;
	gchar *json_header, *json_header_encoded, *sc;
	enum rspamd_newlines_type nl_type = RSPAMD_TASK_NEWLINES_CRLF;

	headers_pos = rspamd_string_find_eoh (input, NULL);

	if (headers_pos == -1) {
		rspamd_fprintf (stderr,"cannot find end of headers position");
		return;
	}

	p = input->str + headers_pos;

	if (headers_pos > 1 && *(p - 1) == '\n') {
		if (headers_pos > 2 && *(p - 2) == '\r') {
			line_end = "\r\n";
			nl_type = RSPAMD_TASK_NEWLINES_CRLF;
		}
		else {
			line_end = "\n";
			nl_type = RSPAMD_TASK_NEWLINES_LF;
		}
	}
	else if (headers_pos > 1 && *(p - 1) == '\r') {
		line_end = "\r";
		nl_type = RSPAMD_TASK_NEWLINES_CR;
	}

	added_headers = g_string_sized_new (127);

	if (result) {
		res = ucl_object_lookup (result, "action");

		if (res) {
			action = ucl_object_tostring (res);
		}

		res = ucl_object_lookup (result, "score");
		if (res) {
			score = ucl_object_todouble (res);
		}

		res = ucl_object_lookup (result, "required_score");
		if (res) {
			required_score = ucl_object_todouble (res);
		}

		rspamd_action_from_str_rspamc (action, &act);

		if (act < METRIC_ACTION_GREYLIST) {
			is_spam = TRUE;
		}

		rspamd_printf_gstring (added_headers, "X-Spam-Scanner: %s%s",
				"rspamc " RVERSION, line_end);
		rspamd_printf_gstring (added_headers, "X-Spam-Scan-Time: %.3f%s",
				time, line_end);

		/*
		 * TODO: add rmilter_headers support here
		 */
		if (is_spam) {
			rspamd_printf_gstring (added_headers, "X-Spam: yes%s", line_end);
		}

		rspamd_printf_gstring (added_headers, "X-Spam-Action: %s%s",
				action, line_end);
		rspamd_printf_gstring (added_headers, "X-Spam-Score: %.2f / %.2f%s",
				score, required_score, line_end);

		/* SA style stars header */
		for (sc = scorebuf; sc < scorebuf + sizeof (scorebuf) - 1 && score > 0;
			 sc ++, score -= 1.0) {
			*sc = '*';
		}

		*sc = '\0';
		rspamd_printf_gstring (added_headers, "X-Spam-Level: %s%s",
				scorebuf, line_end);

		/* Short description of all symbols */
		symbuf = g_string_sized_new (64);
		syms = ucl_object_lookup (result, "symbols");

		while (syms && (cur = ucl_object_iterate (syms, &it, true)) != NULL) {

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
				0, nl_type, ",");
		rspamd_printf_gstring (added_headers, "X-Spam-Symbols: %v%s",
				folded_symbuf, line_end);

		g_string_free (folded_symbuf, TRUE);
		g_string_free (symbuf, TRUE);

		res = ucl_object_lookup (result, "dkim-signature");
		if (res && res->type == UCL_STRING) {
			rspamd_printf_gstring (added_headers, "DKIM-Signature: %s%s",
					ucl_object_tostring (res), line_end);
		} else if (res && res->type == UCL_ARRAY) {
			it = NULL;
			while ((cur = ucl_object_iterate (res, &it, true)) != NULL) {
				rspamd_printf_gstring (added_headers, "DKIM-Signature: %s%s",
					ucl_object_tostring (cur), line_end);
			}
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
					strlen (json_header), 60, NULL, nl_type);
			free (json_header);
			rspamd_printf_gstring (added_headers,
					"X-Spam-Result: %s%s",
					json_header_encoded, line_end);
			g_free (json_header_encoded);
		}

		ucl_object_unref (result);
	}
	else {
		rspamd_printf_gstring (added_headers, "X-Spam-Scanner: %s%s",
				"rspamc " RVERSION, line_end);
		rspamd_printf_gstring (added_headers, "X-Spam-Scan-Time: %.3f%s",
				time, line_end);
		rspamd_printf_gstring (added_headers, "X-Spam-Error: %e%s",
				err, line_end);
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
		gpointer ud, gdouble start_time, gdouble send_time,
		const gchar *body, gsize bodylen,
		GError *err)
{
	gchar *ucl_out;
	struct rspamc_callback_data *cbdata = (struct rspamc_callback_data *)ud;
	struct rspamc_command *cmd;
	FILE *out = stdout;
	gdouble finish = rspamd_get_ticks (FALSE), diff;

	cmd = cbdata->cmd;

	if (send_time > 0) {
		diff = finish - send_time;
	}
	else {
		diff = finish - start_time;
	}

	if (execute) {
		/* Pass all to the external command */
		rspamc_client_execute_cmd (cmd, result, input, diff, err);
	}
	else {

		if (cmd->cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			if (body) {
				GString tmp;

				tmp.str = (char *)body;
				tmp.len = bodylen;
				rspamc_mime_output (out, result, &tmp, diff, err);
			}
			else {
				rspamc_mime_output (out, result, input, diff, err);
			}
		}
		else {
			if (cmd->need_input && !json) {
				if (!compact) {
					rspamd_fprintf (out, "Results for file: %s (%.3f seconds)\n",
							cbdata->filename, diff);
				}
			}
			else {
				if (!compact && !json) {
					rspamd_fprintf (out, "Results for command: %s (%.3f seconds)\n",
							cmd->name, diff);
				}
			}

			if (result != NULL) {
				if (headers && msg != NULL) {
					rspamc_output_headers (out, msg);
				}
				if (raw || cmd->command_output_func == NULL) {
					if (cmd->need_input) {
						ucl_object_insert_key (result,
								ucl_object_fromstring (cbdata->filename),
								"filename", 0,
								false);
					}

					ucl_object_insert_key (result,
							ucl_object_fromdouble (diff),
							"scan_time", 0,
							false);

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

				if (body) {
					rspamd_fprintf (out, "\nNew body:\n%*s\n", (int)bodylen,
							body);
				}

				ucl_object_unref (result);
			}
			else if (err != NULL) {
				rspamd_fprintf (out, "%s\n", err->message);

				if (json && msg != NULL) {
					const gchar *raw;
					gsize rawlen;

					raw = rspamd_http_message_get_body (msg, &rawlen);

					if (raw) {
						/* We can also output the resulting json */
						rspamd_fprintf (out, "%*s\n", (gint)(rawlen - bodylen),
								raw);
					}
				}
			}
			rspamd_fprintf (out, "\n");
		}

		fflush (out);
	}

	rspamd_client_destroy (conn);
	g_free (cbdata->filename);
	g_free (cbdata);

	if (err) {
		retcode = EXIT_FAILURE;
	}
}

static void
rspamc_process_input (struct ev_loop *ev_base, struct rspamc_command *cmd,
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

	if (!hostbuf) {
		if (p != NULL) {
			hostbuf = g_malloc (p - connect_str + 1);
			rspamd_strlcpy (hostbuf, connect_str, p - connect_str + 1);
		}
		else {
			hostbuf = g_strdup (connect_str);
		}
	}

	if (p != NULL) {
		port = strtoul (p + 1, NULL, 10);
	}
	else {
		/*
		 * If we connect to localhost, 127.0.0.1 or ::1, then try controller
		 * port first
		 */

		if (strcmp (hostbuf, "localhost") == 0 ||
				strcmp (hostbuf, "127.0.0.1") == 0 ||
				strcmp (hostbuf, "::1") == 0 ||
				strcmp (hostbuf, "[::1]") == 0) {
			port = DEFAULT_CONTROL_PORT;
		}
		else {
			port = cmd->is_controller ? DEFAULT_CONTROL_PORT : DEFAULT_PORT;
		}

	}

	conn = rspamd_client_init (http_ctx, ev_base, hostbuf, port, timeout, key);

	if (conn != NULL) {
		cbdata = g_malloc0 (sizeof (struct rspamc_callback_data));
		cbdata->cmd = cmd;

		if (name) {
			cbdata->filename = g_strdup (name);
		}

		if (cmd->need_input) {
			rspamd_client_command (conn, cmd->path, attrs, in, rspamc_client_cb,
				cbdata, compressed, dictionary, cbdata->filename, &err);
		}
		else {
			rspamd_client_command (conn,
					cmd->path,
					attrs,
					NULL,
					rspamc_client_cb,
					cbdata,
					compressed,
					dictionary,
					cbdata->filename,
					&err);
		}
	}
	else {
		rspamd_fprintf (stderr, "cannot connect to %s: %s\n", connect_str,
				strerror (errno));
		exit (EXIT_FAILURE);
	}

	g_free (hostbuf);
}

static gsize
rspamd_dirent_size (DIR * dirp)
{
	goffset name_max;
	gsize name_end;

#if defined(HAVE_FPATHCONF) && defined(HAVE_DIRFD) \
       && defined(_PC_NAME_MAX)
	name_max = fpathconf (dirfd (dirp), _PC_NAME_MAX);


# if defined(NAME_MAX)
	if (name_max == -1) {
		name_max = (NAME_MAX > 255) ? NAME_MAX : 255;
	}
# else
	if (name_max == -1) {
		return (size_t)(-1);
	}
# endif
#else
# if defined(NAME_MAX)
	name_max = (NAME_MAX > 255) ? NAME_MAX : 255;
# else
#   error "buffer size for readdir_r cannot be determined"
# endif
#endif

	name_end = G_STRUCT_OFFSET (struct dirent, d_name) + name_max + 1;

	return (name_end > sizeof (struct dirent) ? name_end : sizeof(struct dirent));
}

static void
rspamc_process_dir (struct ev_loop *ev_base, struct rspamc_command *cmd,
	const gchar *name, GQueue *attrs)
{
	DIR *d;
	GPatternSpec **ex;
	struct dirent *pentry;
	gint cur_req = 0, r;
	gchar fpath[PATH_MAX];
	FILE *in;
	struct stat st;
	gboolean is_reg, is_dir, skip;

	d = opendir (name);

	if (d != NULL) {
		while ((pentry = readdir (d))!= NULL) {

			if (pentry->d_name[0] == '.') {
				continue;
			}

			r = rspamd_snprintf (fpath, sizeof (fpath), "%s%c%s",
					name, G_DIR_SEPARATOR,
					pentry->d_name);

			/* Check exclude */
			ex = exclude_compiled;
			skip = FALSE;
			while (ex != NULL && *ex != NULL) {
				if (g_pattern_match (*ex, r, fpath, NULL)) {
					skip = TRUE;
					break;
				}

				ex ++;
			}

			if (skip) {
				continue;
			}

			is_reg = FALSE;
			is_dir = FALSE;

#if (defined(_DIRENT_HAVE_D_TYPE) || defined(__APPLE__)) && defined(DT_UNKNOWN)
			if (pentry->d_type == DT_UNKNOWN) {
				/* Fallback to lstat */
				if (lstat (fpath, &st) == -1) {
					rspamd_fprintf (stderr, "cannot stat file %s: %s\n",
							fpath, strerror (errno));
					continue;
				}

				is_dir = S_ISDIR (st.st_mode);
				is_reg = S_ISREG (st.st_mode);
			}
			else {
				if (pentry->d_type == DT_REG) {
					is_reg = TRUE;
				}
				else if (pentry->d_type == DT_DIR) {
					is_dir = TRUE;
				}
			}
#else
			if (lstat (fpath, &st) == -1) {
				rspamd_fprintf (stderr, "cannot stat file %s: %s\n",
						fpath, strerror (errno));
				continue;
			}

			is_dir = S_ISDIR (st.st_mode);
			is_reg = S_ISREG (st.st_mode);
#endif
			if (is_dir) {
				rspamc_process_dir (ev_base, cmd, fpath, attrs);
				continue;
			}
			else if (is_reg) {
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
					ev_loop (ev_base, 0);
				}
			}
		}
	}
	else {
		fprintf (stderr, "cannot open directory %s: %s\n", name, strerror (errno));
		exit (EXIT_FAILURE);
	}

	closedir (d);
	ev_loop (ev_base, 0);
}


static void
rspamc_kwattr_free (gpointer p)
{
	struct rspamd_http_client_header *h = (struct rspamd_http_client_header *)p;

	g_free (h->value);
	g_free (h->name);
	g_free (h);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint i, start_argc, cur_req = 0, res, ret, npatterns;
	GQueue *kwattrs;
	GList *cur;
	GPid cld;
	struct rspamc_command *cmd;
	FILE *in = NULL;
	struct ev_loop *event_loop;
	struct stat st;
	struct sigaction sigpipe_act;
	gchar **exclude_pattern;

	kwattrs = g_queue_new ();

	read_cmd_line (&argc, &argv);

	tty = isatty (STDOUT_FILENO);

	if (print_commands) {
		print_commands_list ();
		exit (EXIT_SUCCESS);
	}

	/* Deal with exclude patterns */
	exclude_pattern = exclude_patterns;
	npatterns = 0;

	while (exclude_pattern && *exclude_pattern) {
		exclude_pattern ++;
		npatterns ++;
	}

	if (npatterns > 0) {
		exclude_compiled = g_malloc0 (sizeof (*exclude_compiled) * (npatterns + 1));

		for (i = 0; i < npatterns; i ++) {
			exclude_compiled[i] = g_pattern_spec_new (exclude_patterns[i]);

			if (exclude_compiled[i] == NULL) {
				rspamd_fprintf (stderr, "Invalid glob pattern: %s\n",
						exclude_patterns[i]);
				exit (EXIT_FAILURE);
			}
		}
	}

	struct rspamd_external_libs_ctx *libs = rspamd_init_libs ();
	event_loop = ev_loop_new (EVBACKEND_ALL);

	struct rspamd_http_context_cfg http_config;

	memset (&http_config, 0, sizeof (http_config));
	http_config.kp_cache_size_client = 32;
	http_config.kp_cache_size_server = 0;
	http_config.user_agent = user_agent;
	http_ctx = rspamd_http_context_create_config (&http_config,
			event_loop, NULL);

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
			rspamc_process_input (event_loop, cmd, NULL, "empty", kwattrs);
		}
		else {
			rspamc_process_input (event_loop, cmd, in, "stdin", kwattrs);
		}
	}
	else {
		for (i = start_argc; i < argc; i++) {
			if (cmd->cmd == RSPAMC_COMMAND_FUZZY_DELHASH) {
				ADD_CLIENT_HEADER (kwattrs, "Hash",  argv[i]);
			}
			else {
				if (stat (argv[i], &st) == -1) {
					fprintf (stderr, "cannot stat file %s\n", argv[i]);
					exit (EXIT_FAILURE);
				}
				if (S_ISDIR (st.st_mode)) {
					/* Directories are processed with a separate limit */
					rspamc_process_dir (event_loop, cmd, argv[i], kwattrs);
					cur_req = 0;
				}
				else {
					in = fopen (argv[i], "r");
					if (in == NULL) {
						fprintf (stderr, "cannot open file %s\n", argv[i]);
						exit (EXIT_FAILURE);
					}
					rspamc_process_input (event_loop, cmd, in, argv[i], kwattrs);
					cur_req++;
					fclose (in);
				}
				if (cur_req >= max_requests) {
					cur_req = 0;
					/* Wait for completion */
					ev_loop (event_loop, 0);
				}
			}
		}

		if (cmd->cmd == RSPAMC_COMMAND_FUZZY_DELHASH) {
			rspamc_process_input (event_loop, cmd, NULL, "hashes", kwattrs);
		}
	}

	ev_loop (event_loop, 0);

	g_queue_free_full (kwattrs, rspamc_kwattr_free);

	/* Wait for children processes */
	cur = children ? g_list_first (children) : NULL;
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

	for (i = 0; i < npatterns; i ++) {
		g_pattern_spec_free (exclude_compiled[i]);
	}

	rspamd_deinit_libs (libs);

	/* Mix retcode (return from Rspamd side) and ret (return from subprocess) */
	return ret | retcode;
}
