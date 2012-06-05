/*
 * Copyright (c) 2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "../../lib/client/librspamdclient.h"

#define PRINT_FUNC printf

#define DEFAULT_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

static gchar                   *connect_str = "localhost";
static gchar                   *password = NULL;
static gchar                   *statfile = NULL;
static gchar                   *ip = NULL;
static gchar                   *from = NULL;
static gchar                   *deliver_to = NULL;
static gchar                   *rcpt = NULL;
static gchar                   *user = NULL;
static gchar                   *classifier = NULL;
static gchar                   *local_addr = NULL;
static gint                     weight = 1;
static gint                     flag;
static gint                     timeout = 5;
static gboolean                 pass_all;
static gboolean                 tty = FALSE;
static gboolean                 verbose = FALSE;
static struct rspamd_client    *client = NULL;

static GOptionEntry entries[] =
{
		{ "connect", 'h', 0, G_OPTION_ARG_STRING, &connect_str, "Specify host and port", NULL },
		{ "password", 'P', 0, G_OPTION_ARG_STRING, &password, "Specify control password", NULL },
		{ "statfile", 's', 0, G_OPTION_ARG_STRING, &statfile, "Statfile to learn (symbol name)", NULL },
		{ "classifier", 'c', 0, G_OPTION_ARG_STRING, &classifier, "Classifier to learn spam or ham", NULL },
		{ "weight", 'w', 0, G_OPTION_ARG_INT, &weight, "Weight for fuzzy operations", NULL },
		{ "flag", 'f', 0, G_OPTION_ARG_INT, &flag, "Flag for fuzzy operations", NULL },
		{ "pass", 'p', 0, G_OPTION_ARG_NONE, &pass_all, "Pass all filters", NULL },
		{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "More verbose output", NULL },
		{ "ip", 'i', 0, G_OPTION_ARG_STRING, &ip, "Emulate that message was received from specified ip address", NULL },
		{ "user", 'u', 0, G_OPTION_ARG_STRING, &user, "Emulate that message was from specified user", NULL },
		{ "deliver", 'd', 0, G_OPTION_ARG_STRING, &deliver_to, "Emulate that message is delivered to specified user", NULL },
		{ "from", 'F', 0, G_OPTION_ARG_STRING, &from, "Emulate that message is from specified user", NULL },
		{ "rcpt", 'r', 0, G_OPTION_ARG_STRING, &rcpt, "Emulate that message is for specified user", NULL },
		{ "timeout", 't', 0, G_OPTION_ARG_INT, &timeout, "Timeout for waiting for a reply", NULL },
		{ "bind", 'b', 0, G_OPTION_ARG_STRING, &local_addr, "Bind to specified ip address", NULL },
		{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

enum rspamc_command {
	RSPAMC_COMMAND_UNKNOWN = 0,
	RSPAMC_COMMAND_SYMBOLS,
	RSPAMC_COMMAND_LEARN,
	RSPAMC_COMMAND_LEARN_SPAM,
	RSPAMC_COMMAND_LEARN_HAM,
	RSPAMC_COMMAND_FUZZY_ADD,
	RSPAMC_COMMAND_FUZZY_DEL,
	RSPAMC_COMMAND_STAT,
	RSPAMC_COMMAND_UPTIME
};

/*
 * Parse command line
 */
static void
read_cmd_line (gint *argc, gchar ***argv)
{
	GError                         *error = NULL;
	GOptionContext                 *context;

	/* Prepare parser */
	context = g_option_context_new ("- run rspamc client");
	g_option_context_set_summary (context, "Summary:\n  Rspamd client version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);

	/* Parse options */
	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (EXIT_FAILURE);
	}

	/* Argc and argv are shifted after this function */
}

/*
 * Check rspamc command from string (used for arguments parsing)
 */
static enum rspamc_command
check_rspamc_command (const gchar *cmd)
{
	if (g_ascii_strcasecmp (cmd, "SYMBOLS") == 0 ||
		g_ascii_strcasecmp (cmd, "CHECK") == 0 ||
		g_ascii_strcasecmp (cmd, "REPORT") == 0) {
		/* These all are symbols, don't use other commands */
		return RSPAMC_COMMAND_SYMBOLS;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN") == 0) {
		return RSPAMC_COMMAND_LEARN;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_SPAM") == 0) {
		return RSPAMC_COMMAND_LEARN_SPAM;
	}
	else if (g_ascii_strcasecmp (cmd, "LEARN_HAM") == 0) {
		return RSPAMC_COMMAND_LEARN_HAM;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_ADD") == 0) {
		return RSPAMC_COMMAND_FUZZY_ADD;
	}
	else if (g_ascii_strcasecmp (cmd, "FUZZY_DEL") == 0) {
		return RSPAMC_COMMAND_FUZZY_DEL;
	}
	else if (g_ascii_strcasecmp (cmd, "STAT") == 0) {
		return RSPAMC_COMMAND_STAT;
	}
	else if (g_ascii_strcasecmp (cmd, "UPTIME") == 0) {
		return RSPAMC_COMMAND_UPTIME;
	}

	return RSPAMC_COMMAND_UNKNOWN;
}

/*
 * Parse connect_str and add server to librspamdclient
 */
static void
add_rspamd_server (gboolean is_control)
{
	gchar                         **vec, *err_str;
	guint16                         port;
	GError                         *err = NULL;

	if (connect_str == NULL) {
		fprintf (stderr, "cannot connect to rspamd server - empty string\n");
		exit (EXIT_FAILURE);
	}
	vec = g_strsplit_set (connect_str, ":", 2);
	if (vec == NULL || *vec == NULL) {
		fprintf (stderr, "cannot connect to rspamd server: %s\n", connect_str);
		exit (EXIT_FAILURE);
	}

	if (vec[1] == NULL) {
		port = is_control ? DEFAULT_CONTROL_PORT : DEFAULT_PORT;
	}
	else {
		port = strtoul (vec[1], &err_str, 10);
		if (*err_str != '\0') {
			fprintf (stderr, "cannot connect to rspamd server: %s, at pos %s\n", connect_str, err_str);
			exit (EXIT_FAILURE);
		}
	}

	if (! rspamd_add_server (client, vec[0], port, port, &err)) {
		fprintf (stderr, "cannot connect to rspamd server: %s, error: %s\n", connect_str, err->message);
		exit (EXIT_FAILURE);
	}
}

static void
show_symbol_result (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_symbol            *s = value;
	GList                           *cur;
	static gboolean                  first = TRUE;

	if (verbose) {
		if (tty) {
			PRINT_FUNC ("\n\033[1mSymbol\033[0m - %s(%.2f)", s->name, s->weight);
		}
		else {
			PRINT_FUNC ("\nSymbol - %s(%.2f)", s->name, s->weight);
		}
		if (s->options) {
			PRINT_FUNC (": ");
			cur = g_list_first (s->options);
			while (cur) {
				if (cur->next) {
					PRINT_FUNC ("%s,", (const gchar *)cur->data);
				}
				else {
					PRINT_FUNC ("%s", (const gchar *)cur->data);
				}
				cur = g_list_next (cur);
			}
		}
		if (s->description) {
			PRINT_FUNC (" - \"%s\"", s->description);
		}
	}
	else {
		if (! first) {
			PRINT_FUNC (", ");
		}
		else {
			first = FALSE;
		}
		PRINT_FUNC ("%s(%.2f)", s->name, s->weight);

		if (s->options) {
			PRINT_FUNC ("(");
			cur = g_list_first (s->options);
			while (cur) {
				if (cur->next) {
					PRINT_FUNC ("%s,", (const gchar *)cur->data);
				}
				else {
					PRINT_FUNC ("%s)", (const gchar *)cur->data);
				}
				cur = g_list_next (cur);
			}
		}
	}
}

static void
show_metric_result (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_metric            *metric = value;

	if (metric->is_skipped) {
		PRINT_FUNC ("\n%s: Skipped\n", (const gchar *)key);
	}
	else {
		if (tty) {
			PRINT_FUNC ("\n\033[1m%s:\033[0m %s [ %.2f / %.2f ]\n", (const gchar *)key,
						metric->score > metric->required_score ? "True" : "False",
						metric->score, metric->required_score);
		}
		else {
			PRINT_FUNC ("\n%s: %s [ %.2f / %.2f ]\n", (const gchar *)key,
						metric->score > metric->required_score ? "True" : "False",
						metric->score, metric->required_score);
		}
		if (tty) {
			if (metric->action) {
				PRINT_FUNC ("\033[1mAction:\033[0m %s\n", metric->action);
			}
			PRINT_FUNC ("\033[1mSymbols: \033[0m");
		}
		else {
			if (metric->action) {
				PRINT_FUNC ("Action: %s\n", metric->action);
			}
			else {
				PRINT_FUNC ("Symbols: ");
			}
		}
		if (metric->symbols) {
			g_hash_table_foreach (metric->symbols, show_symbol_result, NULL);
		}
		PRINT_FUNC ("\n");
	}
}

static void
show_header_result (gpointer key, gpointer value, gpointer ud)
{
	if (tty) {
		PRINT_FUNC ("\033[1m%s:\033[0m %s\n", (const gchar *)key, (const gchar *)value);
	}
	else {
		PRINT_FUNC ("%s: %s\n", (const gchar *)key, (const gchar *)value);
	}
}

static void
print_rspamd_result (struct rspamd_result *res)
{
	g_assert (res != 0);

	if (tty) {
		printf ("\033[1m");
	}
	PRINT_FUNC ("Results for host: %s\n", connect_str);
	if (tty) {
		printf ("\033[0m");
	}
	g_hash_table_foreach (res->metrics, show_metric_result, NULL);
	/* Show other headers */
	PRINT_FUNC ("\n");
	g_hash_table_foreach (res->headers, show_header_result, NULL);
	PRINT_FUNC ("\n");
}

static void
add_options (GHashTable *opts)
{
	if (ip != NULL) {
		g_hash_table_insert (opts, "Ip", ip);
	}
	if (from != NULL) {
		g_hash_table_insert (opts, "From", from);
	}
	if (user != NULL) {
		g_hash_table_insert (opts, "User", user);
	}
	if (rcpt != NULL) {
		g_hash_table_insert (opts, "Rcpt", rcpt);
	}
	if (deliver_to != NULL) {
		g_hash_table_insert (opts, "Deliver-To", deliver_to);
	}
	if (pass_all) {
		g_hash_table_insert (opts, "Pass", "all");
	}
}

/*
 * Scan STDIN
 */
static void
scan_rspamd_stdin (void)
{
	gchar                           *in_buf;

	gint                             r = 0, len;
	GError                          *err = NULL;
	struct rspamd_result            *res;
	GHashTable                      *opts;

	/* Init options hash */
	opts = g_hash_table_new (g_str_hash, g_str_equal);
	add_options (opts);
	/* Add server */
	add_rspamd_server (FALSE);

	/* Allocate input buffer */
	len = BUFSIZ;
	in_buf = g_malloc (len);

	/* Read stdin */
	while (!feof (stdin)) {
		r += fread (in_buf + r, 1, len - r, stdin);
		if (len - r < len / 2) {
			/* Grow buffer */
			len *= 2;
			in_buf = g_realloc (in_buf, len);
		}
	}
	res = rspamd_scan_memory (client, in_buf, r, opts, &err);
	g_hash_table_destroy (opts);
	if (err != NULL) {
		fprintf (stderr, "cannot scan message: %s\n", err->message);
		exit (EXIT_FAILURE);
	}
	print_rspamd_result (res);
	rspamd_free_result (res);
}

static void
scan_rspamd_file (const gchar *file)
{
	GError                          *err = NULL;
	struct rspamd_result            *res;
	GHashTable                      *opts;

	/* Init options hash */
	opts = g_hash_table_new (g_str_hash, g_str_equal);
	add_options (opts);
	res = rspamd_scan_file (client, file, opts, &err);
	g_hash_table_destroy (opts);
	if (err != NULL) {
		fprintf (stderr, "cannot scan message: %s\n", err->message);
		return;
	}
	print_rspamd_result (res);
	if (res) {
		rspamd_free_result (res);
	}
}

static void
learn_rspamd_stdin (gboolean is_spam)
{
	gchar                           *in_buf;
	gint                             r = 0, len;
	GError                          *err = NULL;

	if ((statfile == NULL && classifier == NULL)) {
		fprintf (stderr, "cannot learn message without password and symbol/classifier name\n");
		exit (EXIT_FAILURE);
	}
	/* Add server */
	add_rspamd_server (TRUE);

	/* Allocate input buffer */
	len = BUFSIZ;
	in_buf = g_malloc (len);

	/* Read stdin */
	while (!feof (stdin)) {
		r += fread (in_buf + r, 1, len - r, stdin);
		if (len - r < len / 2) {
			/* Grow buffer */
			len *= 2;
			in_buf = g_realloc (in_buf, len);
		}
	}
	if (statfile != NULL) {
		if (!rspamd_learn_memory (client, in_buf, r, statfile, password, &err)) {
			if (err != NULL) {
				fprintf (stderr, "cannot learn message: %s\n", err->message);
			}
			else {
				fprintf (stderr, "cannot learn message\n");
			}
			exit (EXIT_FAILURE);
		}
		else {
			if (tty) {
				printf ("\033[1m");
			}
			PRINT_FUNC ("Results for host: %s: learn ok\n", connect_str);
			if (tty) {
				printf ("\033[0m");
			}
		}
	}
	else if (classifier != NULL) {
		if (!rspamd_learn_spam_memory (client, in_buf, r, classifier, is_spam, password, &err)) {
			if (err != NULL) {
				fprintf (stderr, "cannot learn message: %s\n", err->message);
			}
			else {
				fprintf (stderr, "cannot learn message\n");
			}
			exit (EXIT_FAILURE);
		}
		else {
			if (tty) {
				printf ("\033[1m");
			}
			PRINT_FUNC ("Results for host: %s: learn ok\n", connect_str);
			if (tty) {
				printf ("\033[0m");
			}
		}
	}
}

static void
learn_rspamd_file (gboolean is_spam, const gchar *file)
{
	GError                          *err = NULL;

	if ((statfile == NULL && classifier == NULL)) {
		fprintf (stderr, "cannot learn message without password and symbol/classifier name\n");
		exit (EXIT_FAILURE);
	}

	if (statfile != NULL) {
		if (!rspamd_learn_file (client, file, statfile, password, &err)) {
			if (err != NULL) {
				fprintf (stderr, "cannot learn message: %s\n", err->message);
			}
			else {
				fprintf (stderr, "cannot learn message\n");
			}
		}
		else {
			if (tty) {
				printf ("\033[1m");
			}
			PRINT_FUNC ("learn ok\n");
			if (tty) {
				printf ("\033[0m");
			}
		}
	}
	else if (classifier != NULL) {
		if (!rspamd_learn_spam_file (client, file, classifier, is_spam, password, &err)) {
			if (err != NULL) {
				fprintf (stderr, "cannot learn message: %s\n", err->message);
			}
			else {
				fprintf (stderr, "cannot learn message\n");
			}
		}
		else {
			if (tty) {
				printf ("\033[1m");
			}
			PRINT_FUNC ("learn ok\n");
			if (tty) {
				printf ("\033[0m");
			}
		}
	}
}

static void
fuzzy_rspamd_stdin (gboolean delete)
{
	gchar                           *in_buf;
	gint                             r = 0, len;
	GError                          *err = NULL;

	/* Add server */
	add_rspamd_server (TRUE);

	/* Allocate input buffer */
	len = BUFSIZ;
	in_buf = g_malloc (len);

	/* Read stdin */
	while (!feof (stdin)) {
		r += fread (in_buf + r, 1, len - r, stdin);
		if (len - r < len / 2) {
			/* Grow buffer */
			len *= 2;
			in_buf = g_realloc (in_buf, len);
		}
	}
	if (!rspamd_fuzzy_memory (client, in_buf, r, password, weight, flag, delete, &err)) {
		if (err != NULL) {
			fprintf (stderr, "cannot learn message: %s\n", err->message);
		}
		else {
			fprintf (stderr, "cannot learn message\n");
		}
		exit (EXIT_FAILURE);
	}
	else {
		if (tty) {
			printf ("\033[1m");
		}
		PRINT_FUNC ("Results for host: %s: learn ok\n", connect_str);
		if (tty) {
			printf ("\033[0m");
		}
	}
}

static void
fuzzy_rspamd_file (const gchar *file, gboolean delete)
{
	GError                          *err = NULL;

	if (!rspamd_fuzzy_file (client, file, password, weight, flag, delete, &err)) {
		if (err != NULL) {
			fprintf (stderr, "cannot learn message: %s\n", err->message);
		}
		else {
			fprintf (stderr, "cannot learn message\n");
		}
	}
	else {
		if (tty) {
			printf ("\033[1m");
		}
		PRINT_FUNC ("learn ok\n");
		if (tty) {
			printf ("\033[0m");
		}
	}
}

static void
rspamd_do_stat (void)
{
	GError                          *err = NULL;
	GString                         *res;

	/* Add server */
	add_rspamd_server (TRUE);

	res = rspamd_get_stat (client, &err);
	if (res == NULL) {
		if (err != NULL) {
			fprintf (stderr, "cannot stat: %s\n", err->message);
		}
		else {
			fprintf (stderr, "cannot stat\n");
		}
		exit (EXIT_FAILURE);
	}
	if (tty) {
		printf ("\033[1m");
	}
	PRINT_FUNC ("Results for host: %s\n\n", connect_str);
	if (tty) {
		printf ("\033[0m");
	}
	res = g_string_append_c (res, '\0');
	printf ("%s\n", res->str);
}

static void
rspamd_do_uptime (void)
{
	GError                          *err = NULL;
	GString                         *res;

	/* Add server */
	add_rspamd_server (TRUE);

	res = rspamd_get_uptime (client, &err);
	if (res == NULL) {
		if (err != NULL) {
			fprintf (stderr, "cannot uptime: %s\n", err->message);
		}
		else {
			fprintf (stderr, "cannot uptime\n");
		}
		exit (EXIT_FAILURE);
	}
	if (tty) {
		printf ("\033[1m");
	}
	PRINT_FUNC ("Results for host: %s\n\n", connect_str);
	if (tty) {
		printf ("\033[0m");
	}
	res = g_string_append_c (res, '\0');
	printf ("%s\n", res->str);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	enum rspamc_command             cmd;
	gint                            i;
	struct in_addr					ina;


	read_cmd_line (&argc, &argv);

	if (local_addr) {
		if (inet_aton (local_addr, &ina) != 0) {
			client = rspamd_client_init_binded (&ina);
		}
		else {
			fprintf (stderr, "%s is not a valid ip address\n", local_addr);
			exit (EXIT_FAILURE);
		}
	}
	else {
		client = rspamd_client_init ();
	}

	rspamd_set_timeout (client, 1000, timeout * 1000);
	tty = isatty (STDOUT_FILENO);
	/* Now read other args from argc and argv */
	if (argc == 1) {
		/* No args, just read stdin */
		scan_rspamd_stdin ();
	}
	else if (argc == 2) {
		/* One argument is whether command or filename */
		if ((cmd = check_rspamc_command (argv[1])) != RSPAMC_COMMAND_UNKNOWN) {
			/* In case of command read stdin */
			switch (cmd) {
			case RSPAMC_COMMAND_SYMBOLS:
				scan_rspamd_stdin ();
				break;
			case RSPAMC_COMMAND_LEARN:
				learn_rspamd_stdin (TRUE);
				break;
			case RSPAMC_COMMAND_LEARN_SPAM:
				if (classifier != NULL) {
					learn_rspamd_stdin (TRUE);
				}
				else {
					fprintf (stderr, "no classifier specified\n");
					exit (EXIT_FAILURE);
				}
				break;
			case RSPAMC_COMMAND_LEARN_HAM:
				if (classifier != NULL) {
					learn_rspamd_stdin (FALSE);
				}
				else {
					fprintf (stderr, "no classifier specified\n");
					exit (EXIT_FAILURE);
				}
				break;
			case RSPAMC_COMMAND_FUZZY_ADD:
				fuzzy_rspamd_stdin (FALSE);
				break;
			case RSPAMC_COMMAND_FUZZY_DEL:
				fuzzy_rspamd_stdin (TRUE);
				break;
			case RSPAMC_COMMAND_STAT:
				rspamd_do_stat ();
				break;
			case RSPAMC_COMMAND_UPTIME:
				rspamd_do_uptime ();
				break;
			default:
				fprintf (stderr, "invalid arguments\n");
				exit (EXIT_FAILURE);
			}
		}
		else {
			add_rspamd_server (FALSE);
			scan_rspamd_file (argv[1]);
		}
	}
	else {
		if ((cmd = check_rspamc_command (argv[1])) != RSPAMC_COMMAND_UNKNOWN) {
			/* In case of command read arguments starting from 2 */
			switch (cmd) {
			case RSPAMC_COMMAND_SYMBOLS:
				/* Add server */
				add_rspamd_server (FALSE);
				break;
			default:
				add_rspamd_server (TRUE);
				break;
			}
			for (i = 2; i < argc; i ++) {
				if (tty) {
					printf ("\033[1m");
				}
				PRINT_FUNC ("Results for file: %s\n\n", argv[i]);
				if (tty) {
					printf ("\033[0m");
				}
				switch (cmd) {
				case RSPAMC_COMMAND_SYMBOLS:
					scan_rspamd_file (argv[i]);
					break;
				case RSPAMC_COMMAND_LEARN:
					learn_rspamd_file (TRUE, argv[i]);
					break;
				case RSPAMC_COMMAND_LEARN_SPAM:
					if (classifier != NULL) {
						learn_rspamd_file (TRUE, argv[i]);
					}
					else {
						fprintf (stderr, "no classifier specified\n");
						exit (EXIT_FAILURE);
					}
					break;
				case RSPAMC_COMMAND_LEARN_HAM:
					if (classifier != NULL) {
						learn_rspamd_file (FALSE, argv[i]);
					}
					else {
						fprintf (stderr, "no classifier specified\n");
						exit (EXIT_FAILURE);
					}
					break;
				case RSPAMC_COMMAND_FUZZY_ADD:
					fuzzy_rspamd_file (argv[i], FALSE);
					break;
				case RSPAMC_COMMAND_FUZZY_DEL:
					fuzzy_rspamd_file (argv[i], TRUE);
					break;
				default:
					fprintf (stderr, "invalid arguments\n");
					exit (EXIT_FAILURE);
				}
			}
		}
		else {
			for (i = 1; i < argc; i ++) {
				scan_rspamd_file (argv[i]);
			}
		}
	}

	rspamd_client_close (client);

	return 0;
}
