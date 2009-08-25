/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "message.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "modules.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"

#define CRLF "\r\n"
#define END "END" CRLF

/* 120 seconds for controller's IO */
#define CONTROLLER_IO_TIMEOUT 120

enum command_type {
	COMMAND_PASSWORD,
	COMMAND_QUIT,
	COMMAND_RELOAD,
	COMMAND_STAT,
	COMMAND_SHUTDOWN,
	COMMAND_UPTIME,
	COMMAND_LEARN,
	COMMAND_HELP,
	COMMAND_COUNTERS,
};

struct controller_command {
	char *command;
	gboolean privilleged;
	enum command_type type;
};

struct custom_controller_command {
	const char *command;
	gboolean privilleged;
	gboolean require_message;
	controller_func_t handler;	
};

static struct controller_command commands[] = {
	{"password", FALSE, COMMAND_PASSWORD},
	{"quit", FALSE, COMMAND_QUIT},
	{"reload", TRUE, COMMAND_RELOAD},
	{"stat", FALSE, COMMAND_STAT},
	{"shutdown", TRUE, COMMAND_SHUTDOWN},
	{"uptime", FALSE, COMMAND_UPTIME},
	{"learn", TRUE, COMMAND_LEARN},
	{"help", FALSE, COMMAND_HELP},
	{"counters", FALSE, COMMAND_COUNTERS},
};

static GList *custom_commands = NULL;

static GCompletion *comp;
static time_t start_time;

static char greetingbuf[1024];
extern rspamd_hash_t *counters;

static 
void sig_handler (int signo)
{
	switch (signo) {
		case SIGINT:
		case SIGTERM:
			_exit (1);
			break;
	}
}

static void
sigusr_handler (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	msg_info ("controller's shutdown is pending in %d sec", 2);
	event_loopexit (&tv);
	return;
}

static gchar*
completion_func (gpointer elem)
{
	struct controller_command *cmd = (struct controller_command *)elem;

	return cmd->command;
}

static void
free_session (struct controller_session *session, gboolean is_soft)
{
	GList *part;
	struct mime_part *p;
	
	msg_debug ("free_session: freeing session %p", session);
	
	while ((part = g_list_first (session->parts))) {
		session->parts = g_list_remove_link (session->parts, part);
		p = (struct mime_part *)part->data;
		g_byte_array_free (p->content, FALSE);
		g_list_free_1 (part);
	}
	if (is_soft) {
		/* Plan dispatcher shutdown */
		session->dispatcher->wanna_die = 1;
	}
	else {
		rspamd_remove_dispatcher (session->dispatcher);
	}

	close (session->sock);

	memory_pool_delete (session->session_pool);
	g_free (session);
}

static int
check_auth (struct controller_command *cmd, struct controller_session *session) 
{
	char out_buf[128];
	int r;

	if (cmd->privilleged && !session->authorized) {
		r = snprintf (out_buf, sizeof (out_buf), "not authorized" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		return 0;
	}

	return 1;
}

static void
counter_write_callback (gpointer key, gpointer value, void *data)
{
	struct controller_session *session = data;
	struct counter_data *cd = value;
	char *name = key;
	char out_buf[128];
	int r;

	r = snprintf (out_buf, sizeof (out_buf), "%s: %llu" CRLF, name, (unsigned long long int)cd->value);
	rspamd_dispatcher_write (session->dispatcher, out_buf, r, TRUE, FALSE);
}

static void
process_command (struct controller_command *cmd, char **cmd_args, struct controller_session *session)
{
	char out_buf[BUFSIZ], *arg, *err_str;
	int r = 0, days, hours, minutes;
	time_t uptime;
	unsigned long size = 0;
	struct statfile *statfile;
	stat_file_t *file;
	struct metric *metric;
	memory_pool_stat_t mem_st;
	char *password = g_hash_table_lookup (session->worker->cf->params, "password");

	switch (cmd->type) {
		case COMMAND_PASSWORD:
			arg = *cmd_args;
			if (!arg || *arg == '\0') {
				msg_debug ("process_command: empty password passed");
				r = snprintf (out_buf, sizeof (out_buf), "password command requires one argument" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
				return;
			}
			if (password == NULL) {
				r = snprintf (out_buf, sizeof (out_buf), "password command disabled in config, authorized access unallowed" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
				return;
			}
			if (strncmp (arg, password, strlen (arg)) == 0) {
				session->authorized = 1;
				r = snprintf (out_buf, sizeof (out_buf), "password accepted" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
			}
			else {
				session->authorized = 0;
				r = snprintf (out_buf, sizeof (out_buf), "password NOT accepted" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
			}
			break;
		case COMMAND_QUIT:
			session->state = STATE_QUIT;
			break;
		case COMMAND_RELOAD:
			if (check_auth (cmd, session)) {
				r = snprintf (out_buf, sizeof (out_buf), "reload request sent" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
				kill (getppid (), SIGHUP);
			}
			break;
		case COMMAND_STAT:
			if (check_auth (cmd, session)) {
				memory_pool_stat (&mem_st);
				r = snprintf (out_buf, sizeof (out_buf), "Messages scanned: %u" CRLF,
							  session->worker->srv->stat->messages_scanned);
				r += snprintf (out_buf + r, sizeof (out_buf) - r , "Messages learned: %u" CRLF,
							  session->worker->srv->stat->messages_learned);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Connections count: %u" CRLF,
							  session->worker->srv->stat->connections_count);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Control connections count: %u" CRLF,
							  session->worker->srv->stat->control_connections_count);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Pools allocated: %ld" CRLF,
							  (long int)mem_st.pools_allocated);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Pools freed: %ld" CRLF,
							  (long int)mem_st.pools_freed);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Bytes allocated: %ld" CRLF,
							  (long int)mem_st.bytes_allocated);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Memory chunks allocated: %ld" CRLF,
							  (long int)mem_st.chunks_allocated);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Shared chunks allocated: %ld" CRLF,
							  (long int)mem_st.shared_chunks_allocated);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Chunks freed: %ld" CRLF,
							  (long int)mem_st.chunks_freed);
				r += snprintf (out_buf + r, sizeof (out_buf) - r, "Oversized chunks: %ld" CRLF,
							  (long int)mem_st.oversized_chunks);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
			}
			break;
		case COMMAND_SHUTDOWN:
			if (check_auth (cmd, session)) {
				r = snprintf (out_buf, sizeof (out_buf), "shutdown request sent" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
				kill (getppid (), SIGTERM);
			}
			break;
		case COMMAND_UPTIME:
			if (check_auth (cmd, session)) {
				uptime = time (NULL) - start_time;
				/* If uptime more than 2 hours, print as a number of days. */
 				if (uptime >= 2 * 3600) {
					days = uptime / 86400;
					hours = uptime / 3600 - days * 3600;
					minutes = uptime / 60 - hours * 60 - days * 3600;
					r = snprintf (out_buf, sizeof (out_buf), "%d day%s %d hour%s %d minute%s" CRLF, 
								days, days > 1 ? "s" : " ",
								hours, hours > 1 ? "s" : " ",
								minutes, minutes > 1 ? "s" : " ");
				}
				/* If uptime is less than 1 minute print only seconds */
				else if (uptime / 60 == 0) {
					r = snprintf (out_buf, sizeof (out_buf), "%d second%s" CRLF, (int)uptime, (int)uptime > 1 ? "s" : " ");
				}
				/* Else print the minutes and seconds. */
				else {
					hours = uptime / 3600;
					minutes = uptime / 60 - hours * 3600;
					uptime -= hours * 3600 + minutes * 60;
					r = snprintf (out_buf, sizeof (out_buf), "%d hour%s %d minite%s %d second%s" CRLF, 
								hours, hours > 1 ? "s" : " ",
								minutes, minutes > 1 ? "s" : " ",
								(int)uptime, uptime > 1 ? "s" : " ");
				}
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
			}
			break;
		case COMMAND_LEARN:
			if (check_auth (cmd, session)) {
				arg = *cmd_args;
				if (!arg || *arg == '\0') {
					msg_debug ("process_command: no statfile specified in learn command");
					r = snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					return;
				}
				arg = *(cmd_args + 1);
				if (arg == NULL || *arg == '\0') {
					msg_debug ("process_command: no statfile size specified in learn command");
					r = snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					return;
				}
				size = strtoul (arg, &err_str, 10);
				if (err_str && *err_str != '\0') {
					msg_debug ("process_command: statfile size is invalid: %s", arg);
					r = snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					return;
				}

				statfile = g_hash_table_lookup (session->cfg->statfiles, *cmd_args);
				if (statfile == NULL) {
					r = snprintf (out_buf, sizeof (out_buf), "statfile %s is not defined" CRLF, *cmd_args);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					return;

				}

				metric = g_hash_table_lookup (session->cfg->metrics, statfile->metric);

				session->learn_rcpt = NULL;
				session->learn_from = NULL;
				session->learn_filename = NULL;
				session->learn_tokenizer = statfile->tokenizer;
				if (metric != NULL) {
					session->learn_classifier = metric->classifier;
				}
				else {
					session->learn_classifier = get_classifier ("winnow");
				}
				/* By default learn positive */
				session->in_class = 1;
				/* Get all arguments */
				while (*cmd_args++) {
					arg = *cmd_args;
					if (arg && *arg == '-') {
						switch (*(arg + 1)) {
							case 'r':
								arg = *(cmd_args + 1);
								if (!arg || *arg == '\0') {
									r = snprintf (out_buf, sizeof (out_buf), "recipient is not defined" CRLF);
									rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
									return;
								}
								session->learn_rcpt = memory_pool_strdup (session->session_pool, arg);
								break;
							case 'f':
								arg = *(cmd_args + 1);
								if (!arg || *arg == '\0') {
									r = snprintf (out_buf, sizeof (out_buf), "from is not defined" CRLF);
									rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
									return;
								}
								session->learn_from = memory_pool_strdup (session->session_pool, arg);
								break;
							case 'n':
								session->in_class = 0;
								break;
							default:
								r = snprintf (out_buf, sizeof (out_buf), "tokenizer is not defined" CRLF);
								rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
								return;
						}
					}
				}
				session->learn_filename = resolve_stat_filename (session->session_pool, statfile->pattern, 
																	session->learn_rcpt, session->learn_from);
				if ((file = statfile_pool_open (session->worker->srv->statfile_pool, session->learn_filename)) == NULL) {
					/* Try to create statfile */
					if (statfile_pool_create (session->worker->srv->statfile_pool, 
									session->learn_filename, statfile->size / sizeof (struct stat_file_block)) == -1) {
						r = snprintf (out_buf, sizeof (out_buf), "cannot create statfile %s" CRLF, session->learn_filename);
						rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
						return;
					}
					if ((file = statfile_pool_open (session->worker->srv->statfile_pool, session->learn_filename)) == NULL) {
						r = snprintf (out_buf, sizeof (out_buf), "cannot open statfile %s" CRLF, session->learn_filename);
						rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
						return;
					}
				}
                rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
				session->state = STATE_LEARN;
			}
			break;
		case COMMAND_HELP:
			r = snprintf (out_buf, sizeof (out_buf), 
							"Rspamd CLI commands (* - privilleged command):" CRLF
							"    help - this help message" CRLF
							"(*) learn <statfile> <size> [-r recipient], [-f from] [-n] - learn message to specified statfile" CRLF
							"    quit - quit CLI session" CRLF
							"(*) reload - reload rspamd" CRLF
							"(*) shutdown - shutdown rspamd" CRLF
							"    stat - show different rspamd stat" CRLF
							"    counters - show rspamd counters" CRLF
							"    uptime - rspamd uptime" CRLF);
			rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
			break;
		case COMMAND_COUNTERS:
			rspamd_hash_foreach (counters, counter_write_callback, session);
			break;
	}
}

static gboolean
process_custom_command (char *line, char **cmd_args, struct controller_session *session)
{
	GList *cur;
	struct custom_controller_command *cmd;

	cur = custom_commands;
	while (cur) {
		cmd = cur->data;
		if (g_ascii_strcasecmp (cmd->command, line) == 0) {
			/* Call handler */
			cmd->handler (cmd_args, session);
			return TRUE;
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static void
controller_read_socket (f_str_t *in, void *arg)
{
	struct controller_session *session = (struct controller_session *)arg;
	struct classifier_ctx *cls_ctx;
	int len, i;
	char *s, **params, *cmd, out_buf[128];
	GList *comp_list, *cur = NULL;
	GTree *tokens = NULL;
	GByteArray *content = NULL;
	struct mime_part *p;
	f_str_t c;

	switch (session->state) {
		case STATE_COMMAND:
			s = fstrcstr (in, session->session_pool);
			params = g_strsplit (s, " ", -1);
			len = g_strv_length (params);
			if (len > 0) {
				cmd = g_strstrip (params[0]);
				comp_list = g_completion_complete (comp, cmd, NULL);
				switch (g_list_length (comp_list)) {
					case 1:
						process_command ((struct controller_command *)comp_list->data, &params[1], session);
						break;
					case 0:
						if (!process_custom_command (cmd, &params[1], session)) {
							msg_debug ("Unknown command: '%s'", cmd);
							i = snprintf (out_buf, sizeof (out_buf), "Unknown command" CRLF);
							rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE);
						}
						break;
					default:
						msg_debug ("Ambigious command: '%s'", cmd);
						i = snprintf (out_buf, sizeof (out_buf), "Ambigious command" CRLF);
						rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE);
						break;
				}
			}
			if (session->state == STATE_COMMAND) {
				session->state = STATE_REPLY;
			}
			if (session->state != STATE_LEARN && session->state != STATE_OTHER) {
				rspamd_dispatcher_write (session->dispatcher, END, sizeof (END) - 1, FALSE, TRUE);
			}

			g_strfreev (params);
			break;
		case STATE_LEARN:
			session->learn_buf = in;
			process_learn (session);
			while ((content = get_next_text_part (session->session_pool, session->parts, &cur)) != NULL) {
				c.begin = content->data;
				c.len = content->len;
				if (!session->learn_tokenizer->tokenize_func (session->learn_tokenizer, 
							session->session_pool, &c, &tokens)) {
					i = snprintf (out_buf, sizeof (out_buf), "learn fail, tokenizer error" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE);
					session->state = STATE_REPLY;
					return;
				}
			}
			cls_ctx = session->learn_classifier->init_func (session->session_pool);
			session->learn_classifier->learn_func (cls_ctx, session->worker->srv->statfile_pool,
													session->learn_filename, tokens, session->in_class);
			session->worker->srv->stat->messages_learned ++;
			i = snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF);
			rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE);

			/* Clean learned parts */
			while ((cur = g_list_first (session->parts))) {
				session->parts = g_list_remove_link (session->parts, cur);
				p = (struct mime_part *)cur->data;
				g_byte_array_free (p->content, FALSE);
				g_list_free_1 (cur);
			}

			session->state = STATE_REPLY;
			break;
		case STATE_OTHER:
			if (session->other_handler) {
				session->other_handler (session, in);
			}
			session->state = STATE_REPLY;
			break;
		case STATE_WAIT:
			rspamd_dispatcher_pause (session->dispatcher);
			break;
		default:
			msg_debug ("controller_read_socket: unknown state while reading %d", session->state);
			break;
	}
}

static void
controller_write_socket (void *arg)
{
	struct controller_session *session = (struct controller_session *)arg;
	
	if (session->state == STATE_QUIT) {
		/* Free buffers */
		free_session (session, TRUE);
		return;
	}
	else if (session->state == STATE_REPLY) {
		session->state = STATE_COMMAND;
		rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, BUFSIZ);
	}
}

static void
controller_err_socket (GError *err, void *arg)
{
	struct controller_session *session = (struct controller_session *)arg;

	if (err->code != EOF) {
		msg_info ("controller_err_socket: abnormally closing control connection, error: %s", err->message);
	}
	/* Free buffers */
	free_session (session, FALSE);
}

static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage ss;
	struct controller_session *new_session;
    struct timeval *io_tv;
	socklen_t addrlen = sizeof(ss);
	int nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		msg_warn ("accept_socket: accept failed: %s", strerror (errno));
		return;
	}

	new_session = g_malloc (sizeof (struct controller_session));
	if (new_session == NULL) {
		msg_err ("accept_socket: cannot allocate memory for task, %s", strerror (errno));
		return;
	}
	bzero (new_session, sizeof (struct controller_session));
	new_session->worker = worker;
	new_session->sock = nfd;
	new_session->cfg = worker->srv->cfg;
	new_session->state = STATE_COMMAND;
	new_session->session_pool = memory_pool_new (memory_pool_get_size () - 1);
	worker->srv->stat->control_connections_count ++;

	/* Set up dispatcher */
    io_tv = memory_pool_alloc (new_session->session_pool, sizeof (struct timeval));
	io_tv->tv_sec = CONTROLLER_IO_TIMEOUT;
	io_tv->tv_usec = 0;

	new_session->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, controller_read_socket,
														controller_write_socket, controller_err_socket, io_tv,
														(void *)new_session);
	rspamd_dispatcher_write (new_session->dispatcher, greetingbuf, strlen (greetingbuf), FALSE, FALSE);
}

void
start_controller (struct rspamd_worker *worker)
{
	struct sigaction signals;
	int i;
	GList *comp_list = NULL;
	char *hostbuf;
	long int hostmax;

	worker->srv->pid = getpid ();
	event_init ();
	g_mime_init (0);

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *) worker);
	signal_add (&worker->sig_ev, NULL);

	
	start_time = time (NULL);

	/* Init command completion */
	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		comp_list = g_list_prepend (comp_list, &commands[i]);
	}
	comp = g_completion_new (completion_func);
	g_completion_add_items (comp, comp_list);
	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	snprintf (greetingbuf, sizeof (greetingbuf), "Rspamd version %s is running on %s" CRLF, RVERSION, hostbuf);
	/* Accept event */
	event_set(&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add(&worker->bind_ev, NULL);

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

	gperf_profiler_init (worker->srv->cfg, "controller");
	
	event_loop (0);

	exit (EXIT_SUCCESS);
}

void 
register_custom_controller_command (const char *name, controller_func_t handler, gboolean privilleged, gboolean require_message)
{
	struct custom_controller_command *cmd;
	
	cmd = g_malloc (sizeof (struct custom_controller_command));
	cmd->command = name;
	cmd->handler = handler;
	cmd->privilleged = privilleged;
	cmd->require_message = require_message;

	custom_commands = g_list_prepend (custom_commands, cmd);
}

/* 
 * vi:ts=4 
 */
