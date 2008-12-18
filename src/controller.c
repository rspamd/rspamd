#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <netinet/in.h>
#include <syslog.h>
#include <fcntl.h>
#include <netdb.h>

#include <glib.h>

#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "modules.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"

#define CRLF "\r\n"

enum command_type {
	COMMAND_PASSWORD,
	COMMAND_QUIT,
	COMMAND_RELOAD,
	COMMAND_STAT,
	COMMAND_SHUTDOWN,
	COMMAND_UPTIME,
	COMMAND_LEARN,
};

struct controller_command {
	char *command;
	int privilleged;
	enum command_type type;
};

static struct controller_command commands[] = {
	{"password", 0, COMMAND_PASSWORD},
	{"quit", 0, COMMAND_QUIT},
	{"reload", 1, COMMAND_RELOAD},
	{"stat", 0, COMMAND_STAT},
	{"shutdown", 1, COMMAND_SHUTDOWN},
	{"uptime", 0, COMMAND_UPTIME},
	{"learn", 1, COMMAND_LEARN},
};

static GCompletion *comp;
static time_t start_time;

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
	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	msg_info ("controller's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
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
free_session (struct controller_session *session)
{
	bufferevent_disable (session->bev, EV_READ | EV_WRITE);
	bufferevent_free (session->bev);
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
		bufferevent_write (session->bev, out_buf, r);
		return 0;
	}

	return 1;
}

static void
process_command (struct controller_command *cmd, char **cmd_args, struct controller_session *session)
{
	char out_buf[512], *arg, *err_str;
	int r = 0, days, hours, minutes;
	time_t uptime;
	unsigned long size = 0;
	struct statfile *statfile;

	switch (cmd->type) {
		case COMMAND_PASSWORD:
			arg = *cmd_args;
			if (!arg || *arg == '\0') {
				msg_debug ("process_command: empty password passed");
				r = snprintf (out_buf, sizeof (out_buf), "password command requires one argument" CRLF);
				bufferevent_write (session->bev, out_buf, r);
				return;
			}
			if (strncmp (arg, session->cfg->control_password, strlen (arg)) == 0) {
				session->authorized = 1;
				r = snprintf (out_buf, sizeof (out_buf), "password accepted" CRLF);
				bufferevent_write (session->bev, out_buf, r);
			}
			else {
				session->authorized = 0;
				r = snprintf (out_buf, sizeof (out_buf), "password NOT accepted" CRLF);
				bufferevent_write (session->bev, out_buf, r);
			}
			break;
		case COMMAND_QUIT:
			free_session (session);
			break;
		case COMMAND_RELOAD:
			if (check_auth (cmd, session)) {
				r = snprintf (out_buf, sizeof (out_buf), "reload request sent" CRLF);
				bufferevent_write (session->bev, out_buf, r);
				kill (getppid (), SIGHUP);
			}
			break;
		case COMMAND_STAT:
			/* XXX need to implement stat */
			if (check_auth (cmd, session)) {
				r = snprintf (out_buf, sizeof (out_buf), "-- end of stats report" CRLF);
				bufferevent_write (session->bev, out_buf, r);
			}
		case COMMAND_SHUTDOWN:
			if (check_auth (cmd, session)) {
				r = snprintf (out_buf, sizeof (out_buf), "shutdown request sent" CRLF);
				bufferevent_write (session->bev, out_buf, r);
				kill (getppid (), SIGTERM);
			}
			break;
		case COMMAND_UPTIME:
			if (check_auth (cmd, session)) {
				uptime = time (NULL) - start_time;
				/* If uptime more than 2 hours, print as a number of days. */
 				if (uptime >= 2 * 3600) {
					days = uptime / 86400;
					hours = (uptime % 3600) / 60;
					minutes = (uptime % 60) / 60;
					r = snprintf (out_buf, sizeof (out_buf), "%dday%s %dhour%s %dminute%s" CRLF, 
								days, days > 1 ? "s" : " ",
								hours, hours > 1 ? "s" : " ",
								minutes, minutes > 1 ? "s" : " ");
				}
				/* If uptime is less than 1 minute print only seconds */
				else if (uptime / 60 == 0) {
					r = snprintf (out_buf, sizeof (out_buf), "%dsecond%s", (int)uptime, (int)uptime > 1 ? "s" : " ");
				}
				/* Else print the minutes and seconds. */
				else {
					hours = uptime / 3600;
					minutes = (uptime % 60) / 60;
					r = snprintf (out_buf, sizeof (out_buf), "%dhour%s %dminite%s %dsecond%s", 
								hours, hours > 1 ? "s" : " ",
								minutes, minutes > 1 ? "s" : " ",
								(int)uptime, uptime > 1 ? "s" : " ");
				}
				bufferevent_write (session->bev, out_buf, r);
			}
			break;
		case COMMAND_LEARN:
			if (check_auth (cmd, session)) {
				arg = *cmd_args++;
				if (!arg || *arg == '\0') {
					msg_debug ("process_command: no statfile specified in learn command");
					r = snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
					bufferevent_write (session->bev, out_buf, r);
					return;
				}
				arg = *cmd_args;
				if (arg == NULL || *arg == '\0') {
					msg_debug ("process_command: no statfile size specified in learn command");
					r = snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
					bufferevent_write (session->bev, out_buf, r);
					return;
				}
				size = strtoul (arg, &err_str, 10);
				if (err_str && *err_str != '\0') {
					msg_debug ("process_command: statfile size is invalid: %s", arg);
					r = snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
					bufferevent_write (session->bev, out_buf, r);
					return;
				}
				session->learn_buf = memory_pool_alloc (session->session_pool, sizeof (f_str_buf_t));
				session->learn_buf->buf = fstralloc (session->session_pool, size);
				if (session->learn_buf->buf == NULL) {
					r = snprintf (out_buf, sizeof (out_buf), "allocating buffer for learn failed" CRLF);
					bufferevent_write (session->bev, out_buf, r);
					return;
				}

				statfile = g_hash_table_lookup (session->cfg->statfiles, arg);
				if (statfile == NULL) {
					r = snprintf (out_buf, sizeof (out_buf), "statfile %s is not defined" CRLF, arg);
					bufferevent_write (session->bev, out_buf, r);
					return;

				}
				session->learn_rcpt = NULL;
				session->learn_from = NULL;
				session->learn_filename = NULL;
				session->learn_tokenizer = statfile->tokenizer;
				session->learn_classifier = statfile->classifier;
				/* By default learn positive */
				session->in_class = 1;
				/* Get all arguments */
				while (*cmd_args++) {
					arg = *cmd_args;
					if (*arg == '-') {
						switch (*(arg + 1)) {
							case 'r':
								arg = *(cmd_args + 1);
								if (!arg || *arg == '\0') {
									r = snprintf (out_buf, sizeof (out_buf), "recipient is not defined" CRLF, arg);
									bufferevent_write (session->bev, out_buf, r);
									return;
								}
								session->learn_rcpt = memory_pool_strdup (session->session_pool, arg);
								break;
							case 'f':
								arg = *(cmd_args + 1);
								if (!arg || *arg == '\0') {
									r = snprintf (out_buf, sizeof (out_buf), "from is not defined" CRLF, arg);
									bufferevent_write (session->bev, out_buf, r);
									return;
								}
								session->learn_from = memory_pool_strdup (session->session_pool, arg);
								break;
							case 'n':
								session->in_class = 0;
								break;
							default:
								r = snprintf (out_buf, sizeof (out_buf), "tokenizer is not defined" CRLF, arg);
								bufferevent_write (session->bev, out_buf, r);
								return;
						}
					}
				}
				session->learn_filename = resolve_stat_filename (session->session_pool, statfile->pattern, session->learn_rcpt, session->learn_from);
				if (statfile_pool_open (session->worker->srv->statfile_pool, session->learn_filename) == -1) {
					/* Try to create statfile */
					if (statfile_pool_create (session->worker->srv->statfile_pool, session->learn_filename, statfile->size) == -1) {
						r = snprintf (out_buf, sizeof (out_buf), "cannot create statfile %s" CRLF, session->learn_filename);
						bufferevent_write (session->bev, out_buf, r);
						return;
					}
					if (statfile_pool_open (session->worker->srv->statfile_pool, session->learn_filename) == -1) {
						r = snprintf (out_buf, sizeof (out_buf), "cannot open statfile %s" CRLF, session->learn_filename);
						bufferevent_write (session->bev, out_buf, r);
						return;
					}
				}
				session->state = STATE_LEARN;
				r = snprintf (out_buf, sizeof (out_buf), "ok" CRLF);
				bufferevent_write (session->bev, out_buf, r);
				break;
			}
	}
}

static void
read_socket (struct bufferevent *bev, void *arg)
{
	struct controller_session *session = (struct controller_session *)arg;
	int len, i;
	char *s, **params, *cmd, out_buf[128];
	GList *comp_list;
	GTree *tokens;

	switch (session->state) {
		case STATE_COMMAND:
			s = evbuffer_readline (EVBUFFER_INPUT (bev));
			msg_debug ("read_socket: got '%s' string from user", s);
			if (s != NULL && *s != 0) {
				len = strlen (s);
				/* Remove end of line characters from string */
				if (s[len - 1] == '\n') {
					if (s[len - 2] == '\r') {
						s[len - 2] = 0;
					}
					s[len - 1] = 0;
				}
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
							msg_debug ("Unknown command: '%s'", cmd);
							i = snprintf (out_buf, sizeof (out_buf), "Unknown command" CRLF);
							bufferevent_write (bev, out_buf, i);
							break;
						default:
							msg_debug ("Ambigious command: '%s'", cmd);
							i = snprintf (out_buf, sizeof (out_buf), "Ambigious command" CRLF);
							bufferevent_write (bev, out_buf, i);
							break;
					}
				}
				g_strfreev (params);
			}
			if (s != NULL) {
				free (s);
			}
			break;
		case STATE_LEARN:
			i = bufferevent_read (bev, session->learn_buf->pos, session->learn_buf->free);
			if (i > 0) {
				session->learn_buf->pos += i;
				update_buf_size (session->learn_buf);
				if (session->learn_buf->free == 0) {
					tokens = session->learn_tokenizer->tokenize_func (session->learn_tokenizer, session->session_pool, session->learn_buf->buf);
					if (tokens == NULL) {
						i = snprintf (out_buf, sizeof (out_buf), "learn fail, tokenizer error" CRLF);
						bufferevent_write (bev, out_buf, i);
						session->state = STATE_COMMAND;
						return;
					}
					session->learn_classifier->learn_func (session->worker->srv->statfile_pool, session->learn_filename, tokens, session->in_class);
					session->worker->srv->stat->messages_learned ++;
					i = snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF);
					bufferevent_write (bev, out_buf, i);
					session->state = STATE_COMMAND;
					break;
				}
			}
			else {
				i = snprintf (out_buf, sizeof (out_buf), "read error: %d" CRLF, i);
				bufferevent_write (bev, out_buf, i);
				bufferevent_disable (bev, EV_READ);
				free_session (session);
			}
			break;
	}
}

static void
write_socket (struct bufferevent *bev, void *arg)
{
	char buf[1024], hostbuf[256];

	gethostname (hostbuf, sizeof (hostbuf - 1));
	hostbuf[sizeof (hostbuf) - 1] = '\0';
	snprintf (buf, sizeof (buf), "Rspamd version %s is running on %s" CRLF, RVERSION, hostbuf);
	bufferevent_disable (bev, EV_WRITE);
	bufferevent_enable (bev, EV_READ);
}

static void
err_socket (struct bufferevent *bev, short what, void *arg)
{
	struct controller_session *session = (struct controller_session *)arg;
	msg_info ("closing control connection");
	/* Free buffers */
	free_session (session);
}

static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage ss;
	struct controller_session *new_session;
	socklen_t addrlen = sizeof(ss);
	int nfd;

	if ((nfd = accept (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		return;
	}
	if (event_make_socket_nonblocking(fd) < 0) {
		return;
	}
	
	new_session = g_malloc (sizeof (struct controller_session));
	if (new_session == NULL) {
		msg_err ("accept_socket: cannot allocate memory for task, %m");
		return;
	}
	bzero (new_session, sizeof (struct controller_session));
	new_session->worker = worker;
	new_session->sock = nfd;
	new_session->cfg = worker->srv->cfg;
	new_session->state = STATE_COMMAND;
	new_session->session_pool = memory_pool_new (memory_pool_get_size () - 1);
	worker->srv->stat->control_connections_count ++;

	/* Read event */
	new_session->bev = bufferevent_new (nfd, read_socket, write_socket, err_socket, (void *)new_session);
	bufferevent_enable (new_session->bev, EV_WRITE);
}

void
start_controller (struct rspamd_worker *worker)
{
	struct sigaction signals;
	int listen_sock, i;
	struct sockaddr_un *un_addr;
	GList *comp_list = NULL;

	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_CONTROLLER;
	event_init ();
	g_mime_init (0);

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *) worker);
	signal_add (&worker->sig_ev, NULL);

	if (worker->srv->cfg->control_family == AF_INET) {
		if ((listen_sock = make_socket (&worker->srv->cfg->control_addr, worker->srv->cfg->control_port)) == -1) {
			msg_err ("start_controller: cannot create tcp listen socket. %m");
			exit(-errno);
		}
	}
	else {
		un_addr = (struct sockaddr_un *) alloca (sizeof (struct sockaddr_un));
		if (!un_addr || (listen_sock = make_unix_socket (worker->srv->cfg->bind_host, un_addr)) == -1) {
			msg_err ("start_controller: cannot create unix listen socket. %m");
			exit(-errno);
		}
	}
	
	start_time = time (NULL);

	if (listen (listen_sock, -1) == -1) {
		msg_err ("start_controller: cannot listen on socket. %m");
		exit(-errno);
	}
	
	/* Init command completion */
	for (i = 0; i < sizeof (commands) / sizeof (commands[0]) - 1; i ++) {
		comp_list = g_list_prepend (comp_list, &commands[i]);
	}
	comp = g_completion_new (completion_func);
	g_completion_add_items (comp, comp_list);
	/* Accept event */
	event_set(&worker->bind_ev, listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add(&worker->bind_ev, NULL);

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

	event_loop (0);
}


/* 
 * vi:ts=4 
 */
