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
#include "binlog.h"
#include "statfile_sync.h"

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
	COMMAND_SYNC,
	COMMAND_WEIGHTS
};

struct controller_command {
	gchar                           *command;
	gboolean                        privilleged;
	enum command_type               type;
};

struct custom_controller_command {
	const gchar                     *command;
	gboolean                        privilleged;
	gboolean                        require_message;
	controller_func_t               handler;
};

static struct controller_command commands[] = {
	{"password", FALSE, COMMAND_PASSWORD},
	{"quit", FALSE, COMMAND_QUIT},
	{"reload", TRUE, COMMAND_RELOAD},
	{"stat", FALSE, COMMAND_STAT},
	{"shutdown", TRUE, COMMAND_SHUTDOWN},
	{"uptime", FALSE, COMMAND_UPTIME},
	{"learn", TRUE, COMMAND_LEARN},
	{"weights", FALSE, COMMAND_WEIGHTS},
	{"help", FALSE, COMMAND_HELP},
	{"counters", FALSE, COMMAND_COUNTERS},
	{"sync", FALSE, COMMAND_SYNC}
};

static GList                   *custom_commands = NULL;

static GCompletion             *comp;
static time_t                   start_time;

static gchar                     greetingbuf[1024];
static sig_atomic_t             wanna_die = 0;
extern rspamd_hash_t           *counters;

static gboolean                 controller_write_socket (void *arg);

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	struct timeval                  tv;
	switch (signo) {
	case SIGUSR1:
		reopen_log ();
		break;
	case SIGINT:
	case SIGTERM:
		if (!wanna_die) {
			wanna_die = 1;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			event_loopexit (&tv);

#ifdef WITH_GPERF_TOOLS
			ProfilerStop ();
#endif
		}
		break;
	}
}

static void
sigusr_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	msg_info ("controller's shutdown is pending in %d sec", 2);
	event_loopexit (&tv);
	return;
}

static gchar                   *
completion_func (gpointer elem)
{
	struct controller_command      *cmd = (struct controller_command *)elem;

	return cmd->command;
}

static void
free_session (void *ud)
{
	GList                          *part;
	struct mime_part               *p;
	struct controller_session      *session = ud;

	msg_debug ("freeing session %p", session);

	while ((part = g_list_first (session->parts))) {
		session->parts = g_list_remove_link (session->parts, part);
		p = (struct mime_part *)part->data;
		g_byte_array_free (p->content, FALSE);
		g_list_free_1 (part);
	}
	rspamd_remove_dispatcher (session->dispatcher);

	close (session->sock);

	memory_pool_delete (session->session_pool);
	g_free (session);
}

static gint
check_auth (struct controller_command *cmd, struct controller_session *session)
{
	gchar                           out_buf[128];
	gint                            r;

	if (cmd->privilleged && !session->authorized) {
		r = rspamd_snprintf (out_buf, sizeof (out_buf), "not authorized" CRLF);
		if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
			return 0;
		}
		return 0;
	}

	return 1;
}

static void
counter_write_callback (gpointer key, gpointer value, void *data)
{
	struct controller_session      *session = data;
	struct counter_data            *cd = value;
	gchar                           *name = key;
	gchar                           out_buf[128];
	gint                            r;

	r = rspamd_snprintf (out_buf, sizeof (out_buf), "%s: %uD" CRLF, name, (guint32)cd->value);
	if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, TRUE, FALSE)) {
		msg_warn ("cannot write to socket");
	}
}

static gboolean
write_whole_statfile (struct controller_session *session, gchar *symbol, struct classifier_config *ccf)
{
	stat_file_t                    *statfile;
	struct statfile                *st;
	gchar                           out_buf[BUFSIZ];
	gint                            i;
	guint64                         rev, ti, len, pos;
	gchar                           *out;
	struct rspamd_binlog_element    log_elt;
	struct stat_file_block         *stat_elt;

	statfile = get_statfile_by_symbol (session->worker->srv->statfile_pool, ccf,
						symbol, &st, FALSE);
	if (statfile == NULL) {
		return FALSE;
	}
	
	/* Begin to copy all blocks into array */
	statfile_get_revision (statfile, &rev, (time_t *)&ti);
	if (ti == 0) {
		/* Not tracked file */
		ti = time (NULL);
		statfile_set_revision (statfile, rev, ti);
	}
	len = statfile->cur_section.length * sizeof (struct rspamd_binlog_element);
	out = memory_pool_alloc (session->session_pool, len);

	for (i = 0, pos = 0; i < statfile->cur_section.length; i ++) {
		stat_elt = (struct stat_file_block *)((u_char *)statfile->map + statfile->seek_pos + i * sizeof (struct stat_file_block));
		if (fabs (stat_elt->value) > 0.001) {
			/* Write only those values which value is not 0 */
			log_elt.h1 = stat_elt->hash1;
			log_elt.h2 = stat_elt->hash2;
			log_elt.value = stat_elt->value;

			memcpy (out + pos, &log_elt, sizeof (log_elt));
			pos += sizeof (struct rspamd_binlog_element);
		}
	}

	i = rspamd_snprintf (out_buf, sizeof (out_buf), "%uL %uL %uL" CRLF, rev, ti, pos);
	if (! rspamd_dispatcher_write (session->dispatcher, out_buf, i, TRUE, FALSE)) {
		return FALSE;
	}

	if (!rspamd_dispatcher_write (session->dispatcher, out, pos, TRUE, TRUE)) {
		return FALSE;
	}
	
	return TRUE;
}

static gboolean
process_sync_command (struct controller_session *session, gchar **args)
{
	gchar                           out_buf[BUFSIZ], *arg, *err_str, *symbol;
	gint                            r;
	guint64                         rev, time;
	struct statfile                *st;
	struct classifier_config       *ccf;
	GList                          *cur;
	struct rspamd_binlog           *binlog;
	GByteArray                     *data = NULL;

	arg = *args;
	if (!arg || *arg == '\0') {
		msg_info ("bad arguments to sync command, need symbol");
		return FALSE;
	}
	symbol = arg;
	arg = *(args + 1);
	if (!arg || *arg == '\0') {
		msg_info ("bad arguments to sync command, need revision");
		return FALSE;
	}
	rev = strtoull (arg, &err_str, 10);
	if (err_str && *err_str != 0) {
		msg_info ("bad arguments to sync command: %s", arg);
		return FALSE;
	}
	arg = *(args + 2);
	if (!arg || *arg == '\0') {
		msg_info ("bad arguments to sync command, need time");
		return FALSE;
	}
	time = strtoull (arg, &err_str, 10);
	if (err_str && *err_str != 0) {
		msg_info ("bad arguments to sync command: %s", arg);
		return FALSE;
	}

	ccf = g_hash_table_lookup (session->cfg->classifiers_symbols, symbol);
	if (ccf == NULL) {
		msg_info ("bad symbol: %s", symbol);
		return FALSE;
	}
	
	cur = g_list_first (ccf->statfiles);
	while (cur) {
		st = cur->data;
		if (strcmp (symbol, st->symbol) == 0) {
			break;
		}
		st = NULL;
		cur = g_list_next (cur);
	}
    if (st == NULL) {
		msg_info ("bad symbol: %s", symbol);
        return FALSE;
    }
	
	binlog = get_binlog_by_statfile (st);
	if (binlog == NULL) {
		msg_info ("cannot open binlog: %s", symbol);
        return FALSE;
	}
	
	while (binlog_sync (binlog, rev, &time, &data)) {
		r = rspamd_snprintf (out_buf, sizeof (out_buf), "%uL %uL %z" CRLF, rev, time, data->len);
		if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
			if (data != NULL) {
				g_free (data);
			}
			return FALSE;
		}
		if (data->data != NULL) {
			if (!rspamd_dispatcher_write (session->dispatcher, data->data, data->len, TRUE, FALSE)) {
				if (data != NULL) {
					g_free (data);
				}
				return FALSE;
			}
		}
		rev ++;
	}

	if (time == 0) {
		if (data != NULL) {
			g_free (data);
		}
		return write_whole_statfile (session, symbol, ccf);
	}

	if (data != NULL) {
		g_free (data);
	}

	return TRUE;
}

static gboolean
process_stat_command (struct controller_session *session)
{
	gchar                           out_buf[BUFSIZ], *numbuf;
	gint                            r;
	guint64                         used, total, rev;
	time_t                          ti;
	memory_pool_stat_t              mem_st;
	struct classifier_config       *ccf;
	stat_file_t                    *statfile;
	struct statfile                *st;
	GList                          *cur_cl, *cur_st;

	memory_pool_stat (&mem_st);
	r = rspamd_snprintf (out_buf, sizeof (out_buf), "Messages scanned: %ud" CRLF, session->worker->srv->stat->messages_scanned);
	if (session->worker->srv->stat->messages_scanned > 0) {
		r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages treated as spam: %ud, %.2f%%" CRLF, session->worker->srv->stat->messages_spam,
								(double)session->worker->srv->stat->messages_spam / (double)session->worker->srv->stat->messages_scanned * 100.);
		r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages treated as ham: %ud, %.2f%%" CRLF, session->worker->srv->stat->messages_ham,
								(double)session->worker->srv->stat->messages_ham / (double)session->worker->srv->stat->messages_scanned * 100.);
	}
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages learned: %ud" CRLF, session->worker->srv->stat->messages_learned);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Connections count: %ud" CRLF, session->worker->srv->stat->connections_count);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Control connections count: %ud" CRLF, session->worker->srv->stat->control_connections_count);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Pools allocated: %z" CRLF, mem_st.pools_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Pools freed: %z" CRLF, mem_st.pools_freed);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Bytes allocated: %z" CRLF, mem_st.bytes_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Memory chunks allocated: %z" CRLF, mem_st.chunks_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Shared chunks allocated: %z" CRLF, mem_st.shared_chunks_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Chunks freed: %z" CRLF, mem_st.chunks_freed);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Oversized chunks: %z" CRLF, mem_st.oversized_chunks);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Fuzzy hashes stored: %ud" CRLF, session->worker->srv->stat->fuzzy_hashes);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Fuzzy hashes expired: %ud" CRLF, session->worker->srv->stat->fuzzy_hashes_expired);
	/* Now write statistics for each statfile */
	cur_cl = g_list_first (session->cfg->classifiers);
	while (cur_cl) {
		ccf = cur_cl->data;
		cur_st = g_list_first (ccf->statfiles);
		while (cur_st) {
			st = cur_st->data;
			if ((statfile = statfile_pool_is_open (session->worker->srv->statfile_pool, st->path)) == NULL) {
				statfile = statfile_pool_open (session->worker->srv->statfile_pool, st->path, st->size, FALSE);
			}
			if (statfile) {
				used = statfile_get_used_blocks (statfile);
				total = statfile_get_total_blocks (statfile);
				statfile_get_revision (statfile, &rev, &ti);
				if (total != (guint64)-1 && used != (guint64)-1) {
					numbuf = g_format_size_for_display (st->size);
					r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, 
							"Statfile: %s (version %uL); length: %s; free blocks: %uL; total blocks: %uL; free: %.2f%%" CRLF,
							st->symbol, rev, numbuf, 
							(total - used), total,
							(double)((double)(total - used) / (double)total) * 100.);
					g_free (numbuf);
				}
			}
			cur_st = g_list_next (cur_st);
		}
		cur_cl = g_list_next (cur_cl);
	}

	return rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
}

static gboolean
process_command (struct controller_command *cmd, gchar **cmd_args, struct controller_session *session)
{
	gchar                           out_buf[BUFSIZ], *arg, *err_str;
	gint                            r = 0, days, hours, minutes;
	time_t                          uptime;
	guint32                   size = 0;
	struct classifier_config       *cl;
	gchar                           *password = g_hash_table_lookup (session->worker->cf->params, "password");

	switch (cmd->type) {
	case COMMAND_PASSWORD:
		arg = *cmd_args;
		if (!arg || *arg == '\0') {
			msg_debug ("empty password passed");
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password command requires one argument" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		if (password == NULL) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password command disabled in config, authorized access unallowed" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		if (strncmp (arg, password, strlen (arg)) == 0) {
			session->authorized = 1;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password accepted" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		else {
			session->authorized = 0;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password NOT accepted" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		break;
	case COMMAND_QUIT:
		session->state = STATE_QUIT;
		break;
	case COMMAND_RELOAD:
		if (check_auth (cmd, session)) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "reload request sent" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			kill (getppid (), SIGHUP);
		}
		break;
	case COMMAND_STAT:
		if (check_auth (cmd, session)) {
			return process_stat_command (session);
		}
		break;
	case COMMAND_SHUTDOWN:
		if (check_auth (cmd, session)) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "shutdown request sent" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			kill (getppid (), SIGTERM);
		}
		break;
	case COMMAND_UPTIME:
		if (check_auth (cmd, session)) {
			uptime = time (NULL) - start_time;
			/* If uptime more than 2 hours, print as a number of days. */
			if (uptime >= 2 * 3600) {
				days = uptime / 86400;
				hours = uptime / 3600 - days * 24;
				minutes = uptime / 60 - hours * 60 - days * 1440;
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "%d day%s %d hour%s %d minute%s" CRLF, days, days > 1 ? "s" : " ", hours, hours > 1 ? "s" : " ", minutes, minutes > 1 ? "s" : " ");
			}
			/* If uptime is less than 1 minute print only seconds */
			else if (uptime / 60 == 0) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "%d second%s" CRLF, (gint)uptime, (gint)uptime > 1 ? "s" : " ");
			}
			/* Else print the minutes and seconds. */
			else {
				hours = uptime / 3600;
				minutes = uptime / 60 - hours * 60;
				uptime -= hours * 3600 + minutes * 60;
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "%d hour%s %d minute%s %d second%s" CRLF, hours, hours > 1 ? "s" : " ", minutes, minutes > 1 ? "s" : " ", (gint)uptime, uptime > 1 ? "s" : " ");
			}
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		break;
	case COMMAND_LEARN:
		if (check_auth (cmd, session)) {
			arg = *cmd_args;
			if (!arg || *arg == '\0') {
				msg_debug ("no statfile specified in learn command");
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;
			}
			arg = *(cmd_args + 1);
			if (arg == NULL || *arg == '\0') {
				msg_debug ("no statfile size specified in learn command");
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: stat filename and its size" CRLF);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;
			}
			size = strtoul (arg, &err_str, 10);
			if (err_str && *err_str != '\0') {
				msg_debug ("message size is invalid: %s", arg);
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;
			}

			session->learn_symbol = memory_pool_strdup (session->session_pool, *cmd_args);
			cl = g_hash_table_lookup (session->cfg->classifiers_symbols, *cmd_args);
			if (cl == NULL) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "statfile %s is not defined" CRLF, *cmd_args);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;

			}
			session->learn_classifier = cl;

			/* By default learn positive */
			session->in_class = 1;
			session->learn_multiplier = 1.;
			/* Get all arguments */
			while (*cmd_args++) {
				arg = *cmd_args;
				if (arg && *arg == '-') {
					switch (*(arg + 1)) {
					case 'r':
						arg = *(cmd_args + 1);
						if (!arg || *arg == '\0') {
							r = rspamd_snprintf (out_buf, sizeof (out_buf), "recipient is not defined" CRLF);
							if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
								return FALSE;
							}
						}
						session->learn_rcpt = memory_pool_strdup (session->session_pool, arg);
						break;
					case 'f':
						arg = *(cmd_args + 1);
						if (!arg || *arg == '\0') {
							r = rspamd_snprintf (out_buf, sizeof (out_buf), "from is not defined" CRLF);
							if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
								return FALSE;
							}
						}
						session->learn_from = memory_pool_strdup (session->session_pool, arg);
						break;
					case 'n':
						session->in_class = 0;
						break;
					case 'm':
						arg = *(cmd_args + 1);
						if (!arg || *arg == '\0') {
							r = rspamd_snprintf (out_buf, sizeof (out_buf), "multiplier is not defined" CRLF);
							if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
								return FALSE;
							}
						}
						session->learn_multiplier = strtod (arg, NULL);
						break;
					default:
						r = rspamd_snprintf (out_buf, sizeof (out_buf), "tokenizer is not defined" CRLF);
						if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
							return FALSE;
						}
						return TRUE;
					}
				}
			}
			rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
			session->state = STATE_LEARN;
		}
		break;

	case COMMAND_WEIGHTS:
		arg = *cmd_args;
		if (!arg || *arg == '\0') {
			msg_debug ("no statfile specified in weights command");
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "weights command requires two arguments: statfile and message size" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		arg = *(cmd_args + 1);
		if (arg == NULL || *arg == '\0') {
			msg_debug ("no message size specified in weights command");
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "weights command requires two arguments: statfile and message size" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		size = strtoul (arg, &err_str, 10);
		if (err_str && *err_str != '\0') {
			msg_debug ("message size is invalid: %s", arg);
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "message size is invalid" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}

		cl = g_hash_table_lookup (session->cfg->classifiers_symbols, *cmd_args);
		if (cl == NULL) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "statfile %s is not defined" CRLF, *cmd_args);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;

		}
		session->learn_classifier = cl;

		rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
		session->state = STATE_WEIGHTS;
		break;
	case COMMAND_SYNC:
		if (!process_sync_command (session, cmd_args)) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "FAIL" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		else {
			if (! rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) - 1, FALSE, TRUE)) {
				return FALSE;
			}
			return TRUE;
		}
		break;
	case COMMAND_HELP:
		r = rspamd_snprintf (out_buf, sizeof (out_buf),
			"Rspamd CLI commands (* - privileged command):" CRLF
			"    help - this help message" CRLF
			"(*) learn <statfile> <size> [-r recipient] [-m multiplier] [-f from] [-n] - learn message to specified statfile" CRLF
			"    quit - quit CLI session" CRLF
			"    password <password> - authenticate yourself for privileged commands" CRLF
			"(*) reload - reload rspamd" CRLF
			"(*) shutdown - shutdown rspamd" CRLF 
			"    stat - show different rspamd stat" CRLF
			"    sync - run synchronization of statfiles" CRLF
			"    counters - show rspamd counters" CRLF 
			"    uptime - rspamd uptime" CRLF
			"    weights <statfile> <size> - weight of message in all statfiles");
		if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
			return FALSE;
		}
		break;
	case COMMAND_COUNTERS:
		rspamd_hash_foreach (counters, counter_write_callback, session);
		break;
	}
	return TRUE;
}

static                          gboolean
process_custom_command (gchar *line, gchar **cmd_args, struct controller_session *session)
{
	GList                          *cur;
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

static                          gboolean
controller_read_socket (f_str_t * in, void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;
	struct classifier_ctx          *cls_ctx;
	stat_file_t                    *statfile;
	struct statfile                *st;
	gint                            len, i, r;
	gchar                           *s, **params, *cmd, out_buf[128];
	struct worker_task             *task;
	struct mime_text_part          *part;
	GList                          *comp_list, *cur = NULL;
	GTree                          *tokens = NULL;
	GError                         *err = NULL;
	f_str_t                         c;
	double                          sum;

	switch (session->state) {
	case STATE_COMMAND:
		s = fstrcstr (in, session->session_pool);
		params = g_strsplit_set (s, " ", -1);

		memory_pool_add_destructor (session->session_pool, (pool_destruct_func) g_strfreev, params);

		len = g_strv_length (params);
		if (len > 0) {
			cmd = g_strstrip (params[0]);
			comp_list = g_completion_complete (comp, cmd, NULL);
			switch (g_list_length (comp_list)) {
			case 1:
				if (! process_command ((struct controller_command *)comp_list->data, &params[1], session)) {
					return FALSE;
				}
				break;
			case 0:
				if (!process_custom_command (cmd, &params[1], session)) {
					msg_debug ("'%s'", cmd);
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "Unknown command" CRLF);
					if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
						return FALSE;
					}
				}
				break;
			default:
				msg_debug ("'%s'", cmd);
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "Ambigious command" CRLF);
				if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
					return FALSE;
				}
				break;
			}
		}
		if (session->state == STATE_COMMAND) {
			session->state = STATE_REPLY;
		}
		if (session->state != STATE_LEARN && session->state != STATE_WEIGHTS && session->state != STATE_OTHER) {
			if (!rspamd_dispatcher_write (session->dispatcher, END, sizeof (END) - 1, FALSE, TRUE)) {
				return FALSE;
			}
		}

		break;
	case STATE_LEARN:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;

		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			free_task (task, FALSE);
			session->state = STATE_REPLY;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return FALSE;
		}
		if ((s = g_hash_table_lookup (session->learn_classifier->opts, "header")) != NULL) {
			cur = message_get_header (task->task_pool, task->message, s);
			if (cur) {
				memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
			}
		}
		else {
			cur = g_list_first (task->text_parts);
		}
		while (cur) {
			if (s != NULL) {
				c.len = strlen (cur->data);
				c.begin = cur->data;
			}
			else {
				part = cur->data;
				if (part->is_empty) {
					cur = g_list_next (cur);
					continue;
				}
				c.begin = part->content->data;
				c.len = part->content->len;
			}
			if (!session->learn_classifier->tokenizer->tokenize_func (session->learn_classifier->tokenizer, session->session_pool, &c, &tokens)) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, tokenizer error" CRLF);
				free_task (task, FALSE);
				if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
					return FALSE;
				}
				session->state = STATE_REPLY;
				return TRUE;
			}
			cur = g_list_next (cur);
		}
		
		/* Handle messages without text */
		if (tokens == NULL) {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, no tokens can be extracted (no text data)" CRLF);
			msg_info ("learn failed for message <%s>, no tokens to extract", task->message_id);
			free_task (task, FALSE);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			session->state = STATE_REPLY;
			return TRUE;
		}
	

		/* Init classifier */
		cls_ctx = session->learn_classifier->classifier->init_func (session->session_pool, session->learn_classifier);
		/* Get or create statfile */
		statfile = get_statfile_by_symbol (session->worker->srv->statfile_pool, session->learn_classifier,
				session->learn_symbol, &st, TRUE);

		if (statfile == NULL ||
			! session->learn_classifier->classifier->learn_func (cls_ctx, session->worker->srv->statfile_pool,
																session->learn_symbol, tokens, session->in_class, &sum,
																session->learn_multiplier, &err)) {
			if (err) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF, err->message);
				msg_info ("learn failed for message <%s>, learn error: %s", task->message_id, err->message);
				g_error_free (err);
			}
			else {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, unknown learn classifier error" CRLF);
				msg_info ("learn failed for message <%s>, unknown learn error", task->message_id);
			}
			free_task (task, FALSE);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			session->state = STATE_REPLY;
			return TRUE;
		}
		session->worker->srv->stat->messages_learned++;

		maybe_write_binlog (session->learn_classifier, st, statfile, tokens);
		msg_info ("learn success for message <%s>, for statfile: %s, sum weight: %.2f",
				task->message_id, session->learn_symbol, sum);
		statfile_pool_plan_invalidate (session->worker->srv->statfile_pool, DEFAULT_STATFILE_INVALIDATE_TIME, DEFAULT_STATFILE_INVALIDATE_JITTER);
		free_task (task, FALSE);
		i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok, sum weight: %.2f" CRLF, sum);
		if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
			return FALSE;
		}

		session->state = STATE_REPLY;
		break;
	case STATE_WEIGHTS:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;

		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			free_task (task, FALSE);
			session->state = STATE_REPLY;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return FALSE;
		}

		cur = g_list_first (task->text_parts);
		while (cur) {
			part = cur->data;
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}

			c.begin = part->content->data;
			c.len = part->content->len;
			if (!session->learn_classifier->tokenizer->tokenize_func (session->learn_classifier->tokenizer, session->session_pool, &c, &tokens)) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "weights failed, tokenizer error" CRLF);
				free_task (task, FALSE);
				if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
					return FALSE;
				}
				session->state = STATE_REPLY;
				return TRUE;
			}
			cur = g_list_next (cur);
		}
		
		/* Handle messages without text */
		if (tokens == NULL) {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "weights failed, no tokens can be extracted (no text data)" CRLF);
			free_task (task, FALSE);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			session->state = STATE_REPLY;
			return TRUE;
		}
	
		
		/* Init classifier */
		cls_ctx = session->learn_classifier->classifier->init_func (session->session_pool, session->learn_classifier);
		
		cur = session->learn_classifier->classifier->weights_func (cls_ctx, session->worker->srv->statfile_pool, 
																	tokens, task);
		i = 0;
		struct classify_weight *w;

		while (cur) {
			w = cur->data;
			i += rspamd_snprintf (out_buf + i, sizeof (out_buf) - i, "%s: %G" CRLF, w->name, w->weight);
			cur = g_list_next (cur);
		}
		if (i != 0) {
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
		}
		else {
			if (!rspamd_dispatcher_write (session->dispatcher, "weights failed: classifier error", 0, FALSE, TRUE)) {
				return FALSE;
			}
		}

		free_task (task, FALSE);

		session->state = STATE_REPLY;
		break;
	case STATE_OTHER:
		if (session->other_handler) {
			session->other_handler (session, in);
		}
		rspamd_dispatcher_pause (session->dispatcher);
		break;
	case STATE_WAIT:
		rspamd_dispatcher_pause (session->dispatcher);
		break;
	default:
		msg_debug ("unknown state while reading %d", session->state);
		break;
	}

	if (session->state == STATE_REPLY || session->state == STATE_QUIT) {
		return controller_write_socket (session);
	}

	return TRUE;
}

static                          gboolean
controller_write_socket (void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;

	if (session->state == STATE_QUIT) {
		/* Free buffers */
		destroy_session (session->s);
		return FALSE;
	}
	else if (session->state == STATE_REPLY) {
		session->state = STATE_COMMAND;
		rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, BUFSIZ);
	}
	return TRUE;
}

static void
controller_err_socket (GError * err, void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;

	if (err->code != EOF) {
		msg_info ("abnormally closing control connection, error: %s", err->message);
	}

	/* Free buffers */
	destroy_session (session->s);
}

static void
accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage         ss;
	struct controller_session      *new_session;
	struct timeval                 *io_tv;
	socklen_t                       addrlen = sizeof (ss);
	gint                            nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}

	new_session = g_malloc (sizeof (struct controller_session));
	if (new_session == NULL) {
		msg_err ("cannot allocate memory for task, %s", strerror (errno));
		return;
	}
	bzero (new_session, sizeof (struct controller_session));
	new_session->worker = worker;
	new_session->sock = nfd;
	new_session->cfg = worker->srv->cfg;
	new_session->state = STATE_COMMAND;
	new_session->session_pool = memory_pool_new (memory_pool_get_size () - 1);
	worker->srv->stat->control_connections_count++;

	/* Set up dispatcher */
	io_tv = memory_pool_alloc (new_session->session_pool, sizeof (struct timeval));
	io_tv->tv_sec = CONTROLLER_IO_TIMEOUT;
	io_tv->tv_usec = 0;

	new_session->s = new_async_session (new_session->session_pool, free_session, new_session);

	new_session->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, controller_read_socket, controller_write_socket, controller_err_socket, io_tv, (void *)new_session);
	if (! rspamd_dispatcher_write (new_session->dispatcher, greetingbuf, strlen (greetingbuf), FALSE, FALSE)) {
		msg_warn ("cannot write greeting");
	}
}

void
start_controller (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	gint                            i;
	GList                          *comp_list = NULL;
	gchar                          *hostbuf;
	gsize                           hostmax;

	worker->srv->pid = getpid ();
	event_init ();
	g_mime_init (0);

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	signal_add (&worker->sig_ev, NULL);


	start_time = time (NULL);

	/* Start statfile synchronization */
	if (!start_statfile_sync (worker->srv->statfile_pool, worker->srv->cfg)) {
		msg_info ("cannot start statfile synchronization, statfiles would not be synchronized");
	}

	/* Init command completion */
	for (i = 0; i < G_N_ELEMENTS (commands); i++) {
		comp_list = g_list_prepend (comp_list, &commands[i]);
	}
	comp = g_completion_new (completion_func);
	g_completion_add_items (comp, comp_list);
	g_completion_set_compare (comp, g_ascii_strncasecmp);
	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	rspamd_snprintf (greetingbuf, sizeof (greetingbuf), "Rspamd version %s is running on %s" CRLF, RVERSION, hostbuf);
	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	gperf_profiler_init (worker->srv->cfg, "controller");

	event_loop (0);

	exit (EXIT_SUCCESS);
}

void
register_custom_controller_command (const gchar *name, controller_func_t handler, gboolean privilleged, gboolean require_message)
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
