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
#include "cfg_xml.h"
#include "modules.h"
#include "map.h"
#include "dns.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"
#include "binlog.h"
#include "statfile_sync.h"
#include "lua/lua_common.h"

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
	COMMAND_LEARN_SPAM,
	COMMAND_LEARN_HAM,
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

struct rspamd_controller_ctx {
	char 						   *password;
	guint32							timeout;
	struct rspamd_dns_resolver     *resolver;
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
	{"sync", FALSE, COMMAND_SYNC},
	{"learn_spam", TRUE, COMMAND_LEARN_SPAM},
	{"learn_ham", TRUE, COMMAND_LEARN_HAM}
};

static GList                   *custom_commands = NULL;

static time_t                   start_time;

static gchar                    greetingbuf[1024];
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
		reopen_log (rspamd_main->logger);
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
	guint64                         rev, ti, len, pos, blocks;
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
	msg_info ("send a whole statfile %s with version %uL to slave", symbol, rev);

	blocks = statfile_get_total_blocks (statfile);
	len = blocks * sizeof (struct rspamd_binlog_element);
	out = memory_pool_alloc (session->session_pool, len);

	for (i = 0, pos = 0; i < blocks; i ++) {
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
	struct statfile                *st = NULL;
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
		rev ++;
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
	guint32                   		size = 0;
	struct classifier_config       *cl;
	struct rspamd_controller_ctx   *ctx = session->worker->ctx;

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
		if (ctx->password == NULL) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password command disabled in config, authorized access unallowed" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return TRUE;
		}
		if (strncmp (arg, ctx->password, strlen (arg)) == 0) {
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
	case COMMAND_LEARN_SPAM:
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
				msg_debug ("no message size specified in learn command");
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: symbol and message size" CRLF);
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
			cl = find_classifier_conf (session->cfg, *cmd_args);
			if (cl == NULL) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "classifier %s is not defined" CRLF, *cmd_args);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;

			}
			session->learn_classifier = cl;

			/* By default learn positive */
			session->in_class = TRUE;
			rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
			session->state = STATE_LEARN_SPAM_PRE;
		}
		break;
	case COMMAND_LEARN_HAM:
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
				msg_debug ("no message size specified in learn command");
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: symbol and message size" CRLF);
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
			cl = find_classifier_conf (session->cfg, *cmd_args);
			if (cl == NULL) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "classifier %s is not defined" CRLF, *cmd_args);
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
				return TRUE;

			}
			session->learn_classifier = cl;

			/* By default learn positive */
			session->in_class = FALSE;
			rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
			session->state = STATE_LEARN_SPAM_PRE;
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
				msg_debug ("no message size specified in learn command");
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn command requires at least two arguments: symbol and message size" CRLF);
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
						else {
							session->learn_multiplier = strtod (arg, NULL);
						}
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
			"    weights <statfile> <size> - weight of message in all statfiles" CRLF);
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

static struct controller_command *
process_normal_command (const gchar *line)
{
	gint                            i;
	struct controller_command      *c;

	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		c = &commands[i];
		if (g_ascii_strcasecmp (line, c->command) == 0) {
			return c;
		}
	}

	return NULL;
}

static                          gboolean
controller_read_socket (f_str_t * in, void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;
	struct classifier_ctx          *cls_ctx;
	gint                            len, i, r;
	gchar                          *s, **params, *cmd, out_buf[128];
	struct controller_command      *command;
	struct worker_task             *task;
	struct mime_text_part          *part;
	GList                          *cur = NULL;
	GTree                          *tokens = NULL;
	GError                         *err = NULL;
	f_str_t                         c;

	switch (session->state) {
	case STATE_COMMAND:
		s = fstrcstr (in, session->session_pool);
		params = g_strsplit_set (s, " ", -1);

		memory_pool_add_destructor (session->session_pool, (pool_destruct_func) g_strfreev, params);

		len = g_strv_length (params);
		if (len > 0) {
			cmd = g_strstrip (params[0]);

			command = process_normal_command (cmd);
			if (command != NULL) {
				if (! process_command (command, &params[1], session)) {
					return FALSE;
				}
			}
			else {
				if (!process_custom_command (cmd, &params[1], session)) {
					msg_debug ("'%s'", cmd);
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "Unknown command" CRLF);
					if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
						return FALSE;
					}
				}
			}
		}
		if (session->state == STATE_COMMAND) {
			session->state = STATE_REPLY;
		}
		if (session->state != STATE_LEARN && session->state != STATE_LEARN_SPAM_PRE
				&& session->state != STATE_WEIGHTS && session->state != STATE_OTHER) {
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

		if (!learn_task (session->learn_symbol, task, &err)) {
			if (err) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, err->message);
				g_error_free (err);
			}
			else {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, unknown learn classifier error" CRLF END);
			}
			free_task (task, FALSE);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			session->state = STATE_REPLY;
			return TRUE;
		}

		free_task (task, FALSE);
		i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF END);
		if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
			return FALSE;
		}
		session->state = STATE_REPLY;
		break;
	case STATE_LEARN_SPAM_PRE:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;

		task->resolver = session->resolver;

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

		r = process_filters (task);
		if (r == -1) {
			session->state = STATE_REPLY;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			free_task (task, FALSE);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		else if (r == 0) {
			session->state = STATE_LEARN;
			task->dispatcher = session->dispatcher;
			session->learn_task = task;
			rspamd_dispatcher_pause (session->dispatcher);
		}
		else {
			lua_call_post_filters (task);
			session->state = STATE_REPLY;

			if (! learn_task_spam (session->learn_classifier, task, session->in_class, &err)) {
				if (err) {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, err->message);
					g_error_free (err);
				}
				else {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, unknown learn classifier error" CRLF END);
				}
			}
			else {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF END);
			}

			free_task (task, FALSE);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
		}
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
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF END);
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
			if (!session->learn_classifier->tokenizer->tokenize_func (session->learn_classifier->tokenizer,
					session->session_pool, &c, &tokens, FALSE, part->is_utf, part->urls_offset)) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "weights failed, tokenizer error" CRLF END);
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
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "weights failed, no tokens can be extracted (no text data)" CRLF END);
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
		i += rspamd_snprintf (out_buf + i, sizeof (out_buf) - i, END);
		if (i != 0) {
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
		}
		else {
			if (!rspamd_dispatcher_write (session->dispatcher, "weights failed: classifier error" CRLF END, 0, FALSE, TRUE)) {
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
	gint                            i;
	gchar                           out_buf[64];
	GError                         *err = NULL;

	if (session->state == STATE_QUIT) {
		/* Free buffers */
		destroy_session (session->s);
		return FALSE;
	}
	else if (session->state == STATE_LEARN) {
		/* Perform actual learn here */
		if (! learn_task_spam (session->learn_classifier, session->learn_task, session->in_class, &err)) {
			if (err) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, err->message);
				g_error_free (err);
			}
			else {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, unknown learn classifier error" CRLF END);
			}
		}
		else {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF END);
		}
		session->learn_task->dispatcher = NULL;
		free_task (session->learn_task, FALSE);
		session->state = STATE_REPLY;
		if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
			return FALSE;
		}
	}
	else if (session->state == STATE_REPLY) {
		session->state = STATE_COMMAND;
		rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, BUFSIZ);
	}
	rspamd_dispatcher_restore (session->dispatcher);
	return TRUE;
}

static void
controller_err_socket (GError * err, void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;

	if (err->code != EOF) {
		msg_info ("abnormally closing control connection, error: %s", err->message);
	}
	g_error_free (err);
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
	struct rspamd_controller_ctx   *ctx;

	ctx = worker->ctx;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
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
	new_session->resolver = ctx->resolver;
	worker->srv->stat->control_connections_count++;

	/* Set up dispatcher */
	io_tv = memory_pool_alloc (new_session->session_pool, sizeof (struct timeval));
	io_tv->tv_sec = ctx->timeout / 1000;
	io_tv->tv_usec = ctx->timeout - io_tv->tv_sec * 1000;

	new_session->s = new_async_session (new_session->session_pool, free_session, new_session);

	new_session->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, controller_read_socket, controller_write_socket, controller_err_socket, io_tv, (void *)new_session);
	if (! rspamd_dispatcher_write (new_session->dispatcher, greetingbuf, strlen (greetingbuf), FALSE, FALSE)) {
		msg_warn ("cannot write greeting");
	}
}

gpointer
init_controller (void)
{
	struct rspamd_controller_ctx       *ctx;

	ctx = g_malloc0 (sizeof (struct rspamd_controller_ctx));

	ctx->timeout = CONTROLLER_IO_TIMEOUT * 1000;

	register_worker_opt (TYPE_CONTROLLER, "password", xml_handle_string, ctx, G_STRUCT_OFFSET (struct rspamd_controller_ctx, password));
	register_worker_opt (TYPE_CONTROLLER, "timeout", xml_handle_seconds, ctx, G_STRUCT_OFFSET (struct rspamd_controller_ctx, timeout));

	return ctx;
}

void
start_controller (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	gchar                          *hostbuf;
	gsize                           hostmax;
	struct rspamd_controller_ctx   *ctx;

	worker->srv->pid = getpid ();
	ctx = worker->ctx;

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

	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	rspamd_snprintf (greetingbuf, sizeof (greetingbuf), "Rspamd version %s is running on %s" CRLF, RVERSION, hostbuf);
	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	start_map_watch ();
	ctx->resolver = dns_resolver_init (worker->srv->cfg);

	gperf_profiler_init (worker->srv->cfg, "controller");

	event_loop (0);

	close_log (worker->srv->logger);

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
