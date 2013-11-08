/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
#include "util.h"
#include "main.h"
#include "message.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "map.h"
#include "dns.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"
#include "binlog.h"
#include "statfile_sync.h"
#include "lua/lua_common.h"
#include "dynamic_cfg.h"
#include "rrd.h"

#define END "END" CRLF

/* 120 seconds for controller's IO */
#define CONTROLLER_IO_TIMEOUT 120

/* RRD macroes */
/* Write data each minute */
#define CONTROLLER_RRD_STEP 60

/* Init functions */
gpointer init_controller (struct config_file *cfg);
void start_controller (struct rspamd_worker *worker);

worker_t controller_worker = {
	"controller",				/* Name */
	init_controller,			/* Init function */
	start_controller,			/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE,						/* Killable */
	SOCK_STREAM					/* TCP socket */
};

enum command_type {
	COMMAND_PASSWORD,
	COMMAND_QUIT,
	COMMAND_RELOAD,
	COMMAND_STAT,
	COMMAND_STAT_RESET,
	COMMAND_SHUTDOWN,
	COMMAND_UPTIME,
	COMMAND_LEARN,
	COMMAND_LEARN_SPAM,
	COMMAND_LEARN_HAM,
	COMMAND_HELP,
	COMMAND_COUNTERS,
	COMMAND_SYNC,
	COMMAND_WEIGHTS,
	COMMAND_GET,
	COMMAND_POST,
	COMMAND_ADD_SYMBOL,
	COMMAND_ADD_ACTION
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
	struct event_base              *ev_base;
	struct event				    rrd_event;
	struct rspamd_rrd_file         *rrd_file;
	struct rspamd_main			   *srv;
};

static struct controller_command commands[] = {
	{"password", FALSE, COMMAND_PASSWORD},
	{"quit", FALSE, COMMAND_QUIT},
	{"reload", TRUE, COMMAND_RELOAD},
	{"stat", FALSE, COMMAND_STAT},
	{"stat_reset", TRUE, COMMAND_STAT_RESET},
	{"shutdown", TRUE, COMMAND_SHUTDOWN},
	{"uptime", FALSE, COMMAND_UPTIME},
	{"learn", TRUE, COMMAND_LEARN},
	{"weights", FALSE, COMMAND_WEIGHTS},
	{"help", FALSE, COMMAND_HELP},
	{"counters", FALSE, COMMAND_COUNTERS},
	{"sync", FALSE, COMMAND_SYNC},
	{"learn_spam", TRUE, COMMAND_LEARN_SPAM},
	{"learn_ham", TRUE, COMMAND_LEARN_HAM},
	{"get", FALSE, COMMAND_GET},
	{"post", FALSE, COMMAND_POST},
	{"add_symbol", TRUE, COMMAND_ADD_SYMBOL},
	{"add_action", TRUE, COMMAND_ADD_ACTION}
};

static GList                   *custom_commands = NULL;

static time_t                   start_time;

static gchar                    greetingbuf[1024];
static sig_atomic_t             wanna_die = 0;

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
sigusr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev_usr1);
	event_del (&worker->sig_ev_usr2);
	worker_stop_accept (worker);
	msg_info ("controller's shutdown is pending in %d sec", 2);
	event_loopexit (&tv);
	return;
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static void
sigusr1_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;

	reopen_log (worker->srv->logger);

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

	if (session->kwargs) {
		g_hash_table_destroy (session->kwargs);
	}

	close (session->sock);

	memory_pool_delete (session->session_pool);
	g_slice_free1 (sizeof (struct controller_session), session);
}

static gboolean
restful_write_reply (gint error_code, const gchar *err_message, const gchar *buf, gsize buflen, rspamd_io_dispatcher_t *d)
{
	static gchar					 hbuf[256];
	gint							 r;

	r = rspamd_snprintf (hbuf, sizeof (hbuf),
			"HTTP/1.0 %d %s" CRLF "Version: " RVERSION CRLF,
			error_code, err_message ? err_message : "OK");
	if (buflen > 0) {
		r += rspamd_snprintf (hbuf + r, sizeof (hbuf) - r, "Content-Length: %z" CRLF, buflen);
	}
	r += rspamd_snprintf (hbuf + r, sizeof (hbuf) - r, CRLF);

	if (buf != NULL) {
		if (!rspamd_dispatcher_write (d, hbuf, r, TRUE, TRUE)) {
			return FALSE;
		}
		return rspamd_dispatcher_write (d, buf, buflen, FALSE, FALSE);
	}
	else {
		if (!rspamd_dispatcher_write (d, hbuf, r, FALSE, TRUE)) {
			return FALSE;
		}
	}

	return TRUE;
}

static gint
check_auth (struct controller_command *cmd, struct controller_session *session)
{
	gchar                           out_buf[128];
	gint                            r;

	if (cmd->privilleged && !session->authorized) {
		if (!session->restful) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "not authorized" CRLF);
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return 0;
			}
		}
		else {
			(void)restful_write_reply (403, "Not authorized", NULL, 0, session->dispatcher);
		}
		return 0;
	}

	return 1;
}

static gboolean
write_whole_statfile (struct controller_session *session, gchar *symbol, struct classifier_config *ccf)
{
	stat_file_t                    *statfile;
	struct statfile                *st;
	gchar                           out_buf[BUFSIZ];
	guint                           i;
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
process_counters_command (struct controller_session *session)
{
	gchar                           out_buf[BUFSIZ];
	GList                          *cur;
	struct cache_item             *item;
	struct symbols_cache          *cache;
	gint                            r;

	cache = session->cfg->cache;

	if (!session->restful) {
		r = rspamd_snprintf (out_buf, sizeof (out_buf), "Rspamd counters." CRLF);
	}
	else {
		r = 0;
	}

	if (cache != NULL) {
		cur = cache->negative_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "%s %.2f %d %.3f" CRLF,
						item->s->symbol, item->s->weight,
						item->s->frequency, item->s->avg_time);
			}
			cur = g_list_next (cur);
		}
		cur = cache->static_items;
		while (cur) {
			item = cur->data;
			if (!item->is_callback) {
				r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "%s %.2f %d %.3f" CRLF,
						item->s->symbol, item->s->weight,
						item->s->frequency, item->s->avg_time);
			}
			cur = g_list_next (cur);
		}
	}

	if (!session->restful) {
		return rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
	}
	else {
		return restful_write_reply (200, NULL, out_buf, r, session->dispatcher);
	}
}

static gboolean
process_stat_command (struct controller_session *session, gboolean do_reset)
{
	gchar                           out_buf[BUFSIZ];
	gint                            r, i;
	guint64                         used, total, rev, ham = 0, spam = 0;
	time_t                          ti;
	memory_pool_stat_t              mem_st;
	struct classifier_config       *ccf;
	stat_file_t                    *statfile;
	struct statfile                *st;
	GList                          *cur_cl, *cur_st;
	struct rspamd_stat            *stat;

	memory_pool_stat (&mem_st);
	stat = session->worker->srv->stat;
	r = rspamd_snprintf (out_buf, sizeof (out_buf), "Messages scanned: %ud" CRLF, stat->messages_scanned);
	if (session->worker->srv->stat->messages_scanned > 0) {
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i ++) {
			r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages with action %s: %ud, %.2f%%" CRLF,
					str_action_metric (i), stat->actions_stat[i],
					(double)stat->actions_stat[i] / (double)stat->messages_scanned * 100.);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
				stat->actions_stat[i] = 0;
			}
		}
		r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages treated as spam: %ud, %.2f%%" CRLF, spam,
								(double)spam / (double)stat->messages_scanned * 100.);
		r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages treated as ham: %ud, %.2f%%" CRLF, ham,
								(double)ham / (double)stat->messages_scanned * 100.);
	}
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Messages learned: %ud" CRLF, stat->messages_learned);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Connections count: %ud" CRLF, stat->connections_count);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Control connections count: %ud" CRLF, stat->control_connections_count);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Pools allocated: %z" CRLF, mem_st.pools_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Pools freed: %z" CRLF, mem_st.pools_freed);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Bytes allocated: %z" CRLF, mem_st.bytes_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Memory chunks allocated: %z" CRLF, mem_st.chunks_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Shared chunks allocated: %z" CRLF, mem_st.shared_chunks_allocated);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Chunks freed: %z" CRLF, mem_st.chunks_freed);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Oversized chunks: %z" CRLF, mem_st.oversized_chunks);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Fuzzy hashes stored: %ud" CRLF, stat->fuzzy_hashes);
	r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r, "Fuzzy hashes expired: %ud" CRLF, stat->fuzzy_hashes_expired);
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
					if (st->label) {
						r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r,
								"Statfile: %s <%s> (version %uL); length: %Hz; free blocks: %uL; total blocks: %uL; free: %.2f%%" CRLF,
								st->symbol, st->label, rev, st->size,
								(total - used), total,
								(double)((double)(total - used) / (double)total) * 100.);
					}
					else {
						r += rspamd_snprintf (out_buf + r, sizeof (out_buf) - r,
								"Statfile: %s (version %uL); length: %Hz; free blocks: %uL; total blocks: %uL; free: %.2f%%" CRLF,
								st->symbol, rev, st->size,
								(total - used), total,
								(double)((double)(total - used) / (double)total) * 100.);
					}
				}
			}
			cur_st = g_list_next (cur_st);
		}
		cur_cl = g_list_next (cur_cl);
	}

	if (do_reset) {
		stat->messages_scanned = 0;
		stat->messages_learned = 0;
		stat->connections_count = 0;
		stat->control_connections_count = 0;
	}

	if (!session->restful) {
		return rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
	}
	else {
		return restful_write_reply (200, NULL, out_buf, r, session->dispatcher);
	}
}

static gboolean
process_dynamic_conf_command (gchar **cmd_args, struct controller_session *session, gboolean is_action)
{
	struct config_file			   *cfg = session->cfg;
	gchar						   *arg, *metric, *name, *err_str;
	gdouble						    value;
	gboolean						res;
	guint							real_act;

	if (cfg->dynamic_conf == NULL) {
		if (!session->restful) {
			return rspamd_dispatcher_write (session->dispatcher, "dynamic config is not specified" CRLF, 0, FALSE, TRUE);
		}
		else {
			return restful_write_reply (500, "dynamic config is not specified", NULL, 0, session->dispatcher);
		}
	}

	if (session->restful) {
		if ((arg = g_hash_table_lookup (session->kwargs, "metric")) == NULL) {
			metric = DEFAULT_METRIC;
		}
		else {
			metric = arg;
		}
		if ((arg = g_hash_table_lookup (session->kwargs, "name")) == NULL) {
			goto invalid_arguments;
		}
		name = arg;
		if ((arg = g_hash_table_lookup (session->kwargs, "value")) == NULL) {
			goto invalid_arguments;
		}
		value = strtod (arg, &err_str);
		if (err_str && *err_str != '\0') {
			msg_info ("double value is invalid: %s", arg);
			goto invalid_arguments;
		}
	}
	else {
		if (cmd_args[0] == NULL || cmd_args[1] == NULL) {
			goto invalid_arguments;
		}
		if (cmd_args[2] == NULL) {
			metric = DEFAULT_METRIC;
			name = cmd_args[0];
			arg = cmd_args[1];
			value = strtod (arg, &err_str);
			if (err_str && *err_str != '\0') {
				msg_info ("double value is invalid: %s", arg);
				goto invalid_arguments;
			}
		}
		else {
			metric = cmd_args[0];
			name = cmd_args[1];
			arg = cmd_args[2];
			value = strtod (arg, &err_str);
			if (err_str && *err_str != '\0') {
				msg_info ("double value is invalid: %s", arg);
				goto invalid_arguments;
			}
		}
	}

	if (is_action) {
		if (!check_action_str (name, &real_act)) {
			msg_info ("invalid action string: %s", name);
			res = FALSE;
		}
		else {
			res = add_dynamic_action (cfg, metric, real_act, value);
		}
	}
	else {
		res = add_dynamic_symbol (cfg, metric, name, value);
	}

	if (res) {

		res = dump_dynamic_config (cfg);
		if (res) {
			if (!session->restful) {
				return rspamd_dispatcher_write (session->dispatcher, "OK" CRLF, 0, FALSE, TRUE);
			}
			else {
				return restful_write_reply (200, "OK", NULL, 0, session->dispatcher);
			}
		}
		else {
			if (!session->restful) {
				return rspamd_dispatcher_write (session->dispatcher, "Error dumping dynamic config" CRLF, 0, FALSE, TRUE);
			}
			else {
				return restful_write_reply (500, "Error dumping dynamic config", NULL, 0, session->dispatcher);
			}
		}
	}
	else {
		if (!session->restful) {
			return rspamd_dispatcher_write (session->dispatcher, "Cannot add dynamic rule" CRLF, 0, FALSE, TRUE);
		}
		else {
			return restful_write_reply (500, "Cannot add dynamic rule", NULL, 0, session->dispatcher);
		}
	}

invalid_arguments:
	if (!session->restful) {
		return rspamd_dispatcher_write (session->dispatcher, "Invalid arguments" CRLF, 0, FALSE, TRUE);
	}
	else {
		return restful_write_reply (500, "Invalid arguments", NULL, 0, session->dispatcher);
	}
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
	case COMMAND_GET:
	case COMMAND_POST:
		session->restful = TRUE;
		session->state = STATE_HEADER;
		session->kwargs = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		break;
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
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "password command disabled in config, authorized access granted" CRLF);
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
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (200, out_buf, NULL, 0, session->dispatcher)) {
					return FALSE;
				}
			}
			kill (getppid (), SIGHUP);
		}
		break;
	case COMMAND_STAT:
		if (check_auth (cmd, session)) {
			return process_stat_command (session, FALSE);
		}
		break;
	case COMMAND_STAT_RESET:
		if (check_auth (cmd, session)) {
			return process_stat_command (session, TRUE);
		}
		break;
	case COMMAND_SHUTDOWN:
		if (check_auth (cmd, session)) {
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "shutdown request sent" CRLF);
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (200, out_buf, NULL, 0, session->dispatcher)) {
					return FALSE;
				}
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
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (200, NULL, out_buf, r, session->dispatcher)) {
					return FALSE;
				}
			}
		}
		break;
	case COMMAND_LEARN_SPAM:
		if (check_auth (cmd, session)) {
			if (!session->restful) {
				arg = *cmd_args;
				if (!arg || *arg == '\0') {
					msg_debug ("no statfile specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
						return FALSE;
					}
					return TRUE;
				}
				arg = *(cmd_args + 1);
				if (arg == NULL || *arg == '\0') {
					msg_debug ("no message size specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
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
			}
			else {
				if ((arg = g_hash_table_lookup (session->kwargs, "classifier")) == NULL) {
					msg_debug ("no classifier specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
						return FALSE;
					}
					return TRUE;
				}
				else {
					cl = find_classifier_conf (session->cfg, arg);
				}
				if ((arg = g_hash_table_lookup (session->kwargs, "content-length")) == NULL) {
					msg_debug ("no size specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
						return FALSE;
					}
				}
				else {
					size = strtoul (arg, &err_str, 10);
					if (err_str && *err_str != '\0') {
						msg_debug ("message size is invalid: %s", arg);
						r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
						if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
							return FALSE;
						}
						return TRUE;
					}
				}
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
			if (!session->restful) {
				arg = *cmd_args;
				if (!arg || *arg == '\0') {
					msg_debug ("no statfile specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
						return FALSE;
					}
					return TRUE;
				}
				arg = *(cmd_args + 1);
				if (arg == NULL || *arg == '\0') {
					msg_debug ("no message size specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
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
			}
			else {
				if ((arg = g_hash_table_lookup (session->kwargs, "classifier")) == NULL) {
					msg_debug ("no classifier specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
						return FALSE;
					}
					return TRUE;
				}
				else {
					cl = find_classifier_conf (session->cfg, arg);
				}
				if ((arg = g_hash_table_lookup (session->kwargs, "content-length")) == NULL) {
					msg_debug ("no size specified in learn command");
					r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn_spam command requires at least two arguments: classifier name and a message's size" CRLF);
					if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
						return FALSE;
					}
				}
				else {
					size = strtoul (arg, &err_str, 10);
					if (err_str && *err_str != '\0') {
						msg_debug ("message size is invalid: %s", arg);
						r = rspamd_snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
						if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
							return FALSE;
						}
						return TRUE;
					}
				}
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
			/* TODO: remove this command as currenly it should not be used anywhere */
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
		/* TODO: remove this command as currenly it should not be used anywhere */
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
		if (!session->restful) {
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		else {
			if (! restful_write_reply (200, NULL, out_buf, r, session->dispatcher)) {
				return FALSE;
			}
		}
		break;
	case COMMAND_COUNTERS:
		process_counters_command (session);
		break;
	case COMMAND_ADD_ACTION:
		if (check_auth (cmd, session)) {
			return process_dynamic_conf_command (cmd_args, session, TRUE);
		}
		break;
	case COMMAND_ADD_SYMBOL:
		if (check_auth (cmd, session)) {
			return process_dynamic_conf_command (cmd_args, session, FALSE);
		}
		break;
	}
	return TRUE;
}

static controller_func_t
parse_custom_command (gchar *line, gchar **cmd_args, struct controller_session *session, gsize len)
{
	GList                          *cur;
	struct custom_controller_command *cmd;

	if (len == 0) {
		len = strlen (line);
	}
	cur = custom_commands;
	while (cur) {
		cmd = cur->data;
		if (g_ascii_strncasecmp (cmd->command, line, len) == 0) {
			return cmd->handler;
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

static struct controller_command *
parse_normal_command (const gchar *line, gsize len)
{
	guint                           i;
	struct controller_command      *c;

	if (len == 0) {
		len = strlen (line);
	}
	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		c = &commands[i];
		if (g_ascii_strncasecmp (line, c->command, len) == 0) {
			return c;
		}
	}

	return NULL;
}

static gboolean
process_header (f_str_t *line, struct controller_session *session)
{
	gchar							*headern;
	struct controller_command		*command;
	struct rspamd_controller_ctx	*ctx = session->worker->ctx;
	controller_func_t				 custom_handler;

	headern = separate_command (line, ':');

	if (line == NULL || headern == NULL) {
		msg_warn ("bad header: %V", line);
		return FALSE;
	}
	/* Eat whitespaces */
	g_strstrip (headern);
	fstrstrip (line);

	if (*headern == 'c' || *headern == 'C') {
		if (g_ascii_strcasecmp (headern, "command") == 0) {
			/* This header is actually command */
			command = parse_normal_command (line->begin, line->len);
			if (command == NULL) {
				if ((custom_handler = parse_custom_command (line->begin, NULL, session, line->len)) == NULL) {
					msg_info ("bad command header: %V", line);
					return FALSE;
				}
				else {
					session->custom_handler = custom_handler;
				}
			}
			session->cmd = command;
			return TRUE;
		}
	}
	else if (*headern == 'p' || *headern == 'P') {
		/* Password header */
		if (g_ascii_strcasecmp (headern, "password") == 0) {
			if (line->len == strlen (ctx->password) && memcmp (line->begin, ctx->password, line->len) == 0) {
				session->authorized = TRUE;
			}
			else {
				msg_info ("wrong password in controller command");
			}
			return TRUE;
		}
	}

	g_hash_table_insert (session->kwargs, headern, fstrcstr (line, session->session_pool));

	return TRUE;
}

/*
 * Called if all filters are processed, non-threaded and simple version
 */
static gboolean
fin_learn_task (void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;

	if (task->state != WRITING_REPLY) {
		task->state = WRITE_REPLY;
	}

	/* Check if we have all events finished */
	if (task->state != WRITING_REPLY) {
		if (task->fin_callback) {
			task->fin_callback (task->fin_arg);
		}
		else {
			rspamd_dispatcher_restore (task->dispatcher);
		}
	}

	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
restore_learn_task (void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;

	/* Special state */
	task->state = WRITING_REPLY;

	rspamd_dispatcher_pause (task->dispatcher);
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
	controller_func_t				custom_handler;

	switch (session->state) {
	case STATE_COMMAND:
		s = fstrcstr (in, session->session_pool);
		params = g_strsplit_set (s, " ", -1);

		memory_pool_add_destructor (session->session_pool, (pool_destruct_func) g_strfreev, params);

		len = g_strv_length (params);
		if (len > 0) {
			cmd = g_strstrip (params[0]);

			command = parse_normal_command (cmd, 0);
			if (command != NULL) {
				if (! process_command (command, &params[1], session)) {
					return FALSE;
				}
			}
			else {
				if ((custom_handler = parse_custom_command (cmd, &params[1], session, 0)) == NULL) {
					msg_debug ("'%s'", cmd);
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "Unknown command" CRLF);
					if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
						return FALSE;
					}
				}
				else {
					custom_handler (&params[1], session);
				}
			}
		}
		if (session->state != STATE_LEARN && session->state != STATE_LEARN_SPAM_PRE
				&& session->state != STATE_WEIGHTS && session->state != STATE_OTHER && session->state != STATE_HEADER) {
			if (!rspamd_dispatcher_write (session->dispatcher, END, sizeof (END) - 1, FALSE, TRUE)) {
				return FALSE;
			}
			if (session->state == STATE_QUIT) {
				destroy_session (session->s);
				return FALSE;
			}
		}

		break;
	case STATE_HEADER:
		if (in->len == 0) {
			/* End of headers */
			if (session->cmd == NULL && session->custom_handler == NULL) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Bad command" CRLF CRLF);
				if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
					return FALSE;
				}
				destroy_session (session->s);
				return FALSE;
			}
			/* Perform command */
			else if (session->cmd != NULL) {
				if (! process_command (session->cmd, NULL, session)) {
					msg_debug ("process command failed");
					return FALSE;
				}
			}
			else {
				session->custom_handler (NULL, session);
			}
			if (session->state != STATE_LEARN && session->state != STATE_LEARN_SPAM_PRE
					&& session->state != STATE_WEIGHTS && session->state != STATE_OTHER) {
				msg_debug ("closing restful connection");
				destroy_session (session->s);
				return FALSE;
			}
		}
		else if (!process_header (in, session)) {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Bad header" CRLF CRLF);
			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			destroy_session (session->s);
			return FALSE;
		}
		break;
	case STATE_LEARN:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;
		task->ev_base = session->ev_base;

		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			free_task (task, FALSE);
			session->state = STATE_REPLY;
			if (session->restful) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Cannot process message" CRLF CRLF);
			}
			else {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			}
			if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
				return FALSE;
			}
			return FALSE;
		}

		if (!learn_task (session->learn_symbol, task, &err)) {
			free_task (task, FALSE);
			if (err) {
				if (session->restful) {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Learn classifier error: %s" CRLF CRLF, err->message);
				}
				else {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, err->message);
				}
				g_error_free (err);
			}
			else {
				if (session->restful) {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Learn classifier error: unknown" CRLF CRLF);
				}
				else {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, unknown learn classifier error" CRLF END);
				}
			}

			if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
				return FALSE;
			}
			session->state = STATE_REPLY;
			return TRUE;
		}

		free_task (task, FALSE);
		if (session->restful) {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 200 Learn OK" CRLF CRLF);
		}
		else {
			i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF END);
		}
		session->state = STATE_REPLY;
		if (!rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
			return FALSE;
		}
		break;
	case STATE_LEARN_SPAM_PRE:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;

		task->resolver = session->resolver;
		task->ev_base = session->ev_base;

		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			session->state = STATE_REPLY;
			if (session->restful) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Cannot process message" CRLF CRLF);
			}
			else {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			}
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
					return FALSE;
				}
			}
			return FALSE;
		}
		/* Set up async session */
		task->s = new_async_session (task->task_pool, fin_learn_task, restore_learn_task, free_task_hard, task);
		r = process_filters (task);
		if (r == -1) {
			session->state = STATE_REPLY;
			if (session->restful) {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Cannot process message" CRLF CRLF);
			}
			else {
				r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
			}
			destroy_session (task->s);
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
					return FALSE;
				}
			}
		}
		else {
			session->state = STATE_LEARN_SPAM;
			task->dispatcher = session->dispatcher;
			session->learn_task = task;
			rspamd_dispatcher_pause (session->dispatcher);
		}
		break;
	case STATE_WEIGHTS:
		session->learn_buf = in;
		task = construct_task (session->worker);

		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;
		task->ev_base = session->ev_base;

		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			free_task (task, FALSE);
			session->state = STATE_REPLY;
			r = rspamd_snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF END);
			if (!session->restful) {
				if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
					return FALSE;
				}
			}
			else {
				if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
					return FALSE;
				}
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
				if (!session->restful) {
					if (! rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE)) {
						return FALSE;
					}
				}
				else {
					if (! restful_write_reply (500, out_buf, NULL, 0, session->dispatcher)) {
						return FALSE;
					}
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
		rspamd_dispatcher_restore (session->dispatcher);
	}

	return TRUE;
}

static                          gboolean
controller_write_socket (void *arg)
{
	struct controller_session      *session = (struct controller_session *)arg;
	gint                            i;
	gchar                           out_buf[1024];
	GError                         *err = NULL;

	if (session->state == STATE_QUIT) {
		/* Free buffers */
		destroy_session (session->s);
		return FALSE;
	}
	else if (session->state == STATE_LEARN_SPAM) {
		/* Perform actual learn here */
		if (session->learn_classifier == NULL) {
			if (session->restful) {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Learn classifier error: %s" CRLF CRLF, "unknown classifier");
			}
			else {
				i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, "unknown classifier");
			}
		}
		else {
			if (! learn_task_spam (session->learn_classifier, session->learn_task, session->in_class, &err)) {
				if (err) {
					if (session->restful) {
						i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Learn classifier error: %s" CRLF CRLF, err->message);
					}
					else {
						i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: %s" CRLF END, err->message);
					}
					g_error_free (err);
				}
				else {
					if (session->restful) {
						i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 500 Learn classifier error: unknown" CRLF CRLF);
					}
					else {
						i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn failed, learn classifier error: unknown" CRLF END);
					}
				}
			}
			else {
				if (session->restful) {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "HTTP/1.0 200 Learn OK" CRLF CRLF);
				}
				else {
					i = rspamd_snprintf (out_buf, sizeof (out_buf), "learn ok" CRLF END);
				}
			}
		}
		session->learn_task->dispatcher = NULL;
		destroy_session (session->learn_task->s);
		session->state = STATE_REPLY;
		if (! rspamd_dispatcher_write (session->dispatcher, out_buf, i, FALSE, FALSE)) {
			return FALSE;
		}
		if (session->restful) {
			destroy_session (session->s);
			return FALSE;
		}
		return TRUE;
	}
	else if (session->state == STATE_REPLY) {
		if (session->restful) {
			destroy_session (session->s);
			return FALSE;
		}
		else {
			session->state = STATE_COMMAND;
			rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, BUFSIZ);
		}
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
	union sa_union                  su;
	struct controller_session      *new_session;
	struct timeval                 *io_tv;
	socklen_t                       addrlen = sizeof (su.ss);
	gint                            nfd;
	struct rspamd_controller_ctx   *ctx;

	ctx = worker->ctx;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		return;
	}

	new_session = g_slice_alloc0 (sizeof (struct controller_session));
	if (new_session == NULL) {
		msg_err ("cannot allocate memory for task, %s", strerror (errno));
		return;
	}

	new_session->worker = worker;
	new_session->sock = nfd;
	new_session->cfg = worker->srv->cfg;
	new_session->state = STATE_COMMAND;
	new_session->session_pool = memory_pool_new (memory_pool_get_size () - 1);
	new_session->resolver = ctx->resolver;
	new_session->ev_base = ctx->ev_base;
	if (ctx->password == NULL) {
		new_session->authorized = TRUE;
	}
	worker->srv->stat->control_connections_count++;

	/* Set up dispatcher */
	io_tv = memory_pool_alloc (new_session->session_pool, sizeof (struct timeval));
	io_tv->tv_sec = ctx->timeout / 1000;
	io_tv->tv_usec = ctx->timeout - io_tv->tv_sec * 1000;

	new_session->s = new_async_session (new_session->session_pool, NULL, NULL, free_session, new_session);

	new_session->dispatcher = rspamd_create_dispatcher (ctx->ev_base, nfd, BUFFER_LINE, controller_read_socket,
			controller_write_socket, controller_err_socket, io_tv, (void *)new_session);

	if (su.ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		new_session->dispatcher->peer_addr = INADDR_LOOPBACK;
	}
	else if (su.ss.ss_family == AF_INET) {
		msg_info ("accepted connection from %s port %d",
				inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&new_session->dispatcher->peer_addr, &su.s4.sin_addr,
				sizeof (guint32));
	}
#if 0
	/* As we support now restful HTTP like connections, this should not be printed anymore */
	if (! rspamd_dispatcher_write (new_session->dispatcher, greetingbuf, strlen (greetingbuf), FALSE, FALSE)) {
		msg_warn ("cannot write greeting");
	}
#endif
}

static gboolean
create_rrd_file (const gchar *filename, struct rspamd_controller_ctx *ctx)
{
	GError								*err = NULL;
	GArray								 ar;
	struct rrd_rra_def					 rra[5];
	struct rrd_ds_def					 ds[4];

	/*
	 * DS:
	 * 1) reject as spam
	 * 2) mark as spam
	 * 3) greylist
	 * 4) pass
	 */
	/*
	 * RRA:
	 * 1) per minute AVERAGE
	 * 2) per 5 minutes AVERAGE
	 * 3) per 30 minutes AVERAGE
	 * 4) per 2 hours AVERAGE
	 * 5) per day AVERAGE
	 */
	ctx->rrd_file = rspamd_rrd_create (filename, 4, 5, CONTROLLER_RRD_STEP, &err);
	if (ctx->rrd_file == NULL) {
		msg_err ("cannot create rrd file %s, error: %s", filename, err->message);
		g_error_free (err);
		return FALSE;
	}

	/* Add all ds and rra */
	rrd_make_default_ds ("spam", CONTROLLER_RRD_STEP, &ds[0]);
	rrd_make_default_ds ("possible spam", CONTROLLER_RRD_STEP, &ds[1]);
	rrd_make_default_ds ("greylist", CONTROLLER_RRD_STEP, &ds[2]);
	rrd_make_default_ds ("ham", CONTROLLER_RRD_STEP, &ds[3]);

	rrd_make_default_rra ("AVERAGE", 1, 600, &rra[0]);
	rrd_make_default_rra ("AVERAGE", 5, 600, &rra[1]);
	rrd_make_default_rra ("AVERAGE", 30, 700, &rra[2]);
	rrd_make_default_rra ("AVERAGE", 120, 775, &rra[3]);
	rrd_make_default_rra ("AVERAGE", 1440, 797, &rra[4]);

	ar.data = (gchar *)ds;
	ar.len = sizeof (ds);
	if (!rspamd_rrd_add_ds (ctx->rrd_file, &ar, &err)) {
		msg_err ("cannot create rrd file %s, error: %s", filename, err->message);
		g_error_free (err);
		rspamd_rrd_close (ctx->rrd_file);
		return FALSE;
	}

	ar.data = (gchar *)rra;
	ar.len = sizeof (rra);
	if (!rspamd_rrd_add_rra (ctx->rrd_file, &ar, &err)) {
		msg_err ("cannot create rrd file %s, error: %s", filename, err->message);
		g_error_free (err);
		rspamd_rrd_close (ctx->rrd_file);
		return FALSE;
	}

	/* Finalize */
	if (!rspamd_rrd_finalize (ctx->rrd_file, &err)) {
		msg_err ("cannot create rrd file %s, error: %s", filename, err->message);
		g_error_free (err);
		rspamd_rrd_close (ctx->rrd_file);
		return FALSE;
	}

	return TRUE;
}

static void
controller_update_rrd (gint fd, short what, void *arg)
{
	struct rspamd_controller_ctx       *ctx = arg;
	struct timeval                      tv;
	GArray                              ar;
	gdouble                             data[4];
	GError                             *err = NULL;

	/*
	 * Data:
	 * 1) reject as spam
	 * 2) mark as spam
	 * 3) greylist
	 * 4) pass
	 */

	tv.tv_sec = CONTROLLER_RRD_STEP;
	tv.tv_usec = 0;

	/* Fill data */
	data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT];
	data[1] = ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] + ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION];

	ar.data = (gchar *)data;
	ar.len = sizeof (data);
	if (!rspamd_rrd_add_record (ctx->rrd_file, &ar, &err)) {
		msg_err ("cannot add record to rrd database: %s, stop rrd update", err->message);
		g_error_free (err);
	}
	else {
		evtimer_add (&ctx->rrd_event, &tv);
	}
}

gpointer
init_controller (struct config_file *cfg)
{
	struct rspamd_controller_ctx       *ctx;
	GQuark								type;

	type = g_quark_try_string ("controller");
	ctx = g_malloc0 (sizeof (struct rspamd_controller_ctx));

	ctx->timeout = CONTROLLER_IO_TIMEOUT * 1000;

	rspamd_rcl_register_worker_option (cfg, type, "password",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_ctx, password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "timeout",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_ctx, timeout), RSPAMD_CL_FLAG_TIME_UINT_32);

	return ctx;
}

void
start_controller (struct rspamd_worker *worker)
{
	gchar                          *hostbuf;
	gsize                           hostmax;
	struct rspamd_controller_ctx   *ctx = worker->ctx;
	GError                         *err = NULL;
	struct timeval                  tv;

	ctx->ev_base = prepare_worker (worker, "controller", sig_handler, accept_socket);
	g_mime_init (0);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);


	start_time = time (NULL);

	/* Start statfile synchronization */
	if (!start_statfile_sync (worker->srv->statfile_pool, worker->srv->cfg, ctx->ev_base)) {
		msg_info ("cannot start statfile synchronization, statfiles would not be synchronized");
	}

	/* Check for rrd */
	tv.tv_sec = CONTROLLER_RRD_STEP;
	tv.tv_usec = 0;
	ctx->srv = worker->srv;
	if (worker->srv->cfg->rrd_file) {
		ctx->rrd_file = rspamd_rrd_open (worker->srv->cfg->rrd_file, &err);
		if (ctx->rrd_file == NULL) {
			msg_info ("cannot open rrd file: %s, error: %s, trying to create", worker->srv->cfg->rrd_file, err->message);
			g_error_free (err);
			/* Try to create rrd file */
			if (create_rrd_file (worker->srv->cfg->rrd_file, ctx)) {
				evtimer_set (&ctx->rrd_event, controller_update_rrd, ctx);
				event_base_set (ctx->ev_base, &ctx->rrd_event);
				evtimer_add (&ctx->rrd_event, &tv);
			}
		}
		else {
			evtimer_set (&ctx->rrd_event, controller_update_rrd, ctx);
			event_base_set (ctx->ev_base, &ctx->rrd_event);
			evtimer_add (&ctx->rrd_event, &tv);
		}
	}

	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	rspamd_snprintf (greetingbuf, sizeof (greetingbuf), "Rspamd version %s is running on %s" CRLF, RVERSION, hostbuf);

	start_map_watch (worker->srv->cfg, ctx->ev_base);
	ctx->resolver = dns_resolver_init (ctx->ev_base, worker->srv->cfg);

	event_base_loop (ctx->ev_base, 0);

	close_log (worker->srv->logger);
	if (ctx->rrd_file) {
		rspamd_rrd_close (ctx->rrd_file);
	}

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
