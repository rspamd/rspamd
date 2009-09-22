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

/***MODULE:fuzzy
 * rspamd module that checks fuzzy checksums for messages
 */

#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../expressions.h"
#include "../util.h"
#include "../view.h"
#include "../map.h"
#include "../fuzzy_storage.h"

#define DEFAULT_SYMBOL "R_FUZZY_HASH"
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define IO_TIMEOUT 5
#define DEFAULT_PORT 11335

struct storage_server {
	struct upstream up;
	char *name;
	struct in_addr addr;
	uint16_t port;
};

struct fuzzy_ctx {
	int (*filter)(struct worker_task *task);
	char *metric;
	char *symbol;
	struct storage_server *servers;
	int servers_num;
	memory_pool_t *fuzzy_pool;
};

struct fuzzy_client_session {
	int state;
	fuzzy_hash_t *h;
	struct event ev;
	struct timeval tv;
	struct worker_task *task;
	struct storage_server *server;
};

struct fuzzy_learn_session {
	struct event ev;
	fuzzy_hash_t *h;
	int cmd;
	int *saved;
	struct timeval tv;
	struct controller_session *session;
	struct storage_server *server;
	struct worker_task *task;
};

static struct fuzzy_ctx *fuzzy_module_ctx = NULL;

static int fuzzy_mime_filter (struct worker_task *task);
static void fuzzy_symbol_callback (struct worker_task *task, void *unused);
static void fuzzy_add_handler (char **args, struct controller_session *session);
static void fuzzy_delete_handler (char **args, struct controller_session *session);

static void
parse_servers_string (char *str)
{
	char **strvec, *p, portbuf[6], *name;
	int num, i, j, port;
	struct hostent *hent;
	struct in_addr addr;

	strvec = g_strsplit (str, ",", 0);
	num = g_strv_length (strvec);

	fuzzy_module_ctx->servers = memory_pool_alloc0 (fuzzy_module_ctx->fuzzy_pool, sizeof (struct storage_server) * num);

	for (i = 0; i < num; i ++) {
		g_strstrip (strvec[i]);

		if ((p = strchr (strvec[i], ':')) != NULL) {
			j = 0;
			p ++;
			while (g_ascii_isdigit (*(p + j)) && j < sizeof (portbuf) - 1) {
				portbuf[j] = *(p + j);
				j ++;
			}
			portbuf[j] = '\0';
			port = atoi (portbuf);
		}
		else {
			/* Default http port */
			port = DEFAULT_PORT;
		}
		name = memory_pool_alloc (fuzzy_module_ctx->fuzzy_pool, p - strvec[i]);
		g_strlcpy (name, strvec[i], p - strvec[i]);
		if (!inet_aton (name, &addr)) {
			/* Resolve using dns */
			hent = gethostbyname (name);
			if (hent == NULL) {
				msg_info ("parse_servers_string: cannot resolve: %s", name);
				continue;
			}
			else {
				fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].port = port;	
				fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].name = name;	
				memcpy (&fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].addr, hent->h_addr, sizeof(struct in_addr));
				fuzzy_module_ctx->servers_num ++;	
			}
		}
		else {
			fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].port = port;	
			fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].name = name;	
			memcpy (&fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].addr, hent->h_addr, sizeof(struct in_addr));
			fuzzy_module_ctx->servers_num ++;	
		}

	}

	g_strfreev (strvec);

}

int
fuzzy_check_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	fuzzy_module_ctx = g_malloc (sizeof (struct fuzzy_ctx));

	fuzzy_module_ctx->filter = fuzzy_mime_filter;
	fuzzy_module_ctx->fuzzy_pool = memory_pool_new (memory_pool_get_size ());
	fuzzy_module_ctx->servers = NULL;
	fuzzy_module_ctx->servers_num = 0;
	
	*ctx = (struct module_ctx *)fuzzy_module_ctx;

	return 0;
}

int
fuzzy_check_module_config (struct config_file *cfg)
{
	char *value;
	int res = TRUE;
	struct metric *metric;
	double *w;

	if ((value = get_module_opt (cfg, "fuzzy_check", "metric")) != NULL) {
		fuzzy_module_ctx->metric = memory_pool_strdup (fuzzy_module_ctx->fuzzy_pool, value);
		g_free (value);
	}
	else {
		fuzzy_module_ctx->metric = DEFAULT_METRIC;
	}
	if ((value = get_module_opt (cfg, "fuzzy_check", "symbol")) != NULL) {
		fuzzy_module_ctx->symbol = memory_pool_strdup (fuzzy_module_ctx->fuzzy_pool, value);
		g_free (value);
	}
	else {
		fuzzy_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value = get_module_opt (cfg, "fuzzy_check", "servers")) != NULL) {
		parse_servers_string (value);
	}	

	metric = g_hash_table_lookup (cfg->metrics, fuzzy_module_ctx->metric);
	if (metric == NULL) {
		msg_err ("fuzzy_module_config: cannot find metric definition %s", fuzzy_module_ctx->metric);
		return FALSE;
	}

	/* Search in factors hash table */
	w = g_hash_table_lookup (cfg->factors, fuzzy_module_ctx->symbol);
	if (w == NULL) {
		register_symbol (&metric->cache, fuzzy_module_ctx->symbol, 1, fuzzy_symbol_callback, NULL);
	}
	else {
		register_symbol (&metric->cache, fuzzy_module_ctx->symbol, *w, fuzzy_symbol_callback, NULL);
	}

	register_custom_controller_command ("fuzzy_add", fuzzy_add_handler, TRUE, TRUE);
	register_custom_controller_command ("fuzzy_del", fuzzy_delete_handler, TRUE, TRUE);
	
	return res;
}

int
fuzzy_check_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (fuzzy_module_ctx->fuzzy_pool);
	fuzzy_module_ctx->fuzzy_pool = memory_pool_new (memory_pool_get_size ());

	return fuzzy_check_module_config (cfg);
}

static void
fuzzy_io_fin (void *ud)
{
	struct fuzzy_client_session *session = ud;

	event_del (&session->ev);
	session->task->save.saved --;
	if (session->task->save.saved == 0) {
		/* Call other filters */
		session->task->save.saved = 1;
		process_filters (session->task);
	}
}

static void
fuzzy_io_callback (int fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct fuzzy_cmd cmd;
	char buf[sizeof ("ERR")];

	if (what == EV_WRITE) {
		/* Send command to storage */
		cmd.blocksize = session->h->block_size;
		memcpy (cmd.hash, session->h->hash_pipe, sizeof (cmd.hash));
		cmd.cmd = FUZZY_CHECK;
		if (write (fd, &cmd, sizeof (struct fuzzy_cmd)) == -1) {
			goto err;
		}
		else {
			event_set (&session->ev, fd, EV_READ, fuzzy_io_callback, session);
			event_add (&session->ev, &session->tv);
		}
	}
	else if (what == EV_READ) {
		if (read (fd, buf, sizeof (buf)) == -1) {
			goto err;
		}
		else if (buf[0] == 'O' && buf[1] == 'K') {
			insert_result (session->task, fuzzy_module_ctx->metric, fuzzy_module_ctx->symbol, 1, NULL);
		}
		goto ok;
	}
	
	return;

	err:
		msg_err ("fuzzy_io_callback: got error on IO with server %s:%d, %d, %s", session->server->name, session->server->port,
					errno, strerror (errno));
	ok:
		close (fd);
		remove_normal_event (session->task->s, fuzzy_io_fin, session);

}

static void
fuzzy_learn_fin (void *arg)
{
	struct fuzzy_learn_session *session = arg;

	event_del (&session->ev);
	(*session->saved) --;
	if (*session->saved == 0) {
		session->session->state = STATE_REPLY;
		rspamd_dispatcher_write (session->session->dispatcher, "OK" CRLF, sizeof ("OK" CRLF) - 1, FALSE, FALSE);
	}
}

static void
fuzzy_learn_callback (int fd, short what, void *arg)
{
	struct fuzzy_learn_session *session = arg;
	struct fuzzy_cmd cmd;
	char buf[sizeof ("ERR" CRLF)];

	if (what == EV_WRITE) {
		/* Send command to storage */
		cmd.blocksize = session->h->block_size;
		memcpy (cmd.hash, session->h->hash_pipe, sizeof (cmd.hash));
		cmd.cmd = session->cmd;
		if (write (fd, &cmd, sizeof (struct fuzzy_cmd)) == -1) {
			goto err;
		}
		else {
			event_set (&session->ev, fd, EV_READ, fuzzy_learn_callback, session);
			event_add (&session->ev, &session->tv);
		}
	}
	else if (what == EV_READ) {
		if (read (fd, buf, sizeof (buf)) == -1) {
			goto err;
		}
		goto ok;
	}
	
	return;

	err:
		msg_err ("fuzzy_learn_callback: got error in IO with server %s:%d, %d, %s", session->server->name,
					session->server->port, errno, strerror (errno));
	ok:
		close (fd);
		remove_normal_event (session->session->s, fuzzy_learn_fin, session);
}

static void 
fuzzy_symbol_callback (struct worker_task *task, void *unused)
{
	struct mime_text_part *part;
	struct fuzzy_client_session *session;
	struct storage_server *selected;
	GList *cur;
	int sock;

	cur = task->text_parts;

	while (cur) {
		part = cur->data;
		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}
		selected = (struct storage_server *)get_upstream_by_hash (fuzzy_module_ctx->servers, fuzzy_module_ctx->servers_num,
										 sizeof (struct storage_server), task->ts.tv_sec, 
										 DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, 
										 DEFAULT_UPSTREAM_MAXERRORS,
										 part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
		if (selected) {
			if ((sock = make_udp_socket (&selected->addr, selected->port, FALSE, TRUE)) == -1) {
				msg_warn ("fuzzy_symbol_callback: cannot connect to %s, %d, %s", selected->name, errno, strerror (errno));
			}	
			else {
				session = memory_pool_alloc (task->task_pool, sizeof (struct fuzzy_client_session));
				event_set (&session->ev, sock, EV_WRITE, fuzzy_io_callback, session);
				session->tv.tv_sec = IO_TIMEOUT;
				session->tv.tv_usec = 0;
				session->state = 0;
				session->h = part->fuzzy;
				session->task = task;
				session->server = selected;
				event_add (&session->ev, &session->tv);
				register_async_event (task->s, fuzzy_io_fin, session, FALSE);
				task->save.saved ++;
			}
		}
		cur = g_list_next (cur);
	}
}

static void
fuzzy_process_handler (struct controller_session *session, f_str_t *in)
{
	struct worker_task *task;
	struct fuzzy_learn_session *s;
	struct mime_text_part *part;
	struct storage_server *selected;
	GList *cur;
	int sock, r, cmd = 0, *saved;
	char out_buf[BUFSIZ];
	
	if (session->other_data) {
		cmd = GPOINTER_TO_SIZE (session->other_data);
	}
	task = construct_task (session->worker);
	session->other_data = task;
	session->state = STATE_WAIT;

	task->msg = in;
	saved = memory_pool_alloc0 (session->session_pool, sizeof (int));
	r = process_message (task);
	if (r == -1) {
		msg_warn ("read_socket: processing of message failed");
		free_task (task, FALSE);
		session->state = STATE_REPLY;
		r = snprintf (out_buf, sizeof (out_buf), "cannot process message" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		return;
	}
	else {
		/* Plan new event for writing */
		cur = task->text_parts;

		while (cur) {
			part = cur->data;
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			selected = (struct storage_server *)get_upstream_by_hash (fuzzy_module_ctx->servers, fuzzy_module_ctx->servers_num,
											 sizeof (struct storage_server), task->ts.tv_sec, 
											 DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, 
											 DEFAULT_UPSTREAM_MAXERRORS,
											 part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
			if (selected) {
				if ((sock = make_udp_socket (&selected->addr, selected->port, FALSE, TRUE)) == -1) {
					msg_warn ("fuzzy_symbol_callback: cannot connect to %s, %d, %s", selected->name, errno, strerror (errno));
					session->state = STATE_REPLY;
					r = snprintf (out_buf, sizeof (out_buf), "no hashes written" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					free_task (task, FALSE);
					return;
				}	
				else {
					s = memory_pool_alloc (session->session_pool, sizeof (struct fuzzy_learn_session));
					event_set (&s->ev, sock, EV_WRITE, fuzzy_learn_callback, s);
					s->tv.tv_sec = IO_TIMEOUT;
					s->tv.tv_usec = 0;
					s->task = task;
					s->h = memory_pool_alloc (session->session_pool, sizeof (fuzzy_hash_t));
					memcpy (s->h, part->fuzzy, sizeof (fuzzy_hash_t));
					s->session = session;
					s->server = selected;
					s->cmd = cmd;
					s->saved = saved;
					event_add (&s->ev, &s->tv);
					(*saved) ++;
					register_async_event (session->s, fuzzy_learn_fin, s, FALSE);
				}
			}
			else {
				session->state = STATE_REPLY;
				r = snprintf (out_buf, sizeof (out_buf), "cannot write fuzzy hash" CRLF);
				rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
				free_task (task, FALSE);
				return;
			}
			cur = g_list_next (cur);
		}
	}

	free_task (task, FALSE);
	if (*saved == 0) {
		session->state = STATE_REPLY;
		r = snprintf (out_buf, sizeof (out_buf), "no hashes written" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
	}
}

static void
fuzzy_controller_handler (char **args, struct controller_session *session, int cmd)
{
	char *arg, out_buf[BUFSIZ], *err_str;
	uint32_t size;
	int r;

	arg = *args;
	if (!arg || *arg == '\0') {
		msg_info ("fuzzy_controller_handler: empty content length");
		r = snprintf (out_buf, sizeof (out_buf), "fuzzy command requires length as argument" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		session->state = STATE_REPLY;
		return;
	}

	size = strtoul (arg, &err_str, 10);
	if (err_str && *err_str != '\0') {
		r = snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		session->state = STATE_REPLY;
		return;
	}

	session->state = STATE_OTHER;
	rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
	session->other_handler = fuzzy_process_handler;
	session->other_data = GSIZE_TO_POINTER (cmd);
}

static void
fuzzy_add_handler (char **args, struct controller_session *session)
{
	fuzzy_controller_handler (args, session, FUZZY_WRITE);
}

static void
fuzzy_delete_handler (char **args, struct controller_session *session)
{
	fuzzy_controller_handler (args, session, FUZZY_DEL);
}

static int 
fuzzy_mime_filter (struct worker_task *task)
{
	/* XXX: remove this */
	return 0;
}
