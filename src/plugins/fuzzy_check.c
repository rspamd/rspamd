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
 *
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_FUZZY')
 * - max_score (double): maximum score to that weights of hashes would be normalized (default: 0 - no normalization)
 *
 * - fuzzy_map (string): a string that contains map in format { fuzzy_key => [ symbol, weight ] } where fuzzy_key is number of 
 *   fuzzy list. This string itself should be in format 1:R_FUZZY_SAMPLE1:10,2:R_FUZZY_SAMPLE2:1 etc, where first number is fuzzy
 *   key, second is symbol to insert and third - weight for normalization
 *
 * - min_length (integer): minimum length (in characters) for text part to be checked for fuzzy hash (default: 0 - no limit)
 * - whitelist (map string): map of ip addresses that should not be checked with this module
 * - servers (string): list of fuzzy servers in format "server1:port,server2:port" - these servers would be used for checking and storing
 *   fuzzy hashes
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
	struct upstream                 up;
	char                           *name;
	struct in_addr                  addr;
	uint16_t                        port;
};

struct fuzzy_mapping {
	uint32_t fuzzy_flag;
	char *symbol;
	double weight;
};

struct fuzzy_ctx {
	int                             (*filter) (struct worker_task * task);
	char                           *symbol;
	struct storage_server          *servers;
	int                             servers_num;
	memory_pool_t                  *fuzzy_pool;
	double                          max_score;
	uint32_t                        min_hash_len;
	radix_tree_t                   *whitelist;
	GHashTable                     *mappings;
};

struct fuzzy_client_session {
	int                             state;
	fuzzy_hash_t                   *h;
	struct event                    ev;
	struct timeval                  tv;
	struct worker_task             *task;
	struct storage_server          *server;
	int                             fd;
};

struct fuzzy_learn_session {
	struct event                    ev;
	fuzzy_hash_t                   *h;
	int                             cmd;
	int                             value;
	int                             flag;
	int                            *saved;
	struct timeval                  tv;
	struct controller_session      *session;
	struct storage_server          *server;
	struct worker_task             *task;
	int                             fd;
};

static struct fuzzy_ctx        *fuzzy_module_ctx = NULL;

static int                      fuzzy_mime_filter (struct worker_task *task);
static void                     fuzzy_symbol_callback (struct worker_task *task, void *unused);
static void                     fuzzy_add_handler (char **args, struct controller_session *session);
static void                     fuzzy_delete_handler (char **args, struct controller_session *session);

/* Flags string is in format <numeric_flag>:<SYMBOL>:weight[, <numeric_flag>:<SYMBOL>:weight...] */
static void
parse_flags_string (char *str)
{
	char                          **strvec, *item, *err_str, **map_str;
	int                             num, i, t;
	struct fuzzy_mapping           *map;
	
	strvec = g_strsplit (str, ", ;", 0);
	num = g_strv_length (strvec);

	for (i = 0; i < num; i ++) {
		item = strvec[i];
		map_str = g_strsplit (item, ":", 3);
		t = g_strv_length (map_str);
		if (t != 3 && t != 2) {
			msg_err ("invalid fuzzy mapping: %s", item);
		}
		else {
			map = memory_pool_alloc (fuzzy_module_ctx->fuzzy_pool, sizeof (struct fuzzy_mapping));
			map->symbol = memory_pool_strdup (fuzzy_module_ctx->fuzzy_pool, map_str[1]);

			errno = 0;
			map->fuzzy_flag = strtol (map_str[0], &err_str, 10);
			if (errno != 0 || (err_str && *err_str != '\0')) {
				msg_info ("cannot parse flag %s: %s", map_str[0], strerror (errno));
			}
			else if (t == 2) {
				/* Weight is skipped in definition */
				map->weight = fuzzy_module_ctx->max_score;
			}
			else {
				map->weight = strtol (map_str[2], &err_str, 10);
				/* Add flag to hash table */
				g_hash_table_insert (fuzzy_module_ctx->mappings, GINT_TO_POINTER(map->fuzzy_flag), map);
			}
		}
		g_strfreev (map_str);
	}

	g_strfreev (strvec);
}

static void
parse_servers_string (char *str)
{
	char                          **strvec, *p, portbuf[6], *name;
	int                             num, i, j, port;
	struct hostent                 *hent;
	struct in_addr                  addr;

	strvec = g_strsplit (str, ",", 0);
	num = g_strv_length (strvec);

	fuzzy_module_ctx->servers = memory_pool_alloc0 (fuzzy_module_ctx->fuzzy_pool, sizeof (struct storage_server) * num);

	for (i = 0; i < num; i++) {
		g_strstrip (strvec[i]);

		if ((p = strchr (strvec[i], ':')) != NULL) {
			j = 0;
			p++;
			while (g_ascii_isdigit (*(p + j)) && j < sizeof (portbuf) - 1) {
				portbuf[j] = *(p + j);
				j++;
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
				msg_info ("cannot resolve: %s", name);
				continue;
			}
			else {
				fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].port = port;
				fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].name = name;
				memcpy (&fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].addr, hent->h_addr, sizeof (struct in_addr));
				fuzzy_module_ctx->servers_num++;
			}
		}
		else {
			fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].port = port;
			fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].name = name;
			memcpy (&fuzzy_module_ctx->servers[fuzzy_module_ctx->servers_num].addr, hent->h_addr, sizeof (struct in_addr));
			fuzzy_module_ctx->servers_num++;
		}

	}

	g_strfreev (strvec);

}

static double
fuzzy_normalize (int32_t in, double weight)
{
	double ms = weight, ams = fabs (ms), ain = fabs (in);
	
	if (ams > 0.001) {
		if (ain < ams / 2.) {
			return in;
		}
		else if (ain < ams * 2.) {
			ain = ain / 3. + ams / 3.;
			return in > 0 ? ain : -(ain);
		}
		else {
			return in > 0 ? ms : -(ms);
		}
	}
	
	return (double)in;
}

int
fuzzy_check_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	fuzzy_module_ctx = g_malloc (sizeof (struct fuzzy_ctx));

	fuzzy_module_ctx->filter = fuzzy_mime_filter;
	fuzzy_module_ctx->fuzzy_pool = memory_pool_new (memory_pool_get_size ());
	fuzzy_module_ctx->servers = NULL;
	fuzzy_module_ctx->servers_num = 0;
	fuzzy_module_ctx->mappings = g_hash_table_new (g_direct_hash, g_direct_equal);

	*ctx = (struct module_ctx *)fuzzy_module_ctx;

	return 0;
}

int
fuzzy_check_module_config (struct config_file *cfg)
{
	char                           *value;
	int                             res = TRUE;

	if ((value = get_module_opt (cfg, "fuzzy_check", "symbol")) != NULL) {
		fuzzy_module_ctx->symbol = memory_pool_strdup (fuzzy_module_ctx->fuzzy_pool, value);
	}
	else {
		fuzzy_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value = get_module_opt (cfg, "fuzzy_check", "max_score")) != NULL) {
		fuzzy_module_ctx->max_score = strtod (value, NULL);
	}
	else {
		fuzzy_module_ctx->max_score = 0.;
	}

	if ((value = get_module_opt (cfg, "fuzzy_check", "min_length")) != NULL) {
		fuzzy_module_ctx->min_hash_len = strtoul (value, NULL, 10);
	}
	else {
		fuzzy_module_ctx->min_hash_len = 0.;
	}

	if ((value = get_module_opt (cfg, "fuzzy_check", "whitelist")) != NULL) {
		fuzzy_module_ctx->whitelist = radix_tree_create ();
		if (!add_map (value, read_radix_list, fin_radix_list, (void **)&fuzzy_module_ctx->whitelist)) {
			msg_err ("cannot add whitelist '%s'", value);	
		}
	}
	else {
		fuzzy_module_ctx->whitelist = NULL;
	}

	if ((value = get_module_opt (cfg, "fuzzy_check", "servers")) != NULL) {
		parse_servers_string (value);
	}
	if ((value = get_module_opt (cfg, "fuzzy_check", "fuzzy_map")) != NULL) {
		parse_flags_string (value);
	}

	register_symbol (&cfg->cache, fuzzy_module_ctx->symbol, fuzzy_module_ctx->max_score, fuzzy_symbol_callback, NULL);

	register_custom_controller_command ("fuzzy_add", fuzzy_add_handler, TRUE, TRUE);
	register_custom_controller_command ("fuzzy_del", fuzzy_delete_handler, TRUE, TRUE);

	return res;
}

int
fuzzy_check_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (fuzzy_module_ctx->fuzzy_pool);
	fuzzy_module_ctx->servers = NULL;
	fuzzy_module_ctx->servers_num = 0;
	fuzzy_module_ctx->fuzzy_pool = memory_pool_new (memory_pool_get_size ());
	
	g_hash_table_remove_all (fuzzy_module_ctx->mappings);
	return fuzzy_check_module_config (cfg);
}

/* Finalize IO */
static void
fuzzy_io_fin (void *ud)
{
	struct fuzzy_client_session    *session = ud;

	event_del (&session->ev);
	close (session->fd);
	session->task->save.saved--;
	if (session->task->save.saved == 0) {
		/* Call other filters */
		session->task->save.saved = 1;
		process_filters (session->task);
	}
}

/* Call this whenever we got data from fuzzy storage */
static void
fuzzy_io_callback (int fd, short what, void *arg)
{
	struct fuzzy_client_session    *session = arg;
	struct fuzzy_cmd                cmd;
	struct fuzzy_mapping           *map;
	char                            buf[62], *err_str, *symbol;
	int                             value = 0, flag = 0, r;
	double                          nval;

	if (what == EV_WRITE) {
		/* Send command to storage */
		cmd.blocksize = session->h->block_size;
		cmd.value = 0;
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
		/* Got reply */
		if ((r = read (fd, buf, sizeof (buf) - 1)) == -1) {
			goto err;
		}
		else if (buf[0] == 'O' && buf[1] == 'K') {
			buf[r] = 0;
			/* Now try to get value */
			value = strtol (buf + 3, &err_str, 10);
			if (*err_str == ' ') {
				/* Now read flag */
				flag = strtol (err_str + 1, &err_str, 10);
			}
			*err_str = '\0';
			/* Get mapping by flag */
			if ((map = g_hash_table_lookup (fuzzy_module_ctx->mappings, GINT_TO_POINTER (flag))) == NULL) {
				/* Default symbol and default weight */
				symbol = fuzzy_module_ctx->symbol;
				nval = fuzzy_normalize (value, fuzzy_module_ctx->max_score);
			}
			else {
				/* Get symbol and weight from map */
				symbol = map->symbol;
				nval = fuzzy_normalize (value, map->weight);
			}

			snprintf (buf, sizeof (buf), "%d: %d / %.2f", flag, value, nval);
			insert_result (session->task, symbol, nval, g_list_prepend (NULL, 
						memory_pool_strdup (session->task->task_pool, buf)));
		}
		goto ok;
	}
	else {
		errno = ETIMEDOUT;
		goto err;	
	}

	return;

  err:
	msg_err ("got error on IO with server %s:%d, %d, %s", session->server->name, session->server->port, errno, strerror (errno));
  ok:
	remove_normal_event (session->task->s, fuzzy_io_fin, session);

}

static void
fuzzy_learn_fin (void *arg)
{
	struct fuzzy_learn_session     *session = arg;

	event_del (&session->ev);
	close (session->fd);
	(*session->saved)--;
	if (*session->saved == 0) {
		session->session->state = STATE_REPLY;
		session->session->dispatcher->write_callback (session);
	}
}

static void
fuzzy_learn_callback (int fd, short what, void *arg)
{
	struct fuzzy_learn_session     *session = arg;
	struct fuzzy_cmd                cmd;
	char                            buf[64];
	int                             r;

	if (what == EV_WRITE) {
		/* Send command to storage */
		cmd.blocksize = session->h->block_size;
		memcpy (cmd.hash, session->h->hash_pipe, sizeof (cmd.hash));
		cmd.cmd = session->cmd;
		cmd.value = session->value;
		cmd.flag = session->flag;
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
		else if (buf[0] == 'O' && buf[1] == 'K') {
			r = snprintf (buf, sizeof (buf), "OK" CRLF);
			rspamd_dispatcher_write (session->session->dispatcher, buf, r, FALSE, FALSE);
			goto ok;
		}
		else {
			r = snprintf (buf, sizeof (buf), "ERR" CRLF);
			rspamd_dispatcher_write (session->session->dispatcher, buf, r, FALSE, FALSE);
			goto ok;
		}
	}
	else {
		errno = ETIMEDOUT;
		goto err;	
	}

	return;

  err:
	msg_err ("got error in IO with server %s:%d, %d, %s", session->server->name, session->server->port, errno, strerror (errno));
	r = snprintf (buf, sizeof (buf), "Error" CRLF);
	rspamd_dispatcher_write (session->session->dispatcher, buf, r, FALSE, FALSE);
  ok:
	remove_normal_event (session->session->s, fuzzy_learn_fin, session);
}

/* This callback is called when we check message via fuzzy hashes storage */
static void
fuzzy_symbol_callback (struct worker_task *task, void *unused)
{
	struct mime_text_part          *part;
	struct fuzzy_client_session    *session;
	struct storage_server          *selected;
	GList                          *cur;
	int                             sock;

	/* Check whitelist */
	if (fuzzy_module_ctx->whitelist && task->from_addr.s_addr != 0) {
		if (radix32tree_find (fuzzy_module_ctx->whitelist, ntohl ((uint32_t) task->from_addr.s_addr)) != RADIX_NO_VALUE) {
			msg_info ("address %s is whitelisted, skip fuzzy check", inet_ntoa (task->from_addr));
			return;
		}
	}

	cur = task->text_parts;

	while (cur) {
		part = cur->data;
		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}

		/* Check length of hash */
		if (fuzzy_module_ctx->min_hash_len != 0 && 
				strlen (part->fuzzy->hash_pipe) * part->fuzzy->block_size < fuzzy_module_ctx->min_hash_len) {
			msg_info ("part hash is shorter than %d symbols, skip fuzzy check", fuzzy_module_ctx->min_hash_len);
			cur = g_list_next (cur);
			continue;
		}

		/* Get upstream */
		selected = (struct storage_server *)get_upstream_by_hash (fuzzy_module_ctx->servers, fuzzy_module_ctx->servers_num,
			sizeof (struct storage_server), task->ts.tv_sec,
			DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS, part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
		if (selected) {
			if ((sock = make_udp_socket (&selected->addr, selected->port, FALSE, TRUE)) == -1) {
				msg_warn ("cannot connect to %s, %d, %s", selected->name, errno, strerror (errno));
			}
			else {
				/* Create session for a socket */
				session = memory_pool_alloc (task->task_pool, sizeof (struct fuzzy_client_session));
				event_set (&session->ev, sock, EV_WRITE, fuzzy_io_callback, session);
				session->tv.tv_sec = IO_TIMEOUT;
				session->tv.tv_usec = 0;
				session->state = 0;
				session->h = part->fuzzy;
				session->task = task;
				session->fd = sock;
				session->server = selected;
				event_add (&session->ev, &session->tv);
				register_async_event (task->s, fuzzy_io_fin, session, FALSE);
				task->save.saved++;
			}
		}
		cur = g_list_next (cur);
	}
}

static void
fuzzy_process_handler (struct controller_session *session, f_str_t * in)
{
	struct worker_task             *task;
	struct fuzzy_learn_session     *s;
	struct mime_text_part          *part;
	struct storage_server          *selected;
	GList                          *cur;
	int                             sock, r, cmd = 0, value = 0, flag = 0, *saved, *sargs;
	char                            out_buf[BUFSIZ];

	/* Extract arguments */
	if (session->other_data) {
		sargs = session->other_data;
		cmd = sargs[0];
		value = sargs[1];
		flag = sargs[2];
	}
	
	/* Prepare task */
	task = construct_task (session->worker);
	session->other_data = task;
	session->state = STATE_WAIT;
	
	/* Allocate message from string */
	task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
	task->msg->begin = in->begin;
	task->msg->len = in->len;
	

	saved = memory_pool_alloc0 (session->session_pool, sizeof (int));
	r = process_message (task);
	if (r == -1) {
		msg_warn ("processing of message failed");
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
			/* Get upstream */
			selected = (struct storage_server *)get_upstream_by_hash (fuzzy_module_ctx->servers, fuzzy_module_ctx->servers_num,
				sizeof (struct storage_server), task->ts.tv_sec,
				DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS, part->fuzzy->hash_pipe, sizeof (part->fuzzy->hash_pipe));
			if (selected) {
				/* Create UDP socket */
				if ((sock = make_udp_socket (&selected->addr, selected->port, FALSE, TRUE)) == -1) {
					msg_warn ("cannot connect to %s, %d, %s", selected->name, errno, strerror (errno));
					session->state = STATE_REPLY;
					r = snprintf (out_buf, sizeof (out_buf), "no hashes written" CRLF);
					rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
					free_task (task, FALSE);
					return;
				}
				else {
					/* Socket is made, create session */
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
					s->value = value;
					s->flag = flag;
					s->saved = saved;
					s->fd = sock;
					event_add (&s->ev, &s->tv);
					(*saved)++;
					register_async_event (session->s, fuzzy_learn_fin, s, FALSE);
				}
			}
			else {
				/* Cannot write hash */
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
	char                           *arg, out_buf[BUFSIZ], *err_str;
	uint32_t                        size;
	int                             r, value = 1, flag = 0, *sargs;

	/* Process size */
	arg = args[0];
	if (!arg || *arg == '\0') {
		msg_info ("empty content length");
		r = snprintf (out_buf, sizeof (out_buf), "fuzzy command requires length as argument" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		session->state = STATE_REPLY;
		return;
	}
	errno = 0;
	size = strtoul (arg, &err_str, 10);
	if (errno != 0 || (err_str && *err_str != '\0')) {
		r = snprintf (out_buf, sizeof (out_buf), "learn size is invalid" CRLF);
		rspamd_dispatcher_write (session->dispatcher, out_buf, r, FALSE, FALSE);
		session->state = STATE_REPLY;
		return;
	}
	/* Process value */
	arg = args[1];
	if (arg && *arg != '\0') {
		errno = 0;
		value = strtol (arg, &err_str, 10);
		if (errno != 0 || *err_str != '\0') {
			msg_info ("error converting numeric argument %s", arg);
			value = 0;
		}
	}
	/* Process flag */
	arg = args[2];
	if (arg && *arg != '\0') {
		errno = 0;
		flag = strtol (arg, &err_str, 10);
		if (errno != 0 || *err_str != '\0') {
			msg_info ("error converting numeric argument %s", arg);
			flag = 0;
		}
	}

	session->state = STATE_OTHER;
	rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_CHARACTER, size);
	session->other_handler = fuzzy_process_handler;
	/* Prepare args */
	sargs = memory_pool_alloc (session->session_pool, sizeof (int) * 3);
	sargs[0] = cmd;
	sargs[1] = value;
	sargs[2] = flag;
	session->other_data = sargs;
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
